"""Discriminating-mutation (DK) runner for the ``evidence/*dk_spec*.json`` files.

RESEARCH TOOLING. Until W26 the DK specs were executed only by an external,
private runner; reviewers could not reproduce "n/n killed" (A7 UT6-04: "a real
mutation harness ... missing"). This runner makes every claim reproducible:

* It never edits the working tree. All tracked files are copied once into a
  private temporary directory; each mutation is applied there and reverted.
* No bytecode cache: every child runs with ``-B`` and
  ``PYTHONDONTWRITEBYTECODE=1``. Python validates a ``.pyc`` by source mtime
  (seconds) and size only (PEP 552 default), so a same-length mutation written
  in the same second as the original can be masked by a stale cache, and a
  restored file can silently keep running mutated bytecode (observed in W26:
  a false "DK28 survived").
* Each case: the anchor ``alt`` must occur exactly once (else STALE_ANCHOR); the
  named test must pass on the unmutated copy (else BASELINE_RED) and must not be
  skipped there (else SKIPPED_ON_PLATFORM, e.g. a Windows-only test on Linux);
  with the mutation it must fail. A timeout or a crash of the runner itself is
  never counted as a kill (TIMEOUT / RUNNER_ERROR).
* Tests run with ``unittest`` (the specs name ``pytest``; the repository's tests
  are plain unittest and CI runs them with unittest, so no extra dependency).

Exit code 0 only if every applicable case is KILLED and nothing is stale, red
or timed out; SKIPPED_ON_PLATFORM cases are reported and do not count as kills.
``--expect-stale SPEC=N`` pins the known stale anchors of a historical spec:
exactly N are tolerated, the anchored rest must be killed, N+1 fails.
Usage:
  python tools/dk_runner.py evidence/w26_dk_spec.json [more specs] [--json out.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
VERDICTS = ('KILLED', 'SURVIVED', 'STALE_ANCHOR', 'BASELINE_RED', 'SKIPPED_ON_PLATFORM', 'TIMEOUT',
            'RUNNER_ERROR')
_SKIP_RE = re.compile(r'^OK \(.*skipped=(\d+).*\)$', re.M)
_RAN_RE = re.compile(r'^Ran (\d+) tests? in ', re.M)


def test_id(spec_test: str) -> str:
    """``tests/x.py::Class::method`` -> ``tests.x.Class.method``; ValueError otherwise."""
    if type(spec_test) is not str:
        raise ValueError('TEST_ID_INVALID')
    parts = spec_test.split('::')
    if len(parts) != 3 or not parts[0].endswith('.py') or not all(parts) \
            or not all(p.isidentifier() for p in parts[1:]):
        raise ValueError('TEST_ID_INVALID')
    mod = parts[0][:-3].replace('/', '.')
    if not all(seg.isidentifier() for seg in mod.split('.')):
        raise ValueError('TEST_ID_INVALID')
    return f'{mod}.{parts[1]}.{parts[2]}'


def classify(rc, output: str) -> str:
    """One unittest run of exactly one test -> PASS / SKIP / FAIL / TIMEOUT.
    A pass must report exactly one test run; 'OK (skipped=1)' is a skip."""
    if rc is None:
        return 'TIMEOUT'
    ran = _RAN_RE.findall(output or '')
    if rc == 0:
        if ran != ['1']:
            return 'FAIL'                    # nothing (or more than the one test) ran
        return 'SKIP' if _SKIP_RE.search(output) else 'PASS'
    return 'FAIL'


def decide(anchor_count: int, base: str, mutant: str | None) -> str:
    """Pure verdict for one case (pinned by tests/test_w26_dk_runner.py)."""
    if anchor_count != 1:
        return 'STALE_ANCHOR'
    if base == 'TIMEOUT':
        return 'TIMEOUT'
    if base == 'SKIP':
        return 'SKIPPED_ON_PLATFORM'
    if base != 'PASS':
        return 'BASELINE_RED'
    if mutant == 'TIMEOUT' or mutant is None:
        return 'TIMEOUT'
    return 'KILLED' if mutant == 'FAIL' else 'SURVIVED'


def _copy_tree(dest: pathlib.Path) -> None:
    files = subprocess.run(['git', 'ls-files', '-z'], cwd=REPO, stdin=subprocess.DEVNULL,
                           capture_output=True, check=True).stdout.split(b'\0')
    for raw in files:
        if not raw:
            continue
        rel = raw.decode('utf-8')
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, target)


def _inside(work: pathlib.Path, rel) -> pathlib.Path:
    """The spec's ``datei`` as a path inside ``work``; ValueError for anything
    that would leave it (absolute, ``..``, drive letters, symlink escapes)."""
    if type(rel) is not str or not rel or '\0' in rel or '\\' in rel or rel.startswith('/') or ':' in rel:
        raise ValueError('DATEI_INVALID')
    root = work.resolve()
    target = (root / rel).resolve()
    if root not in target.parents or not target.is_file():
        raise ValueError('DATEI_OUTSIDE_WORK')
    return target


def _run(work: pathlib.Path, tid: str, timeout_s: float):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
    env.update(PYTHONPATH='.', PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0')
    try:
        r = subprocess.run([sys.executable, '-B', '-m', 'unittest', tid], cwd=work, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return None, ''
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def run_spec(spec_path: pathlib.Path, work: pathlib.Path, expect_stale: int = 0) -> dict:
    raw = spec_path.read_bytes()
    spec = json.loads(raw)
    timeout_s = float(spec.get('timeout_s', 120))
    out = {'spec': spec_path.relative_to(REPO).as_posix() if spec_path.is_relative_to(REPO) else str(spec_path),
           'spec_sha256': hashlib.sha256(raw).hexdigest(), 'cases': []}
    for case in spec.get('faelle', []):
        rec = {'name': case.get('name'), 'test': case.get('test')}
        try:
            tid = test_id(case.get('test'))
            target = _inside(work, case['datei'])
            # Bytes, never text mode: on Windows a text-mode write turns every LF
            # into CRLF (the repository pins LF via .gitattributes and hashes
            # sources), so mutation AND restore would break unrelated pins.
            orig = target.read_bytes()
            alt, neu = case['alt'].encode('utf-8'), case['neu'].encode('utf-8')
            count = orig.count(alt)
            if count != 1:
                rec['verdict'] = decide(count, 'PASS', None)
                rec['anchor_count'] = count
                out['cases'].append(rec)
                continue
            base = classify(*_run(work, tid, timeout_s))
            mutant = None
            if base == 'PASS':
                try:
                    target.write_bytes(orig.replace(alt, neu))
                    mutant = classify(*_run(work, tid, timeout_s))
                finally:
                    target.write_bytes(orig)
            rec.update(baseline=base, mutant=mutant, verdict=decide(count, base, mutant))
        except (KeyError, ValueError, OSError) as exc:
            rec['verdict'] = 'RUNNER_ERROR'
            rec['error'] = f'{type(exc).__name__}: {exc}'[:200]
        out['cases'].append(rec)
    counts = {v: sum(1 for c in out['cases'] if c['verdict'] == v) for v in VERDICTS}
    out['counts'] = {k: v for k, v in counts.items() if v}
    # A historical spec keeps the anchors of its own wave. Its known number of
    # stale anchors is pinned by the caller (--expect-stale); exactly that many
    # are tolerated, every other anchored case must be killed, and one more
    # stale anchor (code moved on again) fails the run.
    out['expect_stale'] = expect_stale
    stale_ok = counts['STALE_ANCHOR'] == expect_stale
    applicable = len(out['cases']) - counts['SKIPPED_ON_PLATFORM'] - (expect_stale if stale_ok else 0)
    out['killed'] = f"{counts['KILLED']}/{applicable}"
    out['ok'] = stale_ok and applicable > 0 and counts['KILLED'] == applicable
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX discriminating-mutation runner (research only)')
    p.add_argument('specs', nargs='+')
    p.add_argument('--json', help='write the full result as JSON')
    p.add_argument('--expect-stale', action='append', default=[], metavar='SPEC=N',
                   help='pin the known number of stale anchors of a historical spec')
    args = p.parse_args(argv)
    expect = {}
    for item in args.expect_stale:
        spec, sep, n = item.rpartition('=')
        if not sep or not spec or not n.isdigit():
            p.error('--expect-stale needs SPEC=N')
        expect[spec] = int(n)
    unknown = set(expect) - set(args.specs)
    if unknown:
        p.error('--expect-stale for a spec that is not run: ' + ', '.join(sorted(unknown)))
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True).stdout.strip() or None
    result = {'tool': 'dk_runner', 'head': head, 'python': platform.python_version(),
              'platform': sys.platform, 'specs': []}
    with tempfile.TemporaryDirectory(prefix='udx_dk_') as tmp:
        work = pathlib.Path(tmp)
        _copy_tree(work)
        for s in args.specs:
            path = (REPO / s) if not os.path.isabs(s) else pathlib.Path(s)
            r = run_spec(path, work, expect.get(s, 0))
            result['specs'].append(r)
            for c in r['cases']:
                if c['verdict'] != 'KILLED':
                    print(f"  {c['verdict']}: {c['name']}")
            pinned = f" (stale pinned {r['expect_stale']})" if r['expect_stale'] else ''
            print(f"{r['spec']}: {r['killed']} killed {r['counts']}{pinned} {'OK' if r['ok'] else 'NOT_OK'}")
    result['ok'] = all(r['ok'] for r in result['specs'])
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(result, indent=1, sort_keys=True), encoding='utf-8')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
