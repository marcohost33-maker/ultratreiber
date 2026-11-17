"""Two-sided guard sweep: every refusal needs a negative AND a positive control.

RESEARCH TOOLING. W26.1 found a test that only checked refusals: a mutant that
refuses everything survived (SR-10). The hand-written DK specs cannot find that
class, because each names one weakening per guard. This sweep takes its
inventory from the code, not from a list:

* A *guard* is an ``if``/``elif`` whose body ends in ``raise``.
* For every guard two mutants are run against the tests that reach the module:
  ``ADMIT``  - the condition becomes ``False`` (the refusal is gone); a survivor
               means no negative test exercises this refusal.
  ``REFUSE`` - the condition becomes ``True`` (everything is refused); a survivor
               means no positive control passes through this guard.
* Survivors are compared with a pinned baseline file. A new survivor fails the
  run; so does a baseline entry that no longer survives (the pin would rot).
  A timeout is never a kill.

Like ``dk_runner``: private work copies, never the checkout; no bytecode cache;
byte-exact mutation and restore. Guards are keyed by file, enclosing function,
condition text and refusal code, not by line number.

Scope: only what the tests of the *running platform* reach. Windows-only code
swept on Linux would show every guard as a survivor; it is therefore not in the
default module list.

Usage:
  python tools/guard_sweep.py --baseline evidence/w27_guard_sweep_baseline.json [--json out.json]
  python tools/guard_sweep.py --list            # inventory only
"""
from __future__ import annotations

import argparse
import ast
import concurrent.futures
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
try:
    import dk_runner
finally:
    sys.path.pop(0)

DEFAULT_MODULES = ('udx_ref/core.py', 'udx_ref/credentialed_handoff.py', 'udx_ref/durable_grants.py',
                   'udx_ref/fd_handoff.py', 'udx_ref/fd_reader.py', 'udx_ref/frame_lease.py',
                   'udx_ref/linux_ipc.py', 'udx_ref/perception.py', 'udx_ref/portal_boundary.py',
                   'udx_ref/portal_request.py', 'udx_ref/preview_gate.py', 'udx_ref/sealed_snapshot.py')
# Tests of the mutation tooling itself run nested mutation runs; they say nothing about a guard.
EXCLUDED_TESTS = ('test_w26_dk_runner', 'test_w27_guard_sweep')
KINDS = {'ADMIT': b'False', 'REFUSE': b'True'}
ACCEPTED_CLASSES = ('DEFENSE_IN_DEPTH', 'EQUIVALENT', 'OPEN_NO_TEST')
_FAILED_RE = re.compile(r'^FAILED \((.*)\)$', re.M)


def _refusal_code(node: ast.Raise) -> str:
    exc = node.exc
    if exc is None:
        return 'reraise'
    if isinstance(exc, ast.Call):
        name = ast.unparse(exc.func)
        if exc.args and isinstance(exc.args[0], ast.Constant) and type(exc.args[0].value) is str:
            return f'{name}:{exc.args[0].value}'
        return name
    return ast.unparse(exc)


def inventory(rel: str, source: bytes) -> list:
    """All guards of one module with a line-independent key and the byte range
    of the condition. Pure; pinned by tests."""
    tree = ast.parse(source)
    lines = source.split(b'\n')
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    guards = []

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = scope + [child.name]
            if isinstance(child, ast.If) and isinstance(child.body[-1], ast.Raise):
                test = child.test
                begin = starts[test.lineno - 1] + test.col_offset
                end = starts[test.end_lineno - 1] + test.end_col_offset
                text = source[begin:end]
                guards.append({'file': rel, 'scope': '.'.join(scope) or '<module>',
                               'code': _refusal_code(child.body[-1]), 'line': child.lineno,
                               'condition': ' '.join(text.decode('utf-8').split()),
                               'begin': begin, 'end': end})
            visit(child, inner)

    visit(tree, [])
    seen = {}
    for g in guards:
        base = '|'.join((g['file'], g['scope'], g['code'],
                         hashlib.sha256(g['condition'].encode('utf-8')).hexdigest()[:12]))
        n = seen[base] = seen.get(base, 0) + 1
        g['key'] = base if n == 1 else f'{base}#{n}'
    return guards


def mutate(source: bytes, guard: dict, kind: str) -> bytes:
    return source[:guard['begin']] + KINDS[kind] + source[guard['end']:]


def _stems_importing(target_stem: str, repo: pathlib.Path) -> set:
    """Stems of udx_ref modules and tools that (transitively) import the target."""
    graph = {}
    for path in list((repo / 'udx_ref').glob('*.py')) + list((repo / 'tools').glob('*.py')):
        try:
            tree = ast.parse(path.read_bytes())
        except SyntaxError:
            continue
        deps = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    deps.add(node.module.split('.')[-1])
                deps.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                deps.update(a.name.split('.')[-1] for a in node.names)
        graph[path.stem] = deps
    closure, frontier = {target_stem}, [target_stem]
    while frontier:
        current = frontier.pop()
        for stem, deps in graph.items():
            if current in deps and stem not in closure:
                closure.add(stem)
                frontier.append(stem)
    return closure


def tests_for(rel: str, repo: pathlib.Path = REPO) -> list:
    """Test modules that mention the module or anything that imports it."""
    stems = _stems_importing(pathlib.PurePosixPath(rel).stem, repo)
    pattern = re.compile(r'\b(' + '|'.join(sorted(re.escape(s) for s in stems)) + r')\b')
    out = []
    for path in sorted((repo / 'tests').glob('test_*.py')):
        if path.stem in EXCLUDED_TESTS:
            continue
        if pattern.search(path.read_text(encoding='utf-8', errors='replace')):
            out.append('tests.' + path.stem)
    return out


def classify(rc, output: str) -> str:
    """One unittest run of several modules -> PASS / FAIL_ASSERTION / FAIL_ERROR / TIMEOUT."""
    if rc is None:
        return 'TIMEOUT'
    if rc == 0:
        return 'PASS'
    m = _FAILED_RE.search(output or '')
    if m and 'failures=' in m.group(1):
        return 'FAIL_ASSERTION'
    return 'FAIL_ERROR'


def decide(base: str, mutant: str | None) -> str:
    if base == 'TIMEOUT' or mutant == 'TIMEOUT':
        return 'TIMEOUT'
    if base != 'PASS' or mutant is None:
        return 'BASELINE_RED'
    return 'SURVIVED' if mutant == 'PASS' else 'KILLED'


def compare(survivors: set, baseline: dict) -> dict:
    """Ratchet (pure): new survivors and stale baseline entries both fail."""
    pinned = set(baseline)
    return {'new_survivors': sorted(survivors - pinned), 'stale_baseline': sorted(pinned - survivors)}


def load_baseline(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    out = {}
    for entry in data.get('accepted_survivors', []):
        ident = f"{entry['kind']} {entry['key']}"
        if entry.get('class') not in ACCEPTED_CLASSES or not str(entry.get('reason', '')).strip() or ident in out:
            raise ValueError(f'BASELINE_ENTRY_INVALID: {ident}')
        out[ident] = entry
    return out


def _run(work: pathlib.Path, modules: list, timeout_s: float):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
    env.update(PYTHONPATH='.', PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0')
    try:
        r = subprocess.run([sys.executable, '-B', '-m', 'unittest', *modules], cwd=work, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return None, ''
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def sweep(modules, jobs: int, timeout_s: float, repo: pathlib.Path = REPO, copy_tree=None) -> dict:
    copy_tree = copy_tree or dk_runner._copy_tree
    plan = []
    for rel in modules:
        source = (repo / rel).read_bytes()
        for guard in inventory(rel, source):
            for kind in KINDS:
                plan.append((rel, guard, kind))
    result = {'tool': 'guard_sweep', 'python': platform.python_version(), 'platform': sys.platform,
              'modules': {}, 'cases': []}
    with tempfile.TemporaryDirectory(prefix='udx_gs_') as tmp:
        works = []
        for i in range(jobs):
            w = pathlib.Path(tmp) / f'w{i}'
            w.mkdir()
            copy_tree(w)
            works.append(w)
        baselines = {}
        for rel in modules:
            tests = tests_for(rel, repo)
            base = classify(*_run(works[0], tests, timeout_s)) if tests else 'NO_TESTS'
            baselines[rel] = (tests, base)
            result['modules'][rel] = {'tests': tests, 'baseline': base,
                                      'guards': sum(1 for p in plan if p[0] == rel) // len(KINDS)}

        def one(index):
            rel, guard, kind = plan[index]
            work = works[index % jobs]
            tests, base = baselines[rel]
            rec = {'key': guard['key'], 'kind': kind, 'line': guard['line'], 'condition': guard['condition']}
            if base != 'PASS':
                rec['verdict'] = decide(base, None)
                return rec
            target = dk_runner._inside(work, rel)
            orig = target.read_bytes()
            try:
                target.write_bytes(mutate(orig, guard, kind))
                mutant = classify(*_run(work, tests, timeout_s))
            finally:
                target.write_bytes(orig)
            rec.update(mutant=mutant, verdict=decide(base, mutant))
            return rec

        # One thread per work copy: cases of the same copy never run concurrently.
        def lane(start):
            return [one(i) for i in range(start, len(plan), jobs)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            for chunk in pool.map(lane, range(jobs)):
                result['cases'].extend(chunk)
    result['cases'].sort(key=lambda c: (c['key'], c['kind']))
    counts = {}
    for c in result['cases']:
        counts[c['verdict']] = counts.get(c['verdict'], 0) + 1
    result['counts'] = dict(sorted(counts.items()))
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX two-sided guard sweep (research only)')
    p.add_argument('modules', nargs='*', default=list(DEFAULT_MODULES))
    p.add_argument('--baseline', help='pinned accepted survivors (JSON)')
    p.add_argument('--json', help='write the full result as JSON')
    p.add_argument('--jobs', type=int, default=max(1, min(4, os.cpu_count() or 1)))
    p.add_argument('--timeout', type=float, default=180.0)
    p.add_argument('--list', action='store_true', help='print the guard inventory and exit')
    args = p.parse_args(argv)
    if args.list:
        for rel in args.modules:
            for g in inventory(rel, (REPO / rel).read_bytes()):
                print(f"{g['key']}  (line {g['line']}: if {g['condition']})")
        return 0
    if not 1 <= args.jobs <= 32:
        p.error('--jobs 1..32')
    baseline = load_baseline(REPO / args.baseline) if args.baseline else {}
    result = sweep(args.modules, args.jobs, args.timeout)
    survivors = {f"{c['kind']} {c['key']}" for c in result['cases'] if c['verdict'] == 'SURVIVED'}
    result.update(compare(survivors, baseline))
    blocking = [c for c in result['cases'] if c['verdict'] in ('TIMEOUT', 'BASELINE_RED')]
    result['ok'] = not result['new_survivors'] and not result['stale_baseline'] and not blocking \
        and bool(result['cases'])
    for c in result['cases']:
        if c['verdict'] != 'KILLED':
            ident = f"{c['kind']} {c['key']}"
            note = 'pinned' if ident in baseline else 'NEW'
            print(f"  {c['verdict']} [{note}] {ident}  (line {c['line']}: if {c['condition']})")
    for ident in result['stale_baseline']:
        print(f'  STALE_BASELINE {ident}')
    killed = result['counts'].get('KILLED', 0)
    print(f"guard sweep: {len(result['cases'])} mutants, {killed} killed, {len(survivors)} survived "
          f"({len(survivors & set(baseline))} pinned), {len(blocking)} blocking -> "
          f"{'OK' if result['ok'] else 'NOT_OK'}")
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(result, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
