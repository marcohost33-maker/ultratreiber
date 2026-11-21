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

W28 (answers A7-R6 U6-4 and A7-R17 PR-R17-06):

* Two more refusal forms are inventoried. ``if``/``elif`` whose body ends in
  ``return <refusal>`` (an upper-case code string, ``False``, or a call with a
  literal ``False`` argument) get the same ADMIT/REFUSE pair. An ``except``
  handler that converts an exception into a typed refusal (body ends in
  ``raise T(...)`` or ``return <refusal>``) gets one mutant, ``UNTYPED``: the
  handler type becomes ``()``, so the original exception escapes untyped. A
  survivor means no test checks the typed conversion. Bare re-raises and bare
  ``return`` are not refusals and are not inventoried. W27 keys are unchanged.
* A kill must be attributable to a test. ``FAIL_ASSERTION`` (a test failed) and
  ``FAIL_ERROR_IN_TEST`` (a test method raised) kill; ``FAIL_STRUCTURAL`` (only
  import, ``setUpClass``/``setUpModule`` or teardown errors, or no parsable
  summary) says nothing about the guard and is reported as ``STRUCTURAL``, a
  non-kill that needs a pin like a survivor. Each kill records its mode and the
  failing test ids.
* A pin of class ``EQUIVALENT`` (no input reaches the refusal) must name a
  ``witness`` test that exercises the boundary; the sweep checks that it exists.

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
EXCLUDED_TESTS = ('test_w26_dk_runner', 'test_w27_guard_sweep', 'test_w28_guard_sweep_v2')
# W28.1 (Codex review on #8): a condition may have side effects, e.g.
# 'if len(raw) > MAX_STATUS or sock.send(raw) != len(raw)'. Replacing it by a bare
# literal also removed the send, so positive tests failed and counted as a kill
# of a refusal they never exercise. The condition is now still evaluated and only
# its result is forced: ADMIT '((cond) and False)', REFUSE '((cond) or True)'.
KINDS = {'ADMIT': (b'((', b') and False)'), 'REFUSE': (b'((', b') or True)'), 'UNTYPED': (b'', b'()')}
FORM_KINDS = {'raise': ('ADMIT', 'REFUSE'), 'return': ('ADMIT', 'REFUSE'), 'handler': ('UNTYPED',)}
ACCEPTED_CLASSES = ('DEFENSE_IN_DEPTH', 'EQUIVALENT', 'OPEN_NO_TEST', 'STRUCTURAL_ONLY')
# A kill whose failing tests pass when re-run alone against the same mutant is
# UNRELIABLE (W28.1): a non-kill, never pinnable as a class of its own.
NOT_KILLED = ('SURVIVED', 'STRUCTURAL', 'UNRELIABLE')
_FAILED_RE = re.compile(r'^FAILED \((.*)\)$', re.M)
# 'FAIL: test_x (pkg.mod.Class.test_x)' optionally followed by ' (subtest params)'
_HEADER_RE = re.compile(r'^(FAIL|ERROR): (\S+) \(([^()\s]+)\)(?: \(.*\))?\s*$', re.M)
_STRUCTURAL_NAMES = ('setUpClass', 'tearDownClass', 'setUpModule', 'tearDownModule')
_CODE_RE = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')


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


def _return_refusal(node) -> str | None:
    """Code of a refusal-valued ``return``, or None for an ordinary return."""
    if not isinstance(node, ast.Return) or node.value is None:
        return None
    value = node.value
    if isinstance(value, ast.Constant) and value.value is False:
        return 'return:False'
    for sub in ast.walk(value):
        if isinstance(sub, ast.Constant) and type(sub.value) is str and _CODE_RE.match(sub.value):
            return f'return:{sub.value}'
    for sub in ast.walk(value):
        if isinstance(sub, ast.Call) and any(isinstance(a, ast.Constant) and a.value is False
                                             for a in sub.args):
            return 'return:' + ast.unparse(sub.func)
    return None


def _handler_refusal(handler: ast.ExceptHandler) -> str | None:
    last = handler.body[-1]
    if isinstance(last, ast.Raise) and isinstance(last.exc, ast.Call):
        return 'except:' + _refusal_code(last)
    code = _return_refusal(last)
    return f'except:{code}' if code else None


def inventory(rel: str, source: bytes) -> list:
    """All guards of one module with a line-independent key and the byte range
    of the mutated expression. Pure; pinned by tests. ``form`` is ``raise``,
    ``return`` or ``handler``; W27 (``raise``) keys are unchanged."""
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
            target = form = code = None
            if isinstance(child, ast.If) and isinstance(child.body[-1], ast.Raise):
                target, form, code = child.test, 'raise', _refusal_code(child.body[-1])
            elif isinstance(child, ast.If) and _return_refusal(child.body[-1]):
                target, form, code = child.test, 'return', _return_refusal(child.body[-1])
            elif isinstance(child, ast.ExceptHandler) and child.type is not None \
                    and _handler_refusal(child):
                target, form, code = child.type, 'handler', _handler_refusal(child)
            if target is not None:
                begin = starts[target.lineno - 1] + target.col_offset
                end = starts[target.end_lineno - 1] + target.end_col_offset
                text = source[begin:end]
                guards.append({'file': rel, 'scope': '.'.join(scope) or '<module>',
                               'code': code, 'line': child.lineno, 'form': form,
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


def kinds_for(guard: dict) -> tuple:
    return FORM_KINDS[guard.get('form', 'raise')]


def mutate(source: bytes, guard: dict, kind: str) -> bytes:
    if kind not in kinds_for(guard):
        raise ValueError(f'KIND_NOT_APPLICABLE: {kind} {guard.get("form", "raise")}')
    head, tail = KINDS[kind]
    if kind == 'UNTYPED':               # the handler type is replaced, not wrapped
        return source[:guard['begin']] + tail + source[guard['end']:]
    return source[:guard['begin']] + head + source[guard['begin']:guard['end']] + tail + source[guard['end']:]


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


def failing_tests(output: str) -> list:
    """(FAIL|ERROR, test id, structural?) for every failure header of a run."""
    out = []
    for kind, name, where in _HEADER_RE.findall(output or ''):
        structural = name in _STRUCTURAL_NAMES or 'unittest.loader._FailedTest' in where \
            or where.startswith('unittest.suite._ErrorHolder')
        # Python >= 3.11 prints the full test id in the parentheses.
        out.append((kind, where, structural))
    return out


def classify(rc, output: str) -> str:
    """One unittest run -> PASS / FAIL_ASSERTION / FAIL_ERROR_IN_TEST / FAIL_STRUCTURAL / TIMEOUT."""
    if rc is None:
        return 'TIMEOUT'
    if rc == 0:
        return 'PASS'
    m = _FAILED_RE.search(output or '')
    if m and 'failures=' in m.group(1):
        return 'FAIL_ASSERTION'
    if any(kind == 'ERROR' and not structural for kind, _, structural in failing_tests(output)):
        return 'FAIL_ERROR_IN_TEST'
    return 'FAIL_STRUCTURAL'


def decide(base: str, mutant: str | None) -> str:
    if base == 'TIMEOUT' or mutant == 'TIMEOUT':
        return 'TIMEOUT'
    if base != 'PASS' or mutant is None:
        return 'BASELINE_RED'
    if mutant == 'PASS':
        return 'SURVIVED'
    return 'STRUCTURAL' if mutant == 'FAIL_STRUCTURAL' else 'KILLED'


def compare(survivors: set, baseline: dict) -> dict:
    """Ratchet (pure): new survivors and stale baseline entries both fail."""
    pinned = set(baseline)
    return {'new_survivors': sorted(survivors - pinned), 'stale_baseline': sorted(pinned - survivors)}


def load_baseline(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding='utf-8'))
    out = {}
    for entry in data.get('accepted_survivors', []):
        ident = f"{entry['kind']} {entry['key']}"
        if entry.get('class') not in ACCEPTED_CLASSES or not str(entry.get('reason', '')).strip() or ident in out \
                or entry['kind'] not in KINDS \
                or (entry['class'] == 'EQUIVALENT' and not str(entry.get('witness', '')).strip()):
            raise ValueError(f'BASELINE_ENTRY_INVALID: {ident}')
        out[ident] = entry
    return out


def missing_witnesses(baseline: dict, repo: pathlib.Path = REPO) -> list:
    """Witness ids (``tests.module.Class.test``) that do not name an existing test."""
    missing = []
    for ident, entry in sorted(baseline.items()):
        witness = entry.get('witness')
        if not witness:
            continue
        parts = witness.split('.')
        path = repo.joinpath(*parts[:2]).with_suffix('.py') if len(parts) == 4 else None
        found = False
        if path is not None and parts[0] == 'tests' and path.is_file():
            tree = ast.parse(path.read_bytes())
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == parts[2]:
                    found = any(isinstance(f, ast.FunctionDef) and f.name == parts[3] for f in node.body)
        if not found:
            missing.append(f'{ident} -> {witness}')
    return missing


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


def sweep(modules, jobs: int, timeout_s: float, repo: pathlib.Path = REPO, copy_tree=None,
          confirm: bool = True) -> dict:
    copy_tree = copy_tree or dk_runner._copy_tree
    plan = []
    for rel in modules:
        source = (repo / rel).read_bytes()
        for guard in inventory(rel, source):
            for kind in kinds_for(guard):
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
                                      'guards': len({p[1]['key'] for p in plan if p[0] == rel})}

        def one(index):
            rel, guard, kind = plan[index]
            work = works[index % jobs]
            tests, base = baselines[rel]
            rec = {'key': guard['key'], 'kind': kind, 'line': guard['line'], 'condition': guard['condition'],
                   'form': guard['form']}
            if base != 'PASS':
                rec['verdict'] = decide(base, None)
                return rec
            target = dk_runner._inside(work, rel)
            orig = target.read_bytes()
            try:
                target.write_bytes(mutate(orig, guard, kind))
                rc, output = _run(work, tests, timeout_s)
                mutant = classify(rc, output)
                rec.update(mutant=mutant, verdict=decide(base, mutant))
                if rec['verdict'] in ('KILLED', 'STRUCTURAL'):
                    rec['kill_mode'] = {'FAIL_ASSERTION': 'ASSERTION',
                                        'FAIL_ERROR_IN_TEST': 'ERROR_IN_TEST'}.get(mutant, 'STRUCTURAL')
                    rec['failing'] = sorted({tid for kind_, tid, structural in failing_tests(output)
                                             if not structural})
                if rec['verdict'] == 'KILLED' and confirm:
                    # W28.1: a kill must reproduce (Shi, Bell, Marinov, ISSTA 2019): the
                    # failing tests run again, alone, against the same mutant.
                    again = classify(*_run(work, rec['failing'], timeout_s))
                    rec['confirmed'] = again in ('FAIL_ASSERTION', 'FAIL_ERROR_IN_TEST')
                    if not rec['confirmed']:
                        rec['verdict'] = 'UNRELIABLE'
            finally:
                target.write_bytes(orig)
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
    modes = {}
    for c in result['cases']:
        if c['verdict'] == 'KILLED':
            k = f"{c['kind']} {c['kill_mode']}"
            modes[k] = modes.get(k, 0) + 1
    result['kill_modes'] = dict(sorted(modes.items()))
    forms = {}
    for c in result['cases']:
        forms[c['form']] = forms.get(c['form'], 0) + 1
    result['mutants_by_form'] = dict(sorted(forms.items()))
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX two-sided guard sweep (research only)')
    p.add_argument('modules', nargs='*', default=list(DEFAULT_MODULES))
    p.add_argument('--baseline', help='pinned accepted survivors (JSON)')
    p.add_argument('--json', help='write the full result as JSON')
    p.add_argument('--jobs', type=int, default=max(1, min(4, os.cpu_count() or 1)))
    p.add_argument('--timeout', type=float, default=180.0)
    p.add_argument('--list', action='store_true', help='print the guard inventory and exit')
    p.add_argument('--no-confirm', action='store_true',
                   help='do not re-run the failing tests of a kill (faster, weaker; never in CI)')
    args = p.parse_args(argv)
    if args.list:
        for rel in args.modules:
            for g in inventory(rel, (REPO / rel).read_bytes()):
                print(f"{g['form']:7} {g['key']}  (line {g['line']}: {g['condition']})")
        return 0
    if not 1 <= args.jobs <= 32:
        p.error('--jobs 1..32')
    baseline = load_baseline(REPO / args.baseline) if args.baseline else {}
    witnesses = missing_witnesses(baseline)
    for item in witnesses:
        print(f'  MISSING_WITNESS {item}')
    result = sweep(args.modules, args.jobs, args.timeout, confirm=not args.no_confirm)
    result['confirm_kills'] = not args.no_confirm
    survivors = {f"{c['kind']} {c['key']}" for c in result['cases'] if c['verdict'] in NOT_KILLED}
    result.update(compare(survivors, baseline))
    result['missing_witnesses'] = witnesses
    blocking = [c for c in result['cases'] if c['verdict'] in ('TIMEOUT', 'BASELINE_RED')]
    result['ok'] = not result['new_survivors'] and not result['stale_baseline'] and not blocking \
        and not witnesses and bool(result['cases'])
    for c in result['cases']:
        if c['verdict'] != 'KILLED':
            ident = f"{c['kind']} {c['key']}"
            note = 'pinned' if ident in baseline else 'NEW'
            print(f"  {c['verdict']} [{note}] {ident}  (line {c['line']}: {c['condition']})")
    for ident in result['stale_baseline']:
        print(f'  STALE_BASELINE {ident}')
    killed = result['counts'].get('KILLED', 0)
    print(f"guard sweep: {len(result['cases'])} mutants {result['mutants_by_form']}, {killed} killed "
          f"{result['kill_modes']}, {len(survivors)} not killed ({len(survivors & set(baseline))} pinned), "
          f"{len(blocking)} blocking -> {'OK' if result['ok'] else 'NOT_OK'}")
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(result, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
