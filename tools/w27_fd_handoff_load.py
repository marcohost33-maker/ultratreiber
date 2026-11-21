"""W27 (UDX14-06): controlled CPU load against the fd-handoff demo, A/B.

RESEARCH TOOLING, Linux only. Runs the demo of a baseline revision (taken with
``git show``; nothing in the checkout is changed) and the demo of this checkout
alternately under N busy-loop processes and records for every run: exit code,
failure class, wall time and, for the current demo, the per-phase durations.

It measures; it does not judge. The numbers depend on the machine: the load
level is therefore also given as oversubscription (burners per CPU).

Usage:
  PYTHONPATH=. python tools/w27_fd_handoff_load.py --baseline-rev 40f1aa9 \
      --levels 0,64,320,480 --runs 15 --output evidence/W27_FD_HANDOFF_LOAD.json
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
DEMO = 'tools/demo_w8_fd_handoff.py'
OLD_TEST_TIMEOUT_S = 5.0          # outer timeout of tests/test_w8_fd_handoff.py before W27
RUN_GUARD_S = 300.0


def classify(returncode, stdout: str, stderr: str) -> str:
    """Failure class of one demo run (pure; pinned by tests)."""
    if returncode is None:
        return 'RUN_GUARD_TIMEOUT'
    if returncode == 0:
        return 'OK'
    try:
        typed = json.loads(stdout).get('error')
    except (ValueError, AttributeError):
        typed = None
    if type(typed) is str and typed:
        return typed
    for name in ('TimeoutError', 'BlockingIOError', 'BrokenPipeError', 'ConnectionResetError'):
        if name in stderr:
            return name
    return 'OTHER'


def summarize(runs: list) -> dict:
    """Counts and wall-time statistics of one variant at one level (pure)."""
    walls = sorted(r['wall_s'] for r in runs)
    classes = {}
    for r in runs:
        classes[r['class']] = classes.get(r['class'], 0) + 1
    out = {'runs': len(runs), 'classes': dict(sorted(classes.items())),
           'failed': sum(1 for r in runs if r['class'] != 'OK'),
           'wall_s_median': round(statistics.median(walls), 3) if walls else None,
           'wall_s_max': round(walls[-1], 3) if walls else None,
           'over_old_test_timeout': sum(1 for w in walls if w > OLD_TEST_TIMEOUT_S)}
    for phase in ('startup_ms', 'protocol_ms', 'teardown_ms'):
        values = sorted(r['phases_ms'][phase] for r in runs if phase in r.get('phases_ms', {}))
        if values:
            out[phase] = {'median': round(statistics.median(values), 1), 'max': round(values[-1], 1)}
    return out


def _one(script: pathlib.Path, extra: list) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
    env.update(PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1')
    started = time.monotonic()
    try:
        r = subprocess.run([sys.executable, '-B', str(script), *extra], cwd=REPO, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=RUN_GUARD_S)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = None, '', ''
    rec = {'wall_s': round(time.monotonic() - started, 3), 'class': classify(rc, out, err)}
    try:
        phases = json.loads(out).get('phases_ms')
    except (ValueError, AttributeError):
        phases = None
    if type(phases) is dict:
        rec['phases_ms'] = phases
    return rec


def measure(levels, runs, baseline_rev) -> dict:
    rev = subprocess.run(['git', 'rev-parse', '--verify', baseline_rev + '^{commit}'], cwd=REPO,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout.strip()
    old_bytes = subprocess.run(['git', 'show', f'{rev}:{DEMO}'], cwd=REPO, stdin=subprocess.DEVNULL,
                               capture_output=True, check=True).stdout
    result = {'tool': 'w27_fd_handoff_load', 'baseline_rev': rev, 'runs_per_level': runs,
              'python': platform.python_version(), 'platform': sys.platform,
              'kernel': platform.release().split('-')[0], 'cpus': os.cpu_count(),
              'old_test_timeout_s': OLD_TEST_TIMEOUT_S, 'levels': []}
    with tempfile.TemporaryDirectory(prefix='udx_w27_') as tmp:
        old = pathlib.Path(tmp) / 'demo_w8_fd_handoff_baseline.py'
        old.write_bytes(old_bytes)
        for level in levels:
            # W28.1 (Codex review on #8): start the burners inside the protected
            # region, so a failure or interrupt half-way still kills and reaps
            # every burner that did start.
            burners = []
            try:
                for _ in range(level):
                    burners.append(subprocess.Popen([sys.executable, '-c', 'while True: pass'],
                                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                    stderr=subprocess.DEVNULL))
                time.sleep(1.0)
                base, cur = [], []
                for _ in range(runs):                    # alternate, so drift hits both variants
                    base.append(_one(old, []))
                    cur.append(_one(REPO / DEMO, ['--lifecycle']))
            finally:
                for b in burners:
                    b.kill()
                for b in burners:
                    b.wait()
            result['levels'].append({'burners': level, 'burners_per_cpu': round(level / (os.cpu_count() or 1), 1),
                                     'baseline': summarize(base), 'current': summarize(cur)})
            print(json.dumps(result['levels'][-1], sort_keys=True), flush=True)
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX W27 fd-handoff load measurement (research only)')
    p.add_argument('--baseline-rev', required=True)
    p.add_argument('--levels', default='0,64,320,480')
    p.add_argument('--runs', type=int, default=15)
    p.add_argument('--output')
    args = p.parse_args(argv)
    if sys.platform != 'linux':
        p.error('Linux only')
    try:
        levels = [int(x) for x in args.levels.split(',')]
    except ValueError:
        p.error('--levels needs comma-separated integers')
    if not levels or any(not 0 <= x <= 2000 for x in levels) or not 1 <= args.runs <= 1000:
        p.error('levels 0..2000, runs 1..1000')
    result = measure(levels, args.runs, args.baseline_rev)
    if args.output:
        pathlib.Path(args.output).write_text(json.dumps(result, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
