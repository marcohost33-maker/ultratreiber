"""W31: cost of the acknowledged lane against udx/0.1 (research measurement only).

Starts two real server processes (CLI) on private runtime directories, one with
--receipt-journal, and sends N sequential requests to each, interleaved in
blocks so drift hits both lanes alike. Reports per-request latency (median,
p95 nearest rank) and the paired median ratio. Linux, non-root only.

Not a throughput or DoS figure: one client, one connection per request, local
disk. The acked lane pays three journal commits (reserve, respond, ack), each
with synchronous=FULL.

Usage: python tools/bench_w31_ack.py [--requests 200] [--block 20] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from udx_ref.linux_ipc import request_on_socket, request_on_socket_acked, supported  # noqa: E402


def p95(values):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def wire():
    return json.dumps({'version': 'udx/0.1', 'request_id': str(uuid.uuid4()),
                       'capability': 'object.metadata.read', 'params': {'object_id': 'sample-1'}}).encode()


def start(runtime: Path, n: int, journal: Path | None):
    argv = [sys.executable, '-m', 'udx_ref.linux_ipc', '--runtime-dir', str(runtime), '--max-connections', str(n)]
    if journal is not None:
        argv += ['--receipt-journal', str(journal)]
    proc = subprocess.Popen(argv, cwd=REPO, env=dict(os.environ, PYTHONPATH=str(REPO)),
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(1000):
        if (runtime / 'udx.sock').exists():
            return proc
        if proc.poll() is not None:
            raise RuntimeError(proc.stderr.read().decode())
        time.sleep(0.01)
    raise RuntimeError('socket did not appear')


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--requests', type=int, default=200)
    ap.add_argument('--block', type=int, default=20)
    ap.add_argument('--json')
    args = ap.parse_args(argv)
    if not supported() or os.geteuid() == 0:
        print('Linux non-root required', file=sys.stderr)
        return 2
    if not 1 <= args.block <= args.requests <= 10000 or args.requests % args.block:
        ap.error('requests must be a multiple of block, 1..10000')
    with tempfile.TemporaryDirectory(prefix='udx-w31-bench-') as tmp:
        base = Path(tmp)
        dirs = {}
        for name in ('legacy', 'acked', 'store'):
            dirs[name] = base / name
            dirs[name].mkdir(mode=0o700)
        legacy = start(dirs['legacy'], args.requests, None)
        acked = start(dirs['acked'], args.requests, dirs['store'] / 'receipts.db')
        lat = {'legacy': [], 'acked': []}
        receipts = {}
        try:
            for block in range(args.requests // args.block):
                order = ('legacy', 'acked') if block % 2 == 0 else ('acked', 'legacy')
                for lane in order:
                    for _ in range(args.block):
                        raw = wire()
                        t0 = time.perf_counter()
                        if lane == 'legacy':
                            result = request_on_socket(dirs['legacy'] / 'udx.sock', raw)
                        else:
                            result, receipt = request_on_socket_acked(dirs['acked'] / 'udx.sock', raw)
                            receipts[receipt] = receipts.get(receipt, 0) + 1
                        lat[lane].append(time.perf_counter() - t0)
                        if result['code'] != 'OK':
                            raise RuntimeError(result)
        finally:
            for proc in (legacy, acked):
                proc.terminate()
                proc.wait(timeout=5)
    ms = {k: [v * 1000 for v in vals] for k, vals in lat.items()}
    ratios = [a / b for a, b in zip(ms['acked'], ms['legacy'])]
    out = {
        'tool': 'bench_w31_ack', 'requests_per_lane': args.requests, 'block': args.block,
        'python': platform.python_version(), 'platform': platform.platform(),
        'legacy_ms': {'median': round(statistics.median(ms['legacy']), 3), 'p95': round(p95(ms['legacy']), 3)},
        'acked_ms': {'median': round(statistics.median(ms['acked']), 3), 'p95': round(p95(ms['acked']), 3)},
        'paired_median_ratio_acked_over_legacy': round(statistics.median(ratios), 3),
        'receipts': receipts,
        'limits': 'one client, sequential, local disk, no power-loss test; not a throughput or DoS figure',
    }
    text = json.dumps(out, indent=1, sort_keys=True)
    print(text)
    if args.json:
        Path(args.json).write_text(text + '\n', encoding='utf-8')
    return 0 if receipts.get('DELIVERED') == args.requests else 1


if __name__ == '__main__':
    sys.exit(main())
