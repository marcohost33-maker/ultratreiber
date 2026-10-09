"""Offline real-AF_UNIX loopback IPC benchmark, strictly fixture-only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from udx_ref.linux_ipc import request_on_socket, supported
from udx_ref.core import VERSION


def percentile(sorted_data, p):
    i = (len(sorted_data) - 1) * p
    lower = int(i)
    delta = i - lower
    return sorted_data[lower] * (1 - delta) + sorted_data[min(lower+1,len(sorted_data)-1)] * delta


def main():
    if not supported() or os.geteuid() == 0:
        raise RuntimeError('Linux non-root required; no root benchmark substitutes')
    sample_count = 300
    with tempfile.TemporaryDirectory(prefix='udx-bench-') as folder:
        os.chmod(folder, 0o700)
        sock = Path(folder)/'udx.sock'
        proc = subprocess.Popen([sys.executable,'-m','udx_ref.linux_ipc','--runtime-dir',folder,
                                 '--max-connections',str(sample_count)],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            for _ in range(500):
                if sock.exists():break
                if proc.poll() is not None: raise RuntimeError('broker exited at startup')
                time.sleep(.01)
            else:raise RuntimeError('broker failed to bind')
            measurements=[]
            for _ in range(sample_count):
                raw=json.dumps({'version':VERSION,'request_id':str(uuid.uuid4()),
                                'capability':'object.metadata.read','params':{'object_id':'sample-1'}},
                                separators=(',',':')).encode()
                t0=time.perf_counter_ns()
                response=request_on_socket(sock,raw)
                elapsed=(time.perf_counter_ns()-t0)/1e6
                if response['code']!='OK':
                    raise AssertionError(f'unexpected response: {response["code"]}')
                measurements.append(elapsed)
            _,stderr=proc.communicate(timeout=10)
            if proc.returncode!=0:raise RuntimeError(stderr.decode())
            ordered=sorted(measurements)
            print(json.dumps({
                'scope':'local unprivileged Linux AF_UNIX TCP-free fixture metadata read: connect + uid-check + bounded frame + broker + decode',
                'system':platform.platform(),'python':platform.python_version(),
                'n':sample_count,'success':sample_count,
                'p50_ms':round(percentile(ordered,.5),5),
                'p95_ms':round(percentile(ordered,.95),5),
                'p99_ms':round(percentile(ordered,.99),5),
                'mean_ms':round(statistics.mean(ordered),5),
                'max_ms':round(max(measurements),5),
                'notes':'No real OS object read. Single-process server, separate client process. Local non-root account. Not an SLO.'
            },ensure_ascii=False,indent=2))
        finally:
            if proc.poll() is None:
                proc.terminate();proc.communicate(timeout=3)

if __name__=='__main__':main()
