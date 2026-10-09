"""Paired Linux loopback benchmark. Same v0.5 client for both server revisions.

Run as Linux non-root, specifying the extracted v0.4 and v0.5 source roots.
Microbenchmark is NOT a production throughput or SLO claim.
"""
import argparse
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

from udx_ref.core import VERSION
from udx_ref.linux_ipc import request_on_socket, supported


def pctl(samples,q):
    return sorted(samples)[min(len(samples)-1, int((len(samples)-1)*q))]


def once(root,n,warmup):
    env=dict(os.environ, PYTHONPATH=str(root))
    with tempfile.TemporaryDirectory(prefix='udx-bench-pair-') as runtime:
        os.chmod(runtime,0o700)
        sock=Path(runtime)/'udx.sock'
        proc=subprocess.Popen([sys.executable,'-m','udx_ref.linux_ipc',
                               '--runtime-dir',runtime],env=env,cwd=str(root),
                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for _ in range(500):
                if sock.exists():break
                if proc.poll() is not None:
                    raise RuntimeError(f'broker {root} exited: {proc.communicate()[1].decode()}')
                time.sleep(.005)
            if not sock.exists():raise RuntimeError('IPC server did not bind')
            measurements=[]
            for i in range(n+warmup):
                raw=json.dumps({'version':VERSION,'request_id':str(uuid.uuid4()),
                        'capability':'object.metadata.read','params':{'object_id':'sample-1'}},
                        separators=(',',':')).encode()
                t0=time.perf_counter_ns()
                answer=request_on_socket(sock,raw)
                spent=(time.perf_counter_ns()-t0)/1e6
                if answer['code']!='OK':raise RuntimeError(f'non OK: {answer}')
                if i>=warmup:measurements.append(spent)
            return {'n':len(measurements), 'p50_ms':pctl(measurements,.50),
                    'p95_ms':pctl(measurements,.95),
                    'p99_ms':pctl(measurements,.99),
                    'mean_ms':statistics.mean(measurements)}
        finally:
            proc.terminate()
            try:proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.communicate()


def main():
    a=argparse.ArgumentParser()
    a.add_argument('--w4',type=Path,required=True)
    a.add_argument('--w5',type=Path,required=True)
    a.add_argument('--trials',type=int,default=3)
    a.add_argument('--calls',type=int,default=500)
    a.add_argument('--warmup',type=int,default=50)
    a.add_argument('--output',type=Path)
    args=a.parse_args()
    if not supported() or os.geteuid()==0:raise RuntimeError('requires Linux nonroot')
    if args.trials not in range(1,11) or not 10<=args.calls<=50000:
        raise ValueError('invalid benchmark parameters')
    random.seed(20261009)
    results=[]
    for trial in range(args.trials):
        order=['w4','w5']
        random.shuffle(order)
        for revision in order:
            root=args.w4 if revision=='w4' else args.w5
            one=once(root.resolve(strict=True),args.calls,args.warmup)
            results.append(dict(trial=trial+1,revision=revision,**one))
    result={'description':'paired baseline with same W5 client; serial requests only',
            'python':sys.version.split()[0], 'platform':sys.platform,
            'server_w4':str(args.w4),'server_w5':str(args.w5),
            'seed':20261009,'trials':results}
    if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
