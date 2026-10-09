"""Paired W8 (SO_PEERCRED) vs W9 (SO_PASSCRED) *in-process* comparison.
Does NOT measure separate-process context switches or OS authorisation.
"""
import hashlib
import json
import os
import pathlib
import statistics
import tempfile
import time
import uuid
from udx_ref.fd_handoff import private_pair, send_approved_fd, handle_once, recv_status
from udx_ref.credentialed_handoff import credentialed_pair, send_readonly_request, process_one, read_verified_reply

def percentile(vals,p):
    a=sorted(vals);return a[int((len(a)-1)*p)]

def measure(mode, fd, expected_digest, runs):
    arr=[]
    for _ in range(runs):
        a,b=(private_pair() if mode=='w8' else credentialed_pair())
        rid=str(uuid.uuid4())
        try:
            start=time.perf_counter_ns()
            if mode=='w8':
                send_approved_fd(a,fd,rid)
                handle_once(b,expected_uid=os.getuid(),owner_uid=os.getuid())
                out=recv_status(a,rid)
            else:
                send_readonly_request(a,fd,rid)
                process_one(b,expected_sender_uid=os.getuid(),source_owner_uid=os.getuid())
                out=read_verified_reply(a,expected_worker_uid=os.getuid(),request_id=rid)
            arr.append((time.perf_counter_ns()-start)/1e6)
            if out['size']!=4096 or out['sha256']!=expected_digest:raise AssertionError('MISMATCH')
        finally:
            a.close();b.close()
    return {'p50_ms':percentile(arr,.5),'p95_ms':percentile(arr,.95),'p99_ms':percentile(arr,.99),'max_ms':max(arr)}

def run():
    detail={'w8':[],'w9':[]}
    with tempfile.TemporaryDirectory() as tmp:
        p=pathlib.Path(tmp)/'test.bin';p.write_bytes(b'B'*4096)
        fd=os.open(p,os.O_RDONLY)
        try:
            for i in range(5):
                for mode in (['w8','w9'] if i%2==0 else ['w9','w8']):
                    detail[mode].append(measure(mode,fd,hashlib.sha256(b'B'*4096).hexdigest(),250))
        finally:os.close(fd)
    out={'metric':'in-process 4 KiB FD handoff including temporary socketpair/seal/hash',
         'rounds':5,'calls_per_round_per_version':250,'uid':os.getuid(),
         'exclusions':['separate process scheduling','portal UI','system installation','different uid cost','network'],
         'median_round_percentiles':{mode:{key:statistics.median(z[key] for z in rounds) for key in ('p50_ms','p95_ms','p99_ms')}
                                     for mode,rounds in detail.items()},'rounds_detail':detail}
    print(json.dumps(out,indent=2))
if __name__=='__main__':run()
