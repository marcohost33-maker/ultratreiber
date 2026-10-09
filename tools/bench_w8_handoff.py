"""W8 bounded local in-process socketpair/SCM_RIGHTS+sealing benchmark.
Counts socket + metadata + SHA-256, but does NOT include process launch or GUI consent.
"""
import hashlib,json,os,pathlib,statistics,tempfile,time,uuid
from udx_ref.fd_handoff import private_pair,send_approved_fd,handle_once,recv_status

def percent(s,p):
    s=sorted(s);return s[max(0,min(len(s)-1,int((len(s)-1)*p)))]
def run(n=300,rounds=5):
    allrounds=[]
    with tempfile.TemporaryDirectory(prefix='udx-w8-bench-') as d:
        path=pathlib.Path(d)/'a.bin';path.write_bytes(b'a'*4096)
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
        try:
            for j in range(rounds):
                samples=[]
                for i in range(n):
                    a,b=private_pair();rid=str(uuid.uuid4())
                    try:
                        t0=time.perf_counter_ns()
                        send_approved_fd(a,fd,rid)
                        handle_once(b,expected_uid=os.getuid(),owner_uid=os.getuid())
                        ans=recv_status(a,rid)
                        samples.append((time.perf_counter_ns()-t0)/1e6)
                        assert ans['size']==4096 and ans['sha256']==hashlib.sha256(b'a'*4096).hexdigest()
                    finally:a.close();b.close()
                allrounds.append({'p50_ms':percent(samples,.5),'p95_ms':percent(samples,.95),
                                  'p99_ms':percent(samples,.99),'max_ms':max(samples)})
        finally:os.close(fd)
    print(json.dumps({'kind':'in-process-socketpair-transfer-and-seal','sample_file_bytes':4096,
        'samples_per_round':n,'rounds':rounds,'host_process_separation':False,
        'portal_gui_consent':False,'machine':'local Linux test environment',
        'median_of_rounds':{k:statistics.median(x[k] for x in allrounds) for k in allrounds[0]},
        'rounds_detail':allrounds},indent=2))
if __name__=='__main__':run()
