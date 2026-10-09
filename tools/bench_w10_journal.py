"""Local SQLite-WAL-FULL research benchmark, not host IPC or app consent cost."""
import json,os,pathlib,statistics,tempfile,time,uuid
from udx_ref.durable_grants import DurableGrantStore

def pct(nums,q):return sorted(nums)[int((len(nums)-1)*q)]

def run():
    rounds=[];runs=5;n=60
    with tempfile.TemporaryDirectory() as d:
        f=pathlib.Path(d)/'test';f.write_bytes(b'B'*4096)
        fd=os.open(f,os.O_RDONLY)
        try:
            with DurableGrantStore(str(pathlib.Path(d)/'grants.db')) as store:
                for _ in range(5):
                    timings=[]
                    for k in range(n):
                        start=time.perf_counter_ns()
                        grant=store.issue(fd,issuer_uid=os.getuid(),recipient_uid=os.getuid(),ttl_seconds=60)
                        rid=str(uuid.uuid4())
                        store.claim(grant,fd,issuer_uid=os.getuid(),recipient_uid=os.getuid(),request_id=rid)
                        store.finish(grant,rid)
                        timings.append((time.perf_counter_ns()-start)/1e6)
                    rounds.append({'p50_ms':pct(timings,.5),'p95_ms':pct(timings,.95),'p99_ms':pct(timings,.99)})
        finally:os.close(fd)
    print(json.dumps({'benchmark':'W10 three synchronous durable SQLite transitions',
                      'rounds':5,'operations_per_round':n,'uid':os.getuid(),'commit_mode':'WAL/FULL',
                      'median_round_percentiles_ms':{key:statistics.median(row[key] for row in rounds) for key in rounds[0]},
                      'round_details':rounds,
                      'excluded':['portal GUI','real Windows','distinct UID context switches','FD transfer','hardware power-loss simulation']},indent=2))
if __name__=='__main__':run()
