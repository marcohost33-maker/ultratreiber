"""Research microbenchmark, no OS calls, no claim of production SLOs."""
import json,statistics,time
from uuid import uuid4
from udx_ref.preview_gate import PreviewGate,PreviewProposal
from udx_ref.perception import TileChangeTracker

def percentile(xs, pct):
    arr=sorted(xs)
    return arr[min(len(arr)-1,round((len(arr)-1)*pct))]

def bench_gate(n=1000):
    gate=PreviewGate(); results=[]
    for i in range(n):
        grant=gate.issue(human_approved=True, principal='p',session_id='s',resource_id='r',frame_epoch=1,width=16,height=16)
        req=PreviewProposal(str(uuid4()),'p','s','r',1,16,16,5,6)
        start=time.perf_counter_ns()
        decision=gate.check_and_consume(grant,req)
        results.append(time.perf_counter_ns()-start)
        assert decision.accepted
    return results

def bench_perception(n=200):
    tracker=TileChangeTracker(tile_edge=64,quiet_observations=3)
    data=bytes(256*256*4)
    tracker.inspect(data,width=256,height=256)
    results=[]
    for i in range(n):
        start=time.perf_counter_ns()
        tracker.inspect(data,width=256,height=256)
        results.append(time.perf_counter_ns()-start)
    return results

if __name__=='__main__':
    out={}
    for name,fn in [('gate',bench_gate),('tile',bench_perception)]:
        rounds=[fn() for _ in range(5)]
        medians=[statistics.median(r)/1e6 for r in rounds]
        out[name]={'n_per_round':len(rounds[0]),'rounds':5,'median_of_round_medians_ms':statistics.median(medians),
                   'min_round_median_ms':min(medians),'max_round_median_ms':max(medians),
                   'p95_last_round_ms':percentile(rounds[-1],.95)/1e6}
    print(json.dumps(out,indent=2))
