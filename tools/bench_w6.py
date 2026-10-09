"""Reproducible microbench. Local Python only; no OS calls or user workloads."""
import json, platform, statistics, sys, time
from uuid import uuid4
from udx_ref.preview_gate import PreviewGate, PreviewProposal
from udx_ref.perception import TileChangeTracker

def summary(series):
    s=sorted(series)
    return {'n':len(s),'p50_ms':round(s[int((len(s)-1)*.50)],6),
            'p95_ms':round(s[int((len(s)-1)*.95)],6),
            'p99_ms':round(s[int((len(s)-1)*.99)],6),
            'min_ms':round(s[0],6),'max_ms':round(s[-1],6)}

runs=1500
records=[]
gate=PreviewGate()
for _ in range(runs):
    k=gate.issue(human_approved=True,principal='fixture',session_id='s',resource_id='display',
                 frame_epoch=1,width=1280,height=720)
    req=PreviewProposal(str(uuid4()),'fixture','s','display',1,1280,720,15,15)
    t=time.perf_counter_ns()
    r=gate.check_and_consume(k,req)
    dt=(time.perf_counter_ns()-t)/1e6
    assert r.accepted and r.effect=='NONE'
    records.append(dt)
# Avoid collecting new captured content; deterministic synthetic frame.
frame=bytes(256*256*4)
tracker=TileChangeTracker(tile_edge=64,quiet_observations=3)
tracker.inspect(frame,width=256,height=256,channels=4)
frame_samples=[]
for _ in range(300):
    t=time.perf_counter_ns()
    signal=tracker.inspect(frame,width=256,height=256,channels=4)
    frame_samples.append((time.perf_counter_ns()-t)/1e6)
assert signal.state=='STABLE_HEURISTIC'
result={'environment':{'python':sys.version.split()[0],'os':platform.system(),
                       'kernel':platform.release(),'architecture':platform.machine()},
        'scope':'single process; 1500 dry-run authorizations, 300 synthetic 256x256x4 tile scans; not IPC/OS/video benchmarks',
        'gate_check':summary(records),'tile_scan':summary(frame_samples),
        'frame_size_bytes':len(frame),'tracked_digest_bytes':len(tracker._hashes)*16}
print(json.dumps(result,indent=2,sort_keys=True))
