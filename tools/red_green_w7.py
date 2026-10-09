"""Run under v0.6 or v0.7 PYTHONPATH; JSON output for deterministic regression."""
import json
from uuid import uuid4
from dataclasses import replace
from udx_ref.preview_gate import PreviewGate,PreviewProposal
from udx_ref.perception import TileChangeTracker

g=PreviewGate()
key=g.issue(human_approved=True,principal='p',session_id='s',resource_id='r',frame_epoch=1,width=32,height=32)
p=PreviewProposal(str(uuid4()),'p','s','r',True,32.0,32,1,2)
res=g.check_and_consume(key,p)
t=TileChangeTracker(tile_edge=8,quiet_observations=2,change_threshold=1)
base=bytes(32*32); modified=bytearray(base);modified[0]=1
t.inspect(base,width=32,height=32,channels=1)
r1=t.inspect(bytes(modified),width=32,height=32,channels=1)
r2=t.inspect(base,width=32,height=32,channels=1)
print(json.dumps({'type_confusion_accepted':res.accepted,'first_changed_state':r1.state,
 'second_changed_state':r2.state,'second_changed_stable':r2.state=='STABLE_HEURISTIC'},sort_keys=True))
