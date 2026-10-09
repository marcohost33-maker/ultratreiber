import json
import uuid
from udx_ref.core import Broker, FixtureAdapter, ObjectMetadata, PeerIdentity, Policy, VERSION
adapter = FixtureAdapter({'sample-1': ObjectMetadata('sample-1','operator',256,'fixture')})
policy = Policy({'operator': {'udx.discover','udx.metadata.read'}})
broker = Broker(adapter, policy)
peer = PeerIdentity('operator', True)  # test fixture; real IPC must establish this
for capability, params in [('device.capabilities.list',{}),('object.metadata.read',{'object_id':'sample-1'})]:
    req = {'version': VERSION,'request_id':str(uuid.uuid4()),'capability':capability,'params':params}
    print(json.dumps(broker.handle(json.dumps(req).encode(),peer),sort_keys=True))
