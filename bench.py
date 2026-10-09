"""In-process protocol microbenchmark only. Not a product SLO or OS IPC benchmark."""
import json
import platform
import statistics
import time
import uuid
from udx_ref.core import Broker, FixtureAdapter, ObjectMetadata, PeerIdentity, Policy, VERSION

N = 5000
b = Broker(FixtureAdapter({'test-1':ObjectMetadata('test-1','operator',64,'fixture')}),
           Policy({'operator': {'udx.metadata.read'}}))
peer = PeerIdentity('operator',True)
frames = [json.dumps({'version':VERSION,'request_id':str(uuid.uuid4()),
                     'capability':'object.metadata.read','params':{'object_id':'test-1'}},
                     separators=(',',':')).encode() for _ in range(N+100)]
for raw in frames[:100]:
    assert b.handle(raw, peer)['code'] == 'OK'
lat = []
for raw in frames[100:]:
    t = time.perf_counter_ns()
    result = b.handle(raw, peer)
    lat.append((time.perf_counter_ns() - t)/1000)
    assert result['code']=='OK'
lat.sort()
report = {'scope':'in-process Python mock; excludes transport/OS/I/O/security/sandbox',
          'samples':N,'python':platform.python_version(),'platform':platform.platform(),
          'microseconds':{'p50':lat[int(.50*(N-1))], 'p95':lat[int(.95*(N-1))],
                          'p99':lat[int(.99*(N-1))], 'mean':statistics.fmean(lat)}}
print(json.dumps(report,indent=2))
with open('docs/BENCHMARK.json','w',encoding='utf8') as f:
    json.dump(report,f,indent=2)
    f.write('\n')
