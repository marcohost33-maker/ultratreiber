"""Standalone prototype microbenchmark: no real D-Bus/OS consent."""
import json, statistics, time, uuid
from pathlib import Path
from udx_ref.portal_request import PortalRequest

def run(n=2500):
    samples=[]
    for i in range(n):
        a=time.perf_counter_ns()
        p=PortalRequest(caller_unique=':1.55',portal_owner_unique=':1.89')
        p.bind_handle(p.handle)
        p.receive(sender_unique=':1.89',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/fixture']})
        samples.append((time.perf_counter_ns()-a)/1000)
    arr=sorted(samples)
    return dict(kind='W11_PORTAL_SIMULATION_IN_PROCESS',n=n,units='microseconds',p50=statistics.median(arr),p95=arr[int(.95*(n-1))],p99=arr[int(.99*(n-1))],os_consented=False,linux_portal_used=False)
if __name__=='__main__':
    p=Path(__file__).resolve().parents[1]/'evidence'/'W11_PORTAL_MICROBENCH.json'
    x=run();p.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
