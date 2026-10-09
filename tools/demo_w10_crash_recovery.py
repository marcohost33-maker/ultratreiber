"""Controlled W10 crash before transfer completion; no OS actions performed."""
import json,os,pathlib,subprocess,sys,tempfile,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from udx_ref.durable_grants import DurableGrantStore,GrantDenied

def main():
    with tempfile.TemporaryDirectory(prefix='udx-w10-abrupt-') as root:
        p=pathlib.Path(root);f=p/'fixture';f.write_bytes(b'private-data-never-exported')
        loc=str(p/'grants.db')
        fd=os.open(f,os.O_RDONLY)
        try:
            with DurableGrantStore(loc) as s:
                grant=s.issue(fd,issuer_uid=os.getuid(),recipient_uid=os.getuid(),ttl_seconds=90)
        finally:os.close(fd)
        program="""import os,sys,uuid
from udx_ref.durable_grants import DurableGrantStore
loc,source,grant=sys.argv[1:]
fd=os.open(source,os.O_RDONLY)
with DurableGrantStore(loc) as s:
    s.claim(grant,fd,issuer_uid=os.getuid(),recipient_uid=os.getuid(),request_id=str(uuid.uuid4()))
os._exit(47)
"""
        child=subprocess.run([sys.executable,'-c',program,loc,str(f),grant],capture_output=True,text=True,timeout=12)
        if child.returncode!=47:raise RuntimeError(f'NO_CRASH_MARK: {child.returncode}: {child.stderr}')
        with DurableGrantStore(loc) as s:
            before=s.state(grant);recovered=s.recover_inflight();after=s.state(grant)
            fd=os.open(f,os.O_RDONLY)
            try:
                try:s.claim(grant,fd,issuer_uid=os.getuid(),recipient_uid=os.getuid(),request_id=str(uuid.uuid4()))
                except GrantDenied:replay='DENIED'
                else:raise RuntimeError('UNSAFE_RETRY')
            finally:os.close(fd)
        assert before=='INFLIGHT' and recovered==1 and after=='QUARANTINED'
        print(json.dumps({'child_exit':47,'before_recover':before,'quarantined':after,
                          'replay':replay,'status':'PASS'},sort_keys=True))
if __name__=='__main__':main()
