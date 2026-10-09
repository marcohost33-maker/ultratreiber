"""W10 research demo: durable one-use grant + two distinct Linux UIDs, not a production launcher.

Run as root in a disposable Linux test environment with setpriv installed.
It launches a sender as a normal uid and receiver as a distinct unprivileged uid.
The receiver cannot open the chmod-0600 user fixture by path.
"""
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from udx_ref.credentialed_handoff import credentialed_pair


def role_main(role, sock_fd, expected_uid, file_path, request_id, worker_uid):
    from udx_ref.credentialed_handoff import send_readonly_request, process_one, read_verified_reply
    sock=socket.socket(fileno=int(sock_fd))
    sock.settimeout(12.0)
    try:
        if role=='worker':
            # Demonstrate DAC: no direct read of source as cross-UID worker.
            try: fd=os.open(file_path,os.O_RDONLY)
            except PermissionError: direct_access=False
            else:
                os.close(fd); raise RuntimeError('WORKER_COULD_OPEN_SOURCE')
            result=process_one(sock,expected_sender_uid=int(expected_uid),source_owner_uid=int(expected_uid))
            print(json.dumps({'status':'OK','direct_access':direct_access,'size':result['size']}),flush=True)
        elif role=='host':
            from udx_ref.durable_grants import DurableGrantStore, GrantDenied
            from udx_ref.authorized_handoff import perform_trusted_handoff
            fd=os.open(file_path,os.O_RDONLY)
            try:
                with tempfile.TemporaryDirectory(prefix='udx-w10-private-journal-') as dbdir:
                    with DurableGrantStore(str(Path(dbdir)/'grants.db')) as grants:
                        grant=grants.issue(fd,issuer_uid=os.getuid(),recipient_uid=int(worker_uid),ttl_seconds=30)
                        ans=perform_trusted_handoff(grants,sock,fd,grant_id=grant,issuer_uid=os.getuid(),
                                                   worker_uid=int(worker_uid),request_id=request_id)
                        state=grants.state(grant)
                        try:
                            grants.claim(grant,fd,issuer_uid=os.getuid(),recipient_uid=int(worker_uid),request_id=str(uuid.uuid4()))
                        except GrantDenied:
                            replay='DENIED'
                        else:raise RuntimeError('DURABLE_REPLAY_ACCEPTED')
                    with DurableGrantStore(str(Path(dbdir)/'grants.db')) as reopened:
                        after_restart=reopened.state(grant)
            finally:os.close(fd)
            print(json.dumps({'status':'OK','size':ans['size'],'durable_grant':state,
                              'replay':replay,'reopen_state':after_restart}),flush=True)
        elif role=='attacker':
            # Malicious peer has a socket endpoint but cannot impersonate the host UID.
            sock.send(json.dumps({'v':'udx/fd/0.1','op':'inspect.readonly','id':request_id,'uid':int(expected_uid)}).encode())
            print(json.dumps({'sent':'FORGED_UID_FIELD'}),flush=True)
        elif role=='worker_negative':
            from udx_ref.fd_handoff import HandoffError
            try:
                process_one(sock,expected_sender_uid=int(expected_uid),source_owner_uid=int(expected_uid))
            except HandoffError as exc:
                if str(exc)!='CREDENTIALS_MISMATCH':raise
                print(json.dumps({'rejected':'CREDENTIALS_MISMATCH'}),flush=True)
            else:raise RuntimeError('FORGED_UID_ACCEPTED')
        else:raise ValueError('role')
    finally:sock.close()


def parent_main():
    if os.geteuid()!=0:raise RuntimeError('ROOT_FOR_DISPOSABLE_CROSS_UID_LAB_ONLY')
    host_uid=pwd.getpwnam('oai').pw_uid
    worker_uid=pwd.getpwnam('nobody').pw_uid
    if host_uid==worker_uid:raise RuntimeError('EXPECTED_DISTINCT_UIDS')
    here=str(Path(__file__).resolve())
    with tempfile.TemporaryDirectory(prefix='udx-w10-cross-uid-') as scratch:
        os.chmod(scratch,0o711)
        fixture=Path(scratch)/'fixture'
        fixture.write_bytes(b'cross-uid fd only')
        os.chown(fixture,host_uid,pwd.getpwnam('oai').pw_gid)
        os.chmod(fixture,0o600)
        a,b=credentialed_pair()
        req=str(uuid.uuid4())
        command=lambda role,fd,user: ['setpriv','--reuid',str(user),'--regid',str(user),'--clear-groups',sys.executable,here,role,str(fd),str(host_uid),str(fixture),req,str(worker_uid)]
        # Parent holds socket until both children spawned, then closes immediately.
        try:
            worker=subprocess.Popen(command('worker',b.fileno(),worker_uid),pass_fds=(b.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=str(Path(here).parent.parent))
            host=subprocess.Popen(command('host',a.fileno(),host_uid),pass_fds=(a.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=str(Path(here).parent.parent))
        finally:a.close();b.close()
        host_out,host_err=host.communicate(timeout=25)
        worker_out,worker_err=worker.communicate(timeout=25)
        if host.returncode!=0 or worker.returncode!=0:
            raise RuntimeError(json.dumps({'host_rc':host.returncode,'host_err':host_err,'worker_rc':worker.returncode,'worker_err':worker_err}))
        ho=json.loads(host_out);wo=json.loads(worker_out)
        if ho['size']!=len(b'cross-uid fd only') or not (ho['status']=='OK' and wo['status']=='OK' and wo['direct_access'] is False and ho['durable_grant']=='COMPLETED' and ho['replay']=='DENIED' and ho['reopen_state']=='COMPLETED'):
            raise RuntimeError('INTEGRATION_ASSERTION_FAILED')
        # Negative proof: inherited endpoint alone cannot override message-time UID.
        c,d=credentialed_pair()
        try:
            bad_worker=subprocess.Popen(command('worker_negative',d.fileno(),worker_uid),pass_fds=(d.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=str(Path(here).parent.parent))
            attacker=subprocess.Popen(command('attacker',c.fileno(),worker_uid),pass_fds=(c.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,cwd=str(Path(here).parent.parent))
        finally:c.close();d.close()
        _,attacker_err=attacker.communicate(timeout=25)
        rejected,worker_err=bad_worker.communicate(timeout=25)
        if attacker.returncode or bad_worker.returncode or json.loads(rejected)['rejected']!='CREDENTIALS_MISMATCH':
            raise RuntimeError(json.dumps({'attacker_err':attacker_err,'worker_err':worker_err,'rejection':rejected}))
        print(json.dumps({'two_processes':True,'distinct_uids':True,'worker_no_path_permission':True,'forged_claim_denied':True,
                          'host_uid':host_uid,'worker_uid':worker_uid,'message_time_creds':True,'durable_pretransfer_claim':True,'replay_after_restart_denied':True,
                          'result':'PASS'},sort_keys=True))

if __name__=='__main__':
    if len(sys.argv)==1:parent_main()
    else:role_main(sys.argv[1],*sys.argv[2:])
