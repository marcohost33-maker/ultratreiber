"""Optional Linux cross-UID socket permissions probe, needs root test orchestrator.

Creates a temporary 0700 directory owned by 'oai' fixture user and verifies that
'nobody' cannot connect, then owner can connect. No production account management.
DO NOT run on live production hosts; purely controlled CI container test.
"""
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import uuid


def main():
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('controlled root CI container required')
    owner=pwd.getpwnam('oai')
    pwd.getpwnam('nobody')
    with tempfile.TemporaryDirectory(prefix='udx-crossuid-') as folder:
        os.chown(folder,owner.pw_uid,owner.pw_gid)
        os.chmod(folder,0o700)
        path=str(Path(folder)/'udx.sock')
        server=subprocess.Popen(['runuser','-u','oai','--',sys.executable,'-m','udx_ref.linux_ipc',
                                 '--runtime-dir',folder,'--max-connections','1'],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            for _ in range(500):
                if os.path.lexists(path):break
                if server.poll() is not None:
                    raise RuntimeError('server stopped before socket creation')
                time.sleep(.01)
            else:raise RuntimeError('server bind timeout')
            attempt = subprocess.run(['runuser','-u','nobody','--',sys.executable,'-c',
              'import socket,sys; s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1])',path],
              capture_output=True,text=True,timeout=3)
            denied=attempt.returncode!=0 and 'PermissionError' in attempt.stderr
            if not denied:raise AssertionError('cross UID denial not witnessed')
            raw=json.dumps({'version':'udx/0.1','request_id':str(uuid.uuid4()),
                            'capability':'object.metadata.read','params':{'object_id':'sample-1'}}).encode()
            approved=subprocess.run(['runuser','-u','oai','--',sys.executable,'-c',
              'import sys;from udx_ref.linux_ipc import request_on_socket;print(request_on_socket(sys.argv[1],bytes.fromhex(sys.argv[2]))["code"])',
              path,raw.hex()],capture_output=True,text=True,timeout=3)
            if approved.returncode or approved.stdout.strip()!='OK':raise AssertionError(approved.stderr)
            _,stderr=server.communicate(timeout=3)
            if server.returncode!=0:raise AssertionError(stderr.decode())
            print(json.dumps({'different_uid_connect':'PERMISSION_DENIED',
                              'owner_uid_request':'OK','test':'AF_UNIX pathname permission negative control',
                              'status':'PASS', 'note':'Not a claim of protection against root, same-UID attackers, or namespace attacks.'},indent=2))
        finally:
            if server.poll() is None:
                server.terminate();server.communicate(timeout=3)

if __name__=='__main__':main()
