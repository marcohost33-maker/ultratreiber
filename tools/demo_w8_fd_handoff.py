"""Real Linux inter-process SCM_RIGHTS demo on trusted *fixture* data.
No graphical consent claims; no general OS-path/IPC exposure.
"""
import json, os, socket, subprocess, sys, tempfile, uuid
from pathlib import Path
from udx_ref.fd_handoff import private_pair, send_approved_fd, recv_status, handle_once

def main():
    if len(sys.argv)>1 and sys.argv[1]=='child':
        fd=int(sys.argv[2]); s=socket.socket(fileno=fd)
        try:handle_once(s,expected_uid=os.getuid(),owner_uid=os.getuid())
        finally:s.close()
        return
    with tempfile.TemporaryDirectory(prefix='udx-w8-fixture-') as d:
        p=Path(d)/'fixture.bin';p.write_bytes(b'UDX-W8-in-process-and-interprocess-safety-fixture')
        left,right=private_pair()
        try:
            r=subprocess.Popen([sys.executable, __file__,'child',str(right.fileno())], pass_fds=(right.fileno(),),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            right.close()
            request_id=str(uuid.uuid4())
            data_fd=os.open(p,os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:send_approved_fd(left,data_fd,request_id)
            finally:os.close(data_fd)
            ans=recv_status(left,request_id)
            out,err=r.communicate(timeout=3)
            if r.returncode != 0:raise RuntimeError(f'child return {r.returncode}: {err[:300]!r}')
            print(json.dumps({'result':ans,'child_exit':r.returncode,'fixture_only':True},sort_keys=True))
        finally:left.close();right.close()
if __name__=='__main__':main()
