"""Two-process localhost demo with Linux kernel-sourced UID identity."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
from udx_ref.core import VERSION
from udx_ref.linux_ipc import request_on_socket, supported


def main():
    if not supported() or os.geteuid() == 0:
        raise RuntimeError('Linux nonroot account required')
    with tempfile.TemporaryDirectory(prefix='udx-demo-') as folder:
        os.chmod(folder,0o700)
        socket_path=Path(folder)/'udx.sock'
        server=subprocess.Popen([sys.executable,'-m','udx_ref.linux_ipc','--runtime-dir',folder,
                                 '--max-connections','2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            for _ in range(500):
                if socket_path.exists():break
                if server.poll() is not None:raise RuntimeError('server exited early')
                time.sleep(.01)
            else:raise RuntimeError('server start timeout')
            raw=json.dumps({'version':VERSION,'request_id':str(uuid.uuid4()),
                'capability':'object.metadata.read','params':{'object_id':'sample-1'}}).encode('utf-8')
            first=request_on_socket(socket_path,raw)
            second=request_on_socket(socket_path,raw)
            _,err=server.communicate(timeout=3)
            if server.returncode:raise RuntimeError(err.decode())
            print(json.dumps({'first':first,'repeat':second,'clean_socket':not os.path.lexists(socket_path)},indent=2))
            if first['code']!='OK' or second['code']!='REPLAY_REJECTED':raise AssertionError('unexpected outcome')
        finally:
            if server.poll() is None:
                server.terminate();server.communicate(timeout=3)


if __name__=='__main__':main()
