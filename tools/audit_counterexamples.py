"""Concrete red/green counterexamples for W4 vs W5; Linux nonroot only."""
import json,os,socket,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from udx_ref.linux_ipc import request_on_socket
from udx_ref.core import decode_request,Refusal

ROOT=Path(__file__).resolve().parents[1]
W4=ROOT.parent/'udx_standalone_v0_4'
WIRE=json.dumps({'version':'udx/0.1','request_id':str(uuid.uuid4()),
 'capability':'object.metadata.read','params':{'object_id':'sample-1'}}).encode()
NONCHAR=json.dumps({'version':'udx/0.1','request_id':str(uuid.uuid4()),
 'capability':'object.metadata.read','params':{'object_id':'sample-1','n':'\ufffe'}},ensure_ascii=True).encode()

def probe_server(root):
    with tempfile.TemporaryDirectory(prefix='udx-redgreen-') as d:
        os.chmod(d,0o700)
        path=Path(d)/'udx.sock'
        env=dict(os.environ,PYTHONPATH=str(root))
        p=subprocess.Popen([sys.executable,'-m','udx_ref.linux_ipc','--runtime-dir',d],
                            env=env,cwd=str(root),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for _ in range(400):
                if path.exists():break
                if p.poll() is not None:raise RuntimeError(p.communicate()[1].decode())
                time.sleep(.01)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as slow:
                slow.settimeout(2.0);slow.connect(str(path));slow.sendall(b'\x00')
                time.sleep(.12)
                t=time.perf_counter()
                ans=request_on_socket(path,WIRE)
                seconds=time.perf_counter()-t
                assert ans['code']=='OK'
                return seconds
        finally:
            p.terminate()
            try:p.communicate(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.communicate()

def parser_code(module_path):
    import importlib.util
    name='isolated_'+module_path.name.replace('.','_')
    # Avoid mixing Python modules: use isolated subprocess import via PYTHONPATH.
    p=subprocess.run([sys.executable,'-c',
      'from udx_ref.core import decode_request,Refusal; import sys;\n'
      'try: decode_request(sys.stdin.buffer.read()); print("ACCEPT")\n'
      'except Refusal as e: print(e.code)'],
      input=NONCHAR,env=dict(os.environ,PYTHONPATH=str(module_path)),cwd=str(module_path),capture_output=True)
    if p.returncode:raise RuntimeError(p.stderr.decode())
    return p.stdout.decode().strip()

if __name__=='__main__':
    if os.geteuid()==0:raise RuntimeError('nonroot required')
    result={}
    for label,path in [('w4',W4),('w5',ROOT)]:
        result[label]={'noncharacter_parser':parser_code(path),'slow_peer_fast_client_s':probe_server(path)}
    print(json.dumps(result,indent=2))
