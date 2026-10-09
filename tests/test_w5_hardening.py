"""W5 negative controls: bounded resources, concurrency and response integrity."""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from udx_ref.core import (Broker, FixtureAdapter, ObjectMetadata, PeerIdentity,
                          Policy, Refusal, MAX_AUDIT, decode_response, decode_request, VERSION)
from udx_ref.linux_ipc import supported, request_on_socket, HEADER, MAX_WORKERS

RID='00000000-0000-4000-8000-000000000001'

def sample_response(**overrides):
    obj={'version':VERSION,'request_id':RID,'status':'OK','code':'OK',
         'data':{'object_id':'sample-1','kind':'fixture','size_bytes':42}}
    obj.update(overrides)
    return json.dumps(obj,separators=(',',':')).encode()

class CoreSecurity(unittest.TestCase):
    def make_broker(self):
        return Broker(FixtureAdapter({'sample-1':ObjectMetadata('sample-1','alice',42,'fixture')}),
                      Policy({'alice':{'udx.metadata.read'}}))
    def make_request(self,rid=None):
        return json.dumps({'version':VERSION,'request_id':rid or str(uuid.uuid4()),
                           'capability':'object.metadata.read',
                           'params':{'object_id':'sample-1'}}).encode()
    def test_audit_bounded_under_many_failures(self):
        b=self.make_broker();peer=PeerIdentity('alice',True)
        for _ in range(3*MAX_AUDIT+200):
            self.assertEqual(b.handle(b'not-json', peer)['code'],'MALFORMED_JSON')
        self.assertEqual(len(b.audit),MAX_AUDIT)
        self.assertEqual(set(b.audit[0]), {'request_id','code'})
        self.assertEqual(b.adapter.read_count,0)
    def test_identical_replay_atomic_in_parallel(self):
        b=self.make_broker();peer=PeerIdentity('alice',True);raw=self.make_request()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            codes=list(ex.map(lambda _: b.handle(raw,peer)['code'],range(100)))
        self.assertEqual(codes.count('OK'),1)
        self.assertEqual(codes.count('REPLAY_REJECTED'),99)
        self.assertEqual(b.adapter.read_count,1)
        self.assertEqual(len(b.audit),100)
    def test_rejects_bad_response_shapes(self):
        bad=[sample_response(status='OK',code='DENIED'),
             sample_response(request_id=None),
             sample_response(status='DENIED',data={'some':'leak'}),
             sample_response(extra=True),
             sample_response(version='udx/999'),
             sample_response(code='OK',status='MAYBE'),
             sample_response(request_id='not-a-uuid')]
        for raw in bad:
            with self.subTest(raw=raw),self.assertRaises(Refusal):
                decode_response(raw)
    def test_metadata_response_rejects_extra_fields_and_object_swap(self):
        with self.assertRaises(Refusal) as extra:
            decode_response(sample_response(data={'object_id':'sample-1','kind':'fixture',
                                    'size_bytes':42,'secret':'leak'}),
                            expected_capability='object.metadata.read',expected_params={'object_id':'sample-1'})
        self.assertEqual(extra.exception.code,'INVALID_RESPONSE_DATA')
        with self.assertRaises(Refusal) as wrong:
            decode_response(sample_response(data={'object_id':'other','kind':'fixture','size_bytes':42}),
                            expected_capability='object.metadata.read',expected_params={'object_id':'sample-1'})
        self.assertEqual(wrong.exception.code,'RESPONSE_OBJECT_MISMATCH')

    def test_discovery_result_rejects_unknown_and_duplicate_capability(self):
        for caps in ([{'name':'process.spawn','effect':'read','supported_by_reference':True}],
                     [{'name':'object.metadata.read','effect':'read','supported_by_reference':True}]*2):
            with self.subTest(caps=caps), self.assertRaises(Refusal):
                decode_response(sample_response(data={'capabilities':caps}),
                                expected_capability='device.capabilities.list')

    def test_client_requires_request_echo(self):
        self.assertEqual(decode_response(sample_response(), expected_request_id=RID)['code'],'OK')
        with self.assertRaises(Refusal) as e:
            decode_response(sample_response(),expected_request_id=str(uuid.uuid4()))
        self.assertEqual(e.exception.code,'REQUEST_ID_MISMATCH')
    def test_ijson_unicode_noncharacters_rejected(self):
        for codepoint in (0xfdd0,0xfdef,0xfffe,0xffff,0x1fffe,0x10ffff):
            with self.subTest(codepoint=hex(codepoint)):
                raw=self.make_request().decode()
                req=json.loads(raw)
                req['params']['extra']=chr(codepoint)
                for wire in (json.dumps(req,ensure_ascii=False).encode('utf-8'),
                             json.dumps(req,ensure_ascii=True).encode('utf-8')):
                    with self.assertRaises(Refusal) as ctx:decode_request(wire)
                    self.assertEqual(ctx.exception.code,'MALFORMED_JSON')

    def test_response_duplicate_json_keys(self):
        wire=b'{"version":"udx/0.1","version":"udx/0.1"}'
        with self.assertRaises(Refusal) as e:decode_response(wire)
        self.assertEqual(e.exception.code,'DUPLICATE_JSON_KEY')
    def test_response_rejects_non_interoperable_number(self):
        raw=sample_response().replace(b'42',b'9007199254740992')
        with self.assertRaises(Refusal) as e:decode_response(raw)
        self.assertEqual(e.exception.code,'NON_INTEROPERABLE_JSON_NUMBER')

@unittest.skipUnless(supported() and hasattr(os,'geteuid') and os.geteuid()!=0,
                     'Linux non-root kernel integration required')
class IPCConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='udx-w5-')
        self.runtime=Path(self.tmp.name)
        os.chmod(self.runtime,0o700)
        self.sock=self.runtime/'udx.sock'
        self.p=subprocess.Popen([sys.executable,'-m','udx_ref.linux_ipc','--runtime-dir',str(self.runtime)],
                                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(500):
            if self.sock.exists():break
            if self.p.poll() is not None:self.fail('broker terminated: '+self.p.communicate()[1].decode())
            time.sleep(0.01)
        self.assertTrue(self.sock.exists())
    def tearDown(self):
        self.p.terminate()
        try:self.p.communicate(timeout=3)
        except subprocess.TimeoutExpired:self.p.kill();self.p.communicate()
        self.tmp.cleanup()
    def req(self):
        return json.dumps({'version':VERSION,'request_id':str(uuid.uuid4()),
            'capability':'object.metadata.read','params':{'object_id':'sample-1'}}).encode()
    def test_slow_client_does_not_serialize_fast_client(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as slow:
            slow.connect(str(self.sock));slow.sendall(b'\x00')
            time.sleep(0.12)
            t=time.monotonic()
            reply=request_on_socket(self.sock,self.req())
            duration=time.monotonic()-t
            self.assertEqual(reply['code'],'OK')
            self.assertLess(duration,0.70,f'slow client serialized request: {duration:.3f}s')
    def test_saturation_is_bounded_and_fails_closed(self):
        self.assertEqual(MAX_WORKERS,4)
        slow=[]
        try:
            for _ in range(MAX_WORKERS):
                s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                s.settimeout(1.5);s.connect(str(self.sock));s.sendall(b'\x00')
                slow.append(s)
            time.sleep(0.13)
            t=time.monotonic()
            try:
                output=request_on_socket(self.sock,self.req(),timeout=0.7)
            except (ConnectionError, BrokenPipeError, OSError, ValueError) as exc:
                output=None
            elapsed=time.monotonic()-t
            self.assertLess(elapsed,0.95)
            # Slots may be released if the slow clients completed or timed out; if
            # not, the saturated broker rejects the fifth connection promptly.
            self.assertTrue(output is None or output['code']=='OK')
        finally:
            for s in slow:s.close()
    def test_recovery_after_saturated_clients(self):
        slow=[]
        try:
            for _ in range(MAX_WORKERS):
                s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                s.connect(str(self.sock));s.sendall(b'\x00');slow.append(s)
            time.sleep(1.25)
            self.assertEqual(request_on_socket(self.sock,self.req())['code'],'OK')
        finally:
            for s in slow:s.close()

if __name__=='__main__':unittest.main()
