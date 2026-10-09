"""W8 tests: private fd transfer, error handling and real child execution."""
import array, hashlib, json, os, pathlib, socket, subprocess, sys, tempfile, unittest, uuid
from udx_ref.fd_handoff import (HandoffError, private_pair, send_approved_fd,
                                handle_once, recv_status, _recv_fd, supported, MAX_WIRE)
from udx_ref.fd_reader import ReadGuardError

@unittest.skipUnless(supported(), 'Linux SCM_RIGHTS / seqpacket required')
class W8FdTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='udx-w8-tests-')
        self.p=pathlib.Path(self.t.name)/'fixture'
        self.contents=b'UDX-private-test-file-bytes'
        self.p.write_bytes(self.contents)
        self.a,self.b=private_pair()
        self.id=str(uuid.uuid4())
    def tearDown(self):
        self.a.close();self.b.close();self.t.cleanup()
    def send_raw(self, data, *fds):
        anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
        return self.a.sendmsg([data],anc)
    def wire(self):
        return json.dumps({'v':'udx/fd/0.1','op':'inspect.readonly','id':self.id}).encode()
    def test_valid_metadata_no_raw_payload(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        result=handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid())
        self.assertEqual(result['sha256'],hashlib.sha256(self.contents).hexdigest())
        self.assertEqual(result['size'],len(self.contents))
        self.assertNotIn('UDX-private',json.dumps(result))
        self.assertEqual(recv_status(self.a,self.id),result)
    def test_readonly_not_write_fd(self):
        fd=os.open(self.p,os.O_RDWR)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        with self.assertRaises(ReadGuardError):handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid())
    def test_directory_rejected(self):
        fd=os.open(self.t.name,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        with self.assertRaises(ReadGuardError):handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid())
    def test_wrong_owner_denied(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        with self.assertRaises(ReadGuardError):handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid()+1)
    def test_wrong_peer_uid_denied(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        with self.assertRaises(HandoffError):handle_once(self.b,expected_uid=os.getuid()+1,owner_uid=os.getuid())
        # socket closed on teardown; queued descriptor is kernel-managed
    def test_too_many_fds(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:self.send_raw(self.wire(),fd,fd)
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'EXPECTED_EXACTLY_ONE_FD'):_recv_fd(self.b,os.getuid())
    def test_no_fds(self):
        self.send_raw(self.wire())
        with self.assertRaisesRegex(HandoffError,'EXPECTED_EXACTLY_ONE_FD'):_recv_fd(self.b,os.getuid())
    def test_truncated_packet(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:self.send_raw(b'X'*(MAX_WIRE+5),fd)
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'TRUNCATED_PACKET'):_recv_fd(self.b,os.getuid())
    def test_truncated_control(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:self.send_raw(self.wire(),*[fd]*8)
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'TRUNCATED_PACKET'):_recv_fd(self.b,os.getuid())
    def test_malformed_and_duplicate_json(self):
        for raw in [b'{',b'{"v":"udx/fd/0.1","v":"udx/fd/0.1","op":"inspect.readonly","id":"'+self.id.encode()+b'"}',
                    b'{"path":"/etc/passwd"}', b'[]']:
            with self.subTest(raw=raw):
                fd=os.open(self.p,os.O_RDONLY)
                try:self.send_raw(raw,fd)
                finally:os.close(fd)
                with self.assertRaises(HandoffError):_recv_fd(self.b,os.getuid())
    def test_exact_request_id(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid())
        with self.assertRaisesRegex(HandoffError,'RESPONSE_SCOPE_MISMATCH'):
            recv_status(self.a,str(uuid.uuid4()))
    def test_response_injected_fields_and_size(self):
        for response in [dict(v='udx/fd/0.1',id=self.id,status='SEALED_METADATA',size=True,sha256='0'*64),
                         dict(v='udx/fd/0.1',id=self.id,status='SEALED_METADATA',size=2,sha256='0'*64,secret='x')]:
            self.b.send(json.dumps(response).encode())
            with self.assertRaises(HandoffError):recv_status(self.a,self.id)
    def test_client_response_fd_injection_closed(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:self.b.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        finally:os.close(fd)
        with self.assertRaises(HandoffError):recv_status(self.a,self.id)
    def test_limit(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:send_approved_fd(self.a,fd,self.id)
        finally:os.close(fd)
        with self.assertRaises(ReadGuardError):handle_once(self.b,expected_uid=os.getuid(),owner_uid=os.getuid(),limit=2)
    def test_no_fd_leak_on_multiple_fds(self):
        before=len(os.listdir('/proc/self/fd'))
        for _ in range(40):
            fd=os.open(self.p,os.O_RDONLY)
            try:self.send_raw(self.wire(),fd,fd)
            finally:os.close(fd)
            with self.assertRaises(HandoffError):_recv_fd(self.b,os.getuid())
        self.assertEqual(before,len(os.listdir('/proc/self/fd')))
    def test_separate_process(self):
        path=pathlib.Path(__file__).resolve().parent.parent/'tools'/'demo_w8_fd_handoff.py'
        r=subprocess.run([sys.executable,str(path)],cwd=str(path.parent.parent),capture_output=True,text=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr)
        o=json.loads(r.stdout)
        self.assertEqual(o['child_exit'],0)
        self.assertTrue(o['fixture_only'])

if __name__=='__main__':unittest.main()
