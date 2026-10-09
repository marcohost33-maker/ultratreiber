"""Real kernel AF_UNIX test lane: identity from SO_PEERCRED; no privileged calls."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from udx_ref.core import MAX_MESSAGE_BYTES, VERSION
from udx_ref.linux_ipc import request_on_socket, supported, HEADER

@unittest.skipUnless(supported() and hasattr(os, 'geteuid') and os.geteuid()!=0,
                     'Linux non-root kernel-credential lane unavailable')
class LinuxIPC(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='udx-test-')
        self.runtime = Path(self.temp.name)
        os.chmod(self.runtime, 0o700)
        self.sock = self.runtime/'udx.sock'
        self.proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.linux_ipc',
                                       '--runtime-dir', str(self.runtime), '--max-connections', '25'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(500):
            if self.sock.exists():
                break
            if self.proc.poll() is not None:
                out, err = self.proc.communicate()
                self.fail(f'server exited {self.proc.returncode}: {err.decode()}')
            time.sleep(0.01)
        self.assertTrue(self.sock.exists(), 'socket did not appear')
        self.assertEqual(self.sock.stat().st_mode & 0o777, 0o600)
    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill(); self.proc.communicate()
        self.temp.cleanup()
    def wire(self, cap='object.metadata.read', params=None, **other):
        obj={'version':VERSION, 'request_id':str(uuid.uuid4()),
             'capability':cap, 'params':{'object_id':'sample-1'} if params is None else params}
        obj.update(other)
        return json.dumps(obj).encode()
    def test_real_kernel_uid_and_fixture(self):
        answer = request_on_socket(self.sock, self.wire())
        self.assertEqual(answer['code'], 'OK')
        self.assertEqual(answer['data']['size_bytes'], 42)
    def test_fake_identity_in_payload_rejected(self):
        answer = request_on_socket(self.sock, self.wire(actor='uid:0'))
        self.assertEqual(answer['code'], 'INVALID_ENVELOPE')
    def test_no_process_capability(self):
        answer = request_on_socket(self.sock, self.wire('process.spawn', {}))
        self.assertEqual(answer['code'], 'UNKNOWN_CAPABILITY')
    def test_frame_too_large_without_reading_body(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2.0);conn.connect(str(self.sock))
            conn.sendall(HEADER.pack(MAX_MESSAGE_BYTES+1))
            size=HEADER.unpack(self.recv_exact(conn, 4))[0]
            response=json.loads(self.recv_exact(conn,size))
            self.assertEqual(response['code'],'FRAME_TOO_LARGE')
    def test_fragmented_header_and_body(self):
        raw = self.wire()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2.0)
            conn.connect(str(self.sock))
            header = HEADER.pack(len(raw))
            for part in [header[:1], header[1:3], header[3:], raw[:2], raw[2:]]:
                conn.sendall(part)
            size = HEADER.unpack(self.recv_exact(conn, 4))[0]
            response = json.loads(self.recv_exact(conn, size))
            self.assertEqual(response['code'], 'OK')

    def test_truncated_frame_does_not_poison_server(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2.0)
            conn.connect(str(self.sock))
            conn.sendall(HEADER.pack(16) + b'{')
        self.assertEqual(request_on_socket(self.sock,self.wire())['code'], 'OK')

    def test_slowloris_deadline_releases_serial_server(self):
        # One byte sent then a pause longer than whole-request deadline;
        # after timeout, a distinct request must succeed promptly.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as slow:
            slow.settimeout(2.0)
            slow.connect(str(self.sock))
            slow.sendall(b'\x00')
            time.sleep(1.23)
            begin = time.monotonic()
            out=request_on_socket(self.sock, self.wire())
            elapsed=time.monotonic()-begin
            self.assertEqual(out['code'],'OK')
            self.assertLess(elapsed,0.6, f'broker was held by trickle client for {elapsed:.3f}s')

    def test_invalid_utf8(self):
        self.assertEqual(request_on_socket(self.sock,b'\xff')['code'], 'MALFORMED_JSON')
    def test_replay_rejected_on_separate_connections(self):
        raw=self.wire()
        self.assertEqual(request_on_socket(self.sock,raw)['code'], 'OK')
        self.assertEqual(request_on_socket(self.sock,raw)['code'], 'REPLAY_REJECTED')
    def test_no_read_without_capability_grant_in_payload(self):
        ans=request_on_socket(self.sock,self.wire(params={'object_id':'sample-1','grant':'udx.metadata.read'}))
        self.assertEqual(ans['code'], 'INVALID_PARAMS')
    def test_socket_inaccessible_by_directory_mode(self):
        self.assertEqual(self.runtime.stat().st_mode & 0o777,0o700)
    @staticmethod
    def recv_exact(conn, n):
        buf=b''
        while len(buf)<n:
            c=conn.recv(n-len(buf))
            if not c: raise ConnectionError('short frame')
            buf+=c
        return buf

@unittest.skipUnless(supported() and hasattr(os,'geteuid') and os.geteuid()!=0,
                     'Linux non-root required')
class StartupSecurity(unittest.TestCase):
    def test_refuses_world_readable_runtime(self):
        from udx_ref.linux_ipc import verify_directory
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder, 0o755)
            with self.assertRaises(PermissionError):verify_directory(folder)
    def test_refuses_runtime_symlink(self):
        from udx_ref.linux_ipc import verify_directory
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder,0o700)
            with tempfile.TemporaryDirectory() as outer:
                link=Path(outer)/'link'
                link.symlink_to(folder, target_is_directory=True)
                with self.assertRaises(PermissionError):verify_directory(link)
    def test_socket_cleanup_after_bounded_shutdown(self):
        from udx_ref.linux_ipc import serve_forever
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder, 0o700)
            proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.linux_ipc',
                '--runtime-dir', folder, '--max-connections', '1'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sock = Path(folder)/'udx.sock'
            try:
                for _ in range(500):
                    if sock.exists(): break
                    time.sleep(0.01)
                self.assertTrue(sock.exists())
                obj = {'version':VERSION,'request_id':str(uuid.uuid4()),'capability':'device.capabilities.list','params':{}}
                self.assertEqual(request_on_socket(sock,json.dumps(obj).encode())['code'],'OK')
                out,err=proc.communicate(timeout=3)
                self.assertEqual(proc.returncode,0,err.decode())
                self.assertFalse(os.path.lexists(sock))
            finally:
                if proc.poll() is None:
                    proc.terminate();proc.communicate(timeout=3)

    def test_refuses_existing_socket_path(self):
        from udx_ref.linux_ipc import serve_forever
        with tempfile.TemporaryDirectory() as folder:
            os.chmod(folder,0o700)
            path=Path(folder)/'udx.sock'; path.write_text('do not overwrite')
            with self.assertRaises(FileExistsError):serve_forever(folder, max_connections=1)
            self.assertEqual(path.read_text(),'do not overwrite')
