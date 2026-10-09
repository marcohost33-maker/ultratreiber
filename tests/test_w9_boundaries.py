"""W9 message-time credentials, negative packets, portal response shape."""
import array
import json
import os
import pathlib
import socket
import tempfile
import unittest
import uuid
from udx_ref.credentialed_handoff import (
    available, credentialed_pair, _receive, send_readonly_request, process_one,
    read_verified_reply)
from udx_ref.fd_handoff import HandoffError, PROTOCOL, OPERATION, MAX_WIRE, MAX_STATUS
from udx_ref.portal_boundary import PortalRejected, validate_chooser_result

@unittest.skipUnless(available(), 'Linux SO_PASSCRED required')
class CredentialedTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w9-')
        self.path = pathlib.Path(self.dir.name) / 'data'
        self.path.write_bytes(b'w9-ephemeral')
        self.a,self.b=credentialed_pair()
        self.request_id=str(uuid.uuid4())
    def tearDown(self):
        self.a.close(); self.b.close(); self.dir.cleanup()
    def transfer(self):
        fd=os.open(self.path, os.O_RDONLY)
        try:send_readonly_request(self.a, fd, self.request_id)
        finally:os.close(fd)
    def test_valid_message_credentials_and_reply(self):
        self.transfer()
        result=process_one(self.b,expected_sender_uid=os.getuid(),source_owner_uid=os.getuid())
        self.assertEqual(result['size'],len(b'w9-ephemeral'))
        self.assertEqual(read_verified_reply(self.a, expected_worker_uid=os.getuid(),request_id=self.request_id),result)
    def test_bad_sender_uid_rejected(self):
        self.transfer()
        with self.assertRaisesRegex(HandoffError,'CREDENTIALS_MISMATCH'):
            process_one(self.b,expected_sender_uid=os.getuid()+1,source_owner_uid=os.getuid())
    def test_bad_reply_uid_rejected(self):
        self.transfer();process_one(self.b,expected_sender_uid=os.getuid(),source_owner_uid=os.getuid())
        with self.assertRaisesRegex(HandoffError,'CREDENTIALS_MISMATCH'):
            read_verified_reply(self.a,expected_worker_uid=os.getuid()+1,request_id=self.request_id)
    def test_disabled_passcred_denied(self):
        self.b.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,0)
        with self.assertRaisesRegex(HandoffError,'PASSCRED_REQUIRED'):
            _receive(self.b,MAX_WIRE,expected_uid=os.getuid(),expect_fd=True)
    def test_extra_fd_denied(self):
        fd=os.open(self.path,os.O_RDONLY)
        try:
            self.a.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd,fd]))])
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'FD_CARDINALITY'):
            _receive(self.b,MAX_WIRE,expected_uid=os.getuid(),expect_fd=True)
    def test_missing_fd_denied(self):
        self.a.send(b'{}')
        with self.assertRaisesRegex(HandoffError,'FD_CARDINALITY'):
            _receive(self.b,MAX_WIRE,expected_uid=os.getuid(),expect_fd=True)
    def test_overlong_wire_denied(self):
        fd=os.open(self.path,os.O_RDONLY)
        try:self.a.sendmsg([b'A'*(MAX_WIRE+32)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'TRUNCATED_PACKET'):
            _receive(self.b,MAX_WIRE,expected_uid=os.getuid(),expect_fd=True)
    def test_missing_ancillary_response_denied(self):
        self.b.send(b'{}')
        with self.assertRaises(HandoffError):read_verified_reply(self.a,expected_worker_uid=os.getuid(),request_id=self.request_id)
    def test_response_scope_denied(self):
        self.b.send(json.dumps(dict(v=PROTOCOL,id=str(uuid.uuid4()),status='SEALED_METADATA',size=4,sha256='0'*64)).encode())
        with self.assertRaisesRegex(HandoffError,'INVALID_REPLY'):
            read_verified_reply(self.a,expected_worker_uid=os.getuid(),request_id=self.request_id)
    def test_request_extra_identity_field_denied(self):
        fd=os.open(self.path,os.O_RDONLY)
        try:
            data=json.dumps(dict(v=PROTOCOL,op=OPERATION,id=self.request_id,uid=os.getuid())).encode()
            self.a.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'INVALID_ENVELOPE'):
            process_one(self.b,expected_sender_uid=os.getuid(),source_owner_uid=os.getuid())
    def test_reply_fd_injection_denied_and_closed(self):
        fd=os.open(self.path,os.O_RDONLY)
        try:self.b.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        finally:os.close(fd)
        with self.assertRaisesRegex(HandoffError,'FD_CARDINALITY'):
            read_verified_reply(self.a,expected_worker_uid=os.getuid(),request_id=self.request_id)
    def test_fd_leak_repeated_bad_packets(self):
        baseline=len(os.listdir('/proc/self/fd'))
        for i in range(25):
            fd=os.open(self.path,os.O_RDONLY)
            try:self.a.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd,fd]))])
            finally:os.close(fd)
            with self.assertRaises(HandoffError):_receive(self.b,MAX_WIRE,expected_uid=os.getuid(),expect_fd=True)
        self.assertEqual(len(os.listdir('/proc/self/fd')),baseline)

class PortalShapeTests(unittest.TestCase):
    def test_one_local_file(self):
        self.assertEqual(validate_chooser_result(0,{'uris':['file:///tmp/approved%20name.txt']}),'file:///tmp/approved%20name.txt')
    def test_cancel_error_denied(self):
        for code in (1,2,True,None,-1):
            with self.subTest(code=code),self.assertRaises(PortalRejected):
                validate_chooser_result(code,{'uris':['file:///tmp/x']})
    def test_uri_bad_cases(self):
        for uri in ('https://example.com/a','file://badhost/tmp/x', 'file:///tmp/%00secret',
                    'file:///tmp/../etc/shadow','file:///tmp/%2e%2e/private',
                    'file:relative','file:///tmp/a?wrong=1','file:///tmp/x#fragment',
                    'file:///tmp/\\evil'):
            with self.subTest(uri=uri),self.assertRaises(PortalRejected):
                validate_chooser_result(0,{'uris':[uri]})
    def test_multiple_and_writable_denied(self):
        for res in ({'uris':['file:///tmp/a','file:///tmp/b']},
                    {'uris':['file:///tmp/a'],'writable':True},
                    {'uris':['file:///tmp/a'],'grant':'yes'},
                    {'uris':'file:///tmp/a'}):
            with self.subTest(res=res),self.assertRaises(PortalRejected):
                validate_chooser_result(0,res)

if __name__=='__main__':unittest.main()
