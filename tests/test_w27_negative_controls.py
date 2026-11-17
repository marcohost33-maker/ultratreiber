"""W27: negative controls for refusals that had none.

The two-sided guard sweep (tools/guard_sweep.py) removed each refusal in turn
(``ADMIT`` mutant). 80 of 163 refusals in the portable runtime could be removed
without any test noticing. Each test below provokes exactly one such refusal and
requires its code, so that removing the guard turns the test red.

Where the real operating system cannot produce the condition (a kernel that
reports pid 0, a file system that lies about a size), the test substitutes the
smallest possible fake for the OS call and says so. Refusals that no input can
reach at all are not tested here; they are pinned with a reason in
``evidence/w27_guard_sweep_baseline.json``.
"""
from __future__ import annotations

import array
import hashlib
import json
import os
import pathlib
import socket
import struct
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from udx_ref import fd_reader, linux_ipc, sealed_snapshot
from udx_ref.core import (MAX_MESSAGE_BYTES, VERSION, PeerIdentity, Refusal, decode_request,
                          decode_response)
from udx_ref.fd_handoff import supported as handoff_supported

LINUX = handoff_supported()
RID = '00000000-0000-4000-8000-000000000001'


def response(**overrides):
    obj = {'version': VERSION, 'request_id': RID, 'status': 'OK', 'code': 'OK',
           'data': {'object_id': 'sample-1', 'kind': 'fixture', 'size_bytes': 42}}
    obj.update(overrides)
    return json.dumps(obj, separators=(',', ':')).encode()


class Core(unittest.TestCase):
    def code(self, fn, *args, **kwargs):
        with self.assertRaises(Refusal) as caught:
            fn(*args, **kwargs)
        return caught.exception.code

    def test_request_must_be_bytes_not_a_bytes_like_object(self):
        wire = json.dumps({'version': VERSION, 'request_id': RID, 'capability': 'device.capabilities.list',
                           'params': {}}).encode()
        self.assertEqual(decode_request(wire)['request_id'], RID)        # positive control
        self.assertEqual(self.code(decode_request, bytearray(wire)), 'INVALID_FRAME')

    def test_response_must_be_bytes_not_a_bytes_like_object(self):
        self.assertEqual(decode_response(response())['code'], 'OK')      # positive control
        self.assertEqual(self.code(decode_response, bytearray(response())), 'INVALID_RESPONSE')

    def test_response_frame_limit(self):
        padded = response() + b' ' * (MAX_MESSAGE_BYTES + 1 - len(response()))
        self.assertEqual(decode_response(padded[:MAX_MESSAGE_BYTES])['code'], 'OK')
        self.assertEqual(self.code(decode_response, padded), 'FRAME_TOO_LARGE')

    def test_response_request_id_must_be_a_string(self):
        self.assertEqual(self.code(decode_response, response(request_id=5)), 'INVALID_RESPONSE')

    def test_response_code_syntax(self):
        ok = response(status='DENIED', code='POLICY_DENIED', data=None)
        self.assertEqual(decode_response(ok)['code'], 'POLICY_DENIED')
        for bad in ('policy_denied', 'Denied', '', 'A1', 7):
            with self.subTest(code=bad):
                self.assertEqual(self.code(decode_response, response(status='DENIED', code=bad, data=None)),
                                 'INVALID_RESPONSE')

    def test_metadata_response_field_types(self):
        expect = dict(expected_request_id=RID, expected_capability='object.metadata.read')
        self.assertEqual(decode_response(response(), **expect)['code'], 'OK')
        for field, bad in (('size_bytes', True), ('size_bytes', -1), ('kind', 'Fixture'), ('object_id', 7)):
            data = {'object_id': 'sample-1', 'kind': 'fixture', 'size_bytes': 42, field: bad}
            with self.subTest(field=field, bad=bad):
                self.assertEqual(self.code(decode_response, response(data=data), **expect),
                                 'INVALID_RESPONSE_DATA')

    def test_capability_list_response_shape(self):
        expect = dict(expected_request_id=RID, expected_capability='device.capabilities.list')
        self.assertEqual(decode_response(response(data={'capabilities': []}), **expect)['code'], 'OK')
        self.assertEqual(self.code(decode_response, response(data={'capabilities': [], 'more': 1}), **expect),
                         'INVALID_RESPONSE_DATA')
        self.assertEqual(self.code(decode_response, response(data={'capabilities': {}}), **expect),
                         'INVALID_RESPONSE_DATA')


class FakePeerSocket:
    """Stand-in for a kernel that reports an impossible peer (pid 0)."""
    family = socket.AF_UNIX
    type = socket.SOCK_SEQPACKET

    def __init__(self, pid, uid, gid):
        self._raw = struct.pack('3i', pid, uid, gid)

    def getsockopt(self, level, option, size):
        return self._raw


@unittest.skipUnless(LINUX, 'Linux SCM_RIGHTS / seqpacket required')
class FdHandoff(unittest.TestCase):
    def setUp(self):
        from udx_ref import fd_handoff
        self.h = fd_handoff
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w27-')
        self.path = pathlib.Path(self.dir.name) / 'fixture'
        self.path.write_bytes(b'w27-fixture')
        self.a, self.b = fd_handoff.private_pair()
        self.id = str(uuid.uuid4())
        self.uid = os.getuid()

    def tearDown(self):
        self.a.close(); self.b.close(); self.dir.cleanup()

    def send(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            self.h.send_approved_fd(self.a, fd, self.id)
        finally:
            os.close(fd)

    def status(self, **overrides):
        obj = {'v': self.h.PROTOCOL, 'id': self.id, 'status': 'SEALED_METADATA', 'size': 11,
               'sha256': hashlib.sha256(b'w27-fixture').hexdigest()}
        obj.update(overrides)
        return json.dumps(obj).encode()

    def test_stream_socket_is_not_an_accepted_transport(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.settimeout(0.3); right.settimeout(0.3)
            with self.assertRaisesRegex(self.h.HandoffError, 'BAD_TRANSPORT'):
                self.h._recv_fd(right, self.uid)
        finally:
            left.close(); right.close()

    def test_impossible_peer_credentials_are_no_peer(self):
        self.assertEqual(self.h._peer_uid(FakePeerSocket(4242, self.uid, 0)), self.uid)   # positive control
        for pid, uid, gid in ((0, self.uid, 0), (4242, -1, 0), (4242, self.uid, -1)):
            with self.subTest(pid=pid, uid=uid, gid=gid), self.assertRaisesRegex(self.h.HandoffError, 'NO_OS_PEER'):
                self.h._peer_uid(FakePeerSocket(pid, uid, gid))

    def test_foreign_ancillary_data_is_refused(self):
        # With SO_PASSCRED on the receiver the kernel adds SCM_CREDENTIALS to an
        # otherwise valid message. This lane expects SCM_RIGHTS and nothing else.
        self.b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.send()
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(self.h.HandoffError, 'BAD_ANCILLARY|TRUNCATED_PACKET') as caught:
            self.h._recv_fd(self.b, self.uid)
        self.assertEqual(str(caught.exception), 'BAD_ANCILLARY')
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_host_policy_types(self):
        for kwargs in (dict(owner_uid=True), dict(owner_uid=-1), dict(owner_uid=self.uid, limit=0),
                       dict(owner_uid=self.uid, limit=self.h.MAX_READ + 1)):
            with self.subTest(kwargs=kwargs):
                self.send()
                with self.assertRaisesRegex(self.h.HandoffError, 'INVALID_HOST_POLICY'):
                    self.h.handle_once(self.b, expected_uid=self.uid, **kwargs)
                self.h._recv_fd(self.b, self.uid)                # nothing was consumed by the refusal

    def test_unsupported_platform_gets_no_pair(self):
        with mock.patch.object(self.h, 'supported', return_value=False):
            with self.assertRaisesRegex(self.h.HandoffError, 'UNSUPPORTED_PLATFORM'):
                self.h.private_pair()

    def test_send_requires_a_canonical_request_id(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            for bad in ('nope', self.id.upper(), self.id.replace('-', '')):
                with self.subTest(bad=bad), self.assertRaisesRegex(self.h.HandoffError, 'BAD_ARGUMENT'):
                    self.h.send_approved_fd(self.a, fd, bad)
        finally:
            os.close(fd)
        self.b.settimeout(0.1)
        with self.assertRaises(TimeoutError):                    # nothing was sent
            self.b.recv(1)

    def test_status_requires_a_canonical_expected_id(self):
        self.b.send(self.status())
        with self.assertRaisesRegex(self.h.HandoffError, 'BAD_ARGUMENT'):
            self.h.recv_status(self.a, 'nope')

    def test_valid_status_with_an_attached_descriptor_is_refused_and_closed(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            self.b.sendmsg([self.status()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        finally:
            os.close(fd)
        before = len(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(self.h.HandoffError, 'BAD_RESPONSE_CONTROL'):
            self.h.recv_status(self.a, self.id)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_status_digest_syntax(self):
        self.b.send(self.status())
        self.assertEqual(self.h.recv_status(self.a, self.id)['size'], 11)        # positive control
        for bad in ('G' * 64, 'A' * 64, 'a' * 63, 7):
            with self.subTest(bad=bad):
                self.b.send(self.status(sha256=bad))
                with self.assertRaisesRegex(self.h.HandoffError, 'BAD_RESPONSE_DIGEST'):
                    self.h.recv_status(self.a, self.id)


@unittest.skipUnless(LINUX and hasattr(socket, 'SO_PASSCRED'), 'Linux SO_PASSCRED required')
class CredentialedHandoff(unittest.TestCase):
    def setUp(self):
        from udx_ref import credentialed_handoff
        self.c = credentialed_handoff
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w27-')
        self.path = pathlib.Path(self.dir.name) / 'data'
        self.path.write_bytes(b'w27-credentialed')
        self.a, self.b = credentialed_handoff.credentialed_pair()
        self.id = str(uuid.uuid4())
        self.uid = os.getuid()

    def tearDown(self):
        self.a.close(); self.b.close(); self.dir.cleanup()

    def transfer(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            self.c.send_readonly_request(self.a, fd, self.id)
        finally:
            os.close(fd)

    def reply(self, **overrides):
        obj = {'v': self.c.PROTOCOL, 'id': self.id, 'status': 'SEALED_METADATA', 'size': 16,
               'sha256': hashlib.sha256(b'w27-credentialed').hexdigest()}
        obj.update(overrides)
        return json.dumps(obj).encode()

    def test_stream_socket_is_not_an_accepted_transport(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            fd = os.open(self.path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(self.c.HandoffError, 'BAD_TRANSPORT'):
                    self.c.send_readonly_request(left, fd, self.id)
            finally:
                os.close(fd)
        finally:
            left.close(); right.close()

    def test_identity_policy_types(self):
        for bad in (-1, True, '0'):
            with self.subTest(bad=bad):
                self.transfer()
                with self.assertRaisesRegex(self.c.HandoffError, 'INVALID_IDENTITY_POLICY'):
                    self.c.process_one(self.b, expected_sender_uid=bad, source_owner_uid=self.uid)
                self.c._receive(self.b, self.c.MAX_WIRE, expected_uid=self.uid, expect_fd=True)

    def test_host_policy_types(self):
        for kwargs in (dict(source_owner_uid=-1), dict(source_owner_uid=True),
                       dict(source_owner_uid=self.uid, limit=0)):
            with self.subTest(kwargs=kwargs):
                self.transfer()
                with self.assertRaisesRegex(self.c.HandoffError, 'INVALID_HOST_POLICY'):
                    self.c.process_one(self.b, expected_sender_uid=self.uid, **kwargs)
                self.c._receive(self.b, self.c.MAX_WIRE, expected_uid=self.uid, expect_fd=True)

    def test_unsupported_platform_gets_no_pair(self):
        with mock.patch.object(self.c, 'available', return_value=False):
            with self.assertRaisesRegex(self.c.HandoffError, 'UNSUPPORTED_PLATFORM'):
                self.c.credentialed_pair()

    def test_send_requires_a_canonical_request_id(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            for bad in ('nope', self.id.upper()):
                with self.subTest(bad=bad), self.assertRaisesRegex(self.c.HandoffError, 'BAD_ARGUMENT'):
                    self.c.send_readonly_request(self.a, fd, bad)
        finally:
            os.close(fd)
        self.b.settimeout(0.1)
        with self.assertRaises(TimeoutError):
            self.b.recv(1)

    def test_reply_requires_a_canonical_request_id(self):
        self.b.send(self.reply())
        with self.assertRaisesRegex(self.c.HandoffError, 'BAD_ARGUMENT'):
            self.c.read_verified_reply(self.a, expected_worker_uid=self.uid, request_id='nope')

    def test_reply_digest_syntax(self):
        self.b.send(self.reply())
        self.assertEqual(self.c.read_verified_reply(self.a, expected_worker_uid=self.uid,
                                                    request_id=self.id)['size'], 16)
        for bad in ('G' * 64, 'A' * 64, 'a' * 65, None):
            with self.subTest(bad=bad):
                self.b.send(self.reply(sha256=bad))
                with self.assertRaisesRegex(self.c.HandoffError, 'INVALID_REPLY_DIGEST'):
                    self.c.read_verified_reply(self.a, expected_worker_uid=self.uid, request_id=self.id)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX store checks required')
class DurableGrants(unittest.TestCase):
    def setUp(self):
        from udx_ref import durable_grants
        self.d = durable_grants
        self.root = tempfile.TemporaryDirectory(prefix='udx-w27-')
        self.location = str(pathlib.Path(self.root.name) / 'grants.db')
        self.file = pathlib.Path(self.root.name) / 'approved.bin'
        self.file.write_bytes(b'w27')
        self.fd = os.open(self.file, os.O_RDONLY)
        self.uid = os.getuid()
        self.now = [1234567890000000000]
        self.store = durable_grants.DurableGrantStore(self.location, clock_ns=lambda: self.now[0])

    def tearDown(self):
        self.store.close(); os.close(self.fd); self.root.cleanup()

    def claim(self, grant_id, **kwargs):
        args = dict(issuer_uid=self.uid, recipient_uid=self.uid + 1, request_id=str(uuid.uuid4()))
        args.update(kwargs)
        return self.store.claim(grant_id, self.fd, **args)

    def test_clock_must_be_a_positive_integer(self):
        for bad in (0, -1, 1.5, True, None):
            with self.subTest(bad=bad):
                self.now[0] = bad
                with self.assertRaisesRegex(self.d.GrantDenied, 'INVALID_CLOCK'):
                    self.store.issue(self.fd, issuer_uid=self.uid, recipient_uid=self.uid + 1)
        self.now[0] = 1234567890000000000
        self.assertEqual(len(self.store.issue(self.fd, issuer_uid=self.uid, recipient_uid=self.uid + 1)), 40)

    def test_claim_grant_id_syntax(self):
        for bad in ('zz', 'A' * 40, 'a' * 39, 7):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.d.GrantDenied, 'BAD_GRANT_ID'):
                self.claim(bad)

    def test_unknown_grant_cannot_be_claimed_or_revoked(self):
        with self.assertRaisesRegex(self.d.GrantDenied, 'UNKNOWN_GRANT'):
            self.claim('0' * 40)
        with self.assertRaisesRegex(self.d.GrantDenied, 'UNKNOWN_GRANT'):
            self.store.revoke('0' * 40)

    def test_claim_request_id_must_be_canonical(self):
        grant = self.store.issue(self.fd, issuer_uid=self.uid, recipient_uid=self.uid + 1)
        canonical = str(uuid.uuid4())
        for bad in (canonical.upper(), canonical.replace('-', ''), '{' + canonical + '}'):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.d.GrantDenied, 'BAD_REQUEST_ID'):
                self.claim(grant, request_id=bad)
        self.assertEqual(self.store.state(grant), 'ISSUED')
        self.claim(grant, request_id=canonical)
        self.assertEqual(self.store.state(grant), 'INFLIGHT')

    def test_claim_owner_type(self):
        grant = self.store.issue(self.fd, issuer_uid=self.uid, recipient_uid=self.uid + 1)
        for bad in (-1, True):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.d.GrantDenied, 'BAD_OWNER'):
                self.claim(grant, issuer_uid=bad)
        self.assertEqual(self.store.state(grant), 'ISSUED')

    def test_store_path_must_be_absolute(self):
        with self.assertRaisesRegex(self.d.GrantDenied, 'ABSOLUTE_STORE_PATH_REQUIRED'):
            self.d.DurableGrantStore('udx-w27-no-such-directory/grants.db')

    def test_store_refuses_a_database_that_does_not_reach_wal_or_full_sync(self):
        # Stand-in for a file system on which SQLite cannot switch to WAL (it then
        # answers with the old journal mode) or does not keep synchronous=FULL.
        real_connect = self.d.sqlite3.connect

        class Answers:
            def __init__(self, db, statement, value):
                self._db, self._statement, self._value = db, statement, value

            def execute(self, sql, *args):
                cursor = self._db.execute(sql, *args)
                if sql == self._statement:
                    cursor.fetchone()
                    return mock.Mock(fetchone=lambda: (self._value,))
                return cursor

            def close(self):
                self._db.close()

        for statement, value, code in (('PRAGMA journal_mode=WAL', 'delete', 'WAL_REQUIRED'),
                                       ('PRAGMA synchronous', 1, 'FULL_SYNC_REQUIRED')):
            opened = []

            def connect(*args, **kwargs):
                opened.append(Answers(real_connect(*args, **kwargs), statement, value))
                return opened[-1]

            location = str(pathlib.Path(self.root.name) / f'{code}.db')
            with self.subTest(code=code), mock.patch.object(self.d.sqlite3, 'connect', connect):
                try:
                    with self.assertRaisesRegex(self.d.GrantDenied, code):
                        self.d.DurableGrantStore(location)
                finally:
                    for db in opened:
                        db.close()

    def test_non_posix_platform_is_refused_with_a_typed_reason(self):
        with mock.patch.object(os, 'name', 'nt'):
            with self.assertRaisesRegex(self.d.GrantDenied, 'UNSUPPORTED_PLATFORM'):
                self.d._secure_store(self.location)


@unittest.skipUnless(fd_reader.fcntl is not None and os.name == 'posix', 'POSIX descriptor reads required')
class FdReaderAndSnapshot(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w27-')
        self.path = pathlib.Path(self.dir.name) / 'source'
        self.path.write_bytes(b'stable-source')
        self.fd = os.open(self.path, os.O_RDONLY)
        self.uid = os.getuid()

    def tearDown(self):
        os.close(self.fd); self.dir.cleanup()

    def test_closed_reader_cannot_be_entered(self):
        reader = fd_reader.ApprovedFdReader(self.fd)
        with reader:
            self.assertEqual(reader.read(), b'stable-source')
        with self.assertRaisesRegex(fd_reader.ReadGuardError, 'CLOSED'):
            with reader:
                self.fail('entered a closed reader')

    def test_limit_type_and_range(self):
        for bad in (0, fd_reader.MAX_READ + 1, True, 1.0):
            with self.subTest(bad=bad), self.assertRaisesRegex(fd_reader.ReadGuardError, 'INVALID_LIMIT'):
                fd_reader.ApprovedFdReader(self.fd, limit=bad)

    def test_platform_without_fcntl_is_refused(self):
        with mock.patch.object(fd_reader, 'fcntl', None):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'UNSUPPORTED_PLATFORM'):
                fd_reader.ApprovedFdReader(self.fd)

    def test_change_during_the_read_is_detected_even_at_constant_size(self):
        # The stat before the read is clean; the source changes while it is read
        # (same size, new mtime). Only the stat after the read can see that.
        real_pread = os.pread

        def pread_then_touch(fd, size, offset):
            data = real_pread(fd, size, offset)
            os.utime(self.path, ns=(1, 1))
            return data

        with fd_reader.ApprovedFdReader(self.fd) as reader:
            with mock.patch.object(os, 'pread', pread_then_touch):
                with self.assertRaisesRegex(fd_reader.ReadGuardError, 'RESOURCE_CHANGED'):
                    reader.read()

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_closed_snapshot_cannot_be_entered(self):
        snap = sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid)
        with snap:
            self.assertEqual(snap.read(), b'stable-source')
        with self.assertRaisesRegex(fd_reader.ReadGuardError, 'CLOSED'):
            with snap:
                self.fail('entered a closed snapshot')

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_snapshot_platform_without_fcntl_is_refused(self):
        with mock.patch.object(sealed_snapshot, 'fcntl', None):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'UNSUPPORTED_PLATFORM'):
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid)

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_copy_that_makes_no_progress_is_refused(self):
        real_write = os.write
        calls = []

        def write_nothing_once(fd, data):
            calls.append(len(data))
            return 0 if len(calls) == 1 else real_write(fd, data)

        with mock.patch.object(os, 'write', write_nothing_once):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SNAPSHOT_COPY_FAILED'):
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid)
        self.assertEqual(calls, [len(b'stable-source')])

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_copy_whose_seals_did_not_take_is_refused(self):
        real = sealed_snapshot.fcntl

        class SealsDoNotTake:
            def __getattr__(self, name):
                return getattr(real, name)

            def fcntl(self, fd, op, *args):
                result = real.fcntl(fd, op, *args)
                return 0 if op == real.F_GET_SEALS else result

        with mock.patch.object(sealed_snapshot, 'fcntl', SealsDoNotTake()):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SNAPSHOT_UNSEALED'):
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid)

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_two_differing_reads_are_an_unstable_source(self):
        # Stand-in for a source whose bytes differ between two reads although its
        # stat data did not change (the reader's own checks cannot see that).
        class TwoFaces:
            def __init__(self, *args, **kwargs):
                self._answers = [b'first', b'other']

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return self._answers.pop(0)

        with mock.patch.object(sealed_snapshot, 'ApprovedFdReader', TwoFaces):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SOURCE_UNSTABLE'):
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid)

    @unittest.skipUnless(LINUX, 'Linux memfd sealing required')
    def test_snapshot_read_checks_size_and_digest(self):
        with sealed_snapshot.SealedSnapshot(self.fd, expected_uid=self.uid) as snap:
            self.assertEqual(snap.read(), b'stable-source')
            good = snap._digest
            snap._digest = hashlib.sha256(b'other').digest()     # the sealed copy itself cannot be changed
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SNAPSHOT_INTEGRITY_FAILURE'):
                snap.read()
            snap._digest, snap._size = good, snap._size - 1
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SNAPSHOT_INTEGRITY_FAILURE'):
                snap.read()


class RecordingSocket:
    def __init__(self):
        self.sent = b''

    def sendall(self, data):
        self.sent += data


@unittest.skipUnless(linux_ipc.supported(), 'Linux SO_PEERCRED required')
class LinuxIpc(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w27-')
        self.base = pathlib.Path(self.dir.name).resolve()
        os.chmod(self.base, 0o700)

    def tearDown(self):
        self.dir.cleanup()

    def listener(self, reply=b''):
        """One-connection fake service; records what the client sent."""
        path = self.base / 's'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path)); server.listen(1); server.settimeout(5)
        got = {'bytes': None}

        def run():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(0.5)
                if reply:
                    conn.sendall(reply)
                data = b''
                try:
                    while True:
                        part = conn.recv(4096)
                        if not part:
                            break
                        data += part
                except OSError:
                    pass
                got['bytes'] = data

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(server.close)
        return path, got, thread

    def test_impossible_peer_credentials_are_unauthenticated(self):
        uid = os.getuid()
        self.assertEqual(linux_ipc.peer_identity(FakePeerSocket(4242, uid, 0)),
                         PeerIdentity(subject=f'uid:{uid}', authenticated=True))
        for pid, peer_uid, gid in ((0, uid, 0), (4242, -1, 0), (4242, uid, -1)):
            with self.subTest(pid=pid, uid=peer_uid, gid=gid), self.assertRaises(Refusal) as caught:
                linux_ipc.peer_identity(FakePeerSocket(pid, peer_uid, gid))
            self.assertEqual(caught.exception.code, 'UNAUTHENTICATED_PEER')

    def test_truncated_frame_is_a_connection_error_not_a_wait(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.sendall(b'\x00\x00'); left.close()
            started = time.monotonic()
            with self.assertRaisesRegex(ConnectionError, 'truncated frame'):
                linux_ipc.recv_exact(right, 4, deadline=time.monotonic() + 5)
            self.assertLess(time.monotonic() - started, 2.0)
        finally:
            right.close()

    def test_expired_deadline_is_typed_before_any_receive(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.sendall(b'\x00\x00\x00\x01')
            with self.assertRaisesRegex(TimeoutError, 'full-request deadline exceeded'):
                linux_ipc.recv_exact(right, 4, deadline=time.monotonic() - 1)
            self.assertEqual(linux_ipc.recv_exact(right, 4, deadline=time.monotonic() + 5), b'\x00\x00\x00\x01')
        finally:
            left.close(); right.close()

    def test_response_budget_is_checked_before_sending(self):
        conn = RecordingSocket()
        linux_ipc.send_frame(conn, {'x': 'a'})
        self.assertTrue(conn.sent)
        conn = RecordingSocket()
        with self.assertRaisesRegex(ValueError, 'response exceeds budget'):
            linux_ipc.send_frame(conn, {'x': 'a' * linux_ipc.MAX_RESPONSE_BYTES})
        self.assertEqual(conn.sent, b'')

    def test_client_refuses_a_service_of_another_uid_before_sending(self):
        path, got, thread = self.listener()
        other = PeerIdentity(subject=f'uid:{os.geteuid() + 1}', authenticated=True)
        with mock.patch.object(linux_ipc, 'peer_identity', return_value=other):
            with self.assertRaisesRegex(PermissionError, 'not the expected local UID'):
                linux_ipc.request_on_socket(path, b'{}', timeout=0.5)
        thread.join(5)
        self.assertEqual(got['bytes'], b'')

    def test_client_refuses_an_oversized_response_header(self):
        path, _, thread = self.listener(reply=linux_ipc.HEADER.pack(linux_ipc.MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'oversized response'):
            linux_ipc.request_on_socket(path, b'{}', timeout=0.5)
        thread.join(5)

    def test_client_request_type_and_size(self):
        for bad in ('{}', bytearray(b'{}'), b'x' * (MAX_MESSAGE_BYTES + 1)):
            with self.subTest(kind=type(bad).__name__, size=len(bad)):
                with self.assertRaisesRegex(ValueError, 'request too large or wrong type'):
                    linux_ipc.request_on_socket(self.base / 'absent', bad, timeout=0.2)

    def test_server_refuses_to_run_as_root(self):
        with mock.patch.object(os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'unprivileged execution required'):
                linux_ipc.serve_forever(self.base, max_connections=1)
        self.assertEqual(os.listdir(self.base), [])

    def test_runtime_directory_must_not_be_a_symlink(self):
        self.assertEqual(linux_ipc.verify_directory(self.base), self.base)       # positive control
        link = self.base / 'link'
        real = self.base / 'real'
        real.mkdir(mode=0o700)
        link.symlink_to(real)
        for bad in (link, pathlib.Path('relative-udx-w27')):
            with self.subTest(bad=bad.name), self.assertRaisesRegex(PermissionError, 'absolute, canonical'):
                linux_ipc.verify_directory(bad)

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0, 'needs a directory owned by another UID')
    def test_runtime_directory_of_another_owner_is_refused(self):
        with self.assertRaisesRegex(PermissionError, 'not owned by server UID'):
            linux_ipc.verify_directory('/')

    def test_runtime_directory_path_length(self):
        deep = self.base / ('d' * 100)
        deep.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'pathname too long'):
            linux_ipc.verify_directory(deep)


class PortableValidation(unittest.TestCase):
    def test_tile_tracker_parameters(self):
        from udx_ref.perception import TileChangeTracker
        TileChangeTracker(tile_edge=8, quiet_observations=1, change_threshold=0)   # positive control
        for kwargs, message in ((dict(tile_edge=7), 'bad tile_edge'), (dict(tile_edge=True), 'bad tile_edge'),
                                (dict(quiet_observations=0), 'bad quiet_observations'),
                                (dict(quiet_observations=121), 'bad quiet_observations'),
                                (dict(change_threshold=1.5), 'bad change_threshold'),
                                (dict(change_threshold='0'), 'bad change_threshold')):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, message):
                TileChangeTracker(**kwargs)

    def test_tile_tracker_dimension_types_and_tile_budget(self):
        from udx_ref.perception import TileChangeTracker
        tracker = TileChangeTracker(tile_edge=8)
        for kwargs in (dict(width=True, height=1, channels=1), dict(width=1, height=1.0, channels=1),
                       dict(width=1, height=1, channels=True)):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, 'dimensions must be integers'):
                tracker.inspect(b'\x00', **kwargs)
        tracker.inspect(bytes(8192 * 32), width=8192, height=32, channels=1)       # 4096 tiles: allowed
        with self.assertRaisesRegex(ValueError, 'too many tiles'):
            tracker.inspect(bytes(8192 * 40), width=8192, height=40, channels=1)   # 5120 tiles

    def test_chooser_uri_with_backslash_or_nul(self):
        from udx_ref.portal_boundary import PortalRejected, validate_chooser_result
        self.assertEqual(validate_chooser_result(0, {'uris': ['file:///tmp/a']}), 'file:///tmp/a')
        for bad in ('file:///tmp/a\\b', 'file:///tmp/a\x00b'):
            with self.subTest(bad=bad), self.assertRaisesRegex(PortalRejected, r'^INVALID_URI$'):
                validate_chooser_result(0, {'uris': [bad]})

    def test_portal_request_construction_and_state(self):
        from udx_ref.portal_request import PortalFlowError, PortalRequest
        good = dict(caller_unique=':1.42', portal_owner_unique=':1.7', clock=lambda: 10.0)
        for kwargs, code in ((dict(good, caller_unique='org.example'), 'BAD_CALLER_NAME'),
                             (dict(good, caller_unique=None), 'BAD_CALLER_NAME'),
                             (dict(good, ttl_seconds=0), 'BAD_DEADLINE'),
                             (dict(good, ttl_seconds=301), 'BAD_DEADLINE'),
                             (dict(good, ttl_seconds='5'), 'BAD_DEADLINE')):
            with self.subTest(code=code, kwargs=sorted(kwargs)), self.assertRaisesRegex(PortalFlowError, code):
                PortalRequest(**kwargs)
        request = PortalRequest(**good)
        request.bind_handle(request.handle)
        with self.assertRaisesRegex(PortalFlowError, 'NOT_AWAITING'):
            request.bind_handle(request.handle)
        request.cancel()
        self.assertEqual(request.state, 'CANCELLED')
        with self.assertRaisesRegex(PortalFlowError, 'TOO_LATE'):
            request.cancel()

    def test_preview_gate_scope_epoch_and_dimensions(self):
        from udx_ref.preview_gate import GateError, PreviewGate
        gate = PreviewGate(clock=lambda: 1.0)
        good = dict(human_approved=True, principal='test-app', session_id='s1', resource_id='display-1',
                    frame_epoch=7, width=100, height=80)
        for change, code in ((dict(principal='bad scope!'), 'INVALID_SCOPE'), (dict(resource_id=7), 'INVALID_SCOPE'),
                             (dict(frame_epoch=-1), 'INVALID_EPOCH'), (dict(frame_epoch=True), 'INVALID_EPOCH'),
                             (dict(width=0), 'INVALID_DIMENSIONS'), (dict(height=16385), 'INVALID_DIMENSIONS'),
                             (dict(width=1.0), 'INVALID_DIMENSIONS')):
            with self.subTest(change=change), self.assertRaisesRegex(GateError, code):
                gate.issue(**dict(good, **change))
        self.assertEqual(gate.grant_count, 0)
        gate.issue(**good)
        self.assertEqual(gate.grant_count, 1)


if __name__ == '__main__':
    unittest.main()
