"""W28: negative controls for the nine refusals the v2 sweep found untested.

The W27 sweep only saw ``if ...: raise``. Sweep v2 (W28) also inventories
``if ...: return <refusal>`` and ``except`` handlers that convert an exception
into a typed refusal. On the W27 tests nine of these survived:

* four ``return`` refusals of ``PreviewGate`` whose removal no test noticed.
  Two of them were security-relevant gaps in the *tests* (the code was right):
  without INVALID_REQUEST a proposal with a non-UUID request id consumed a
  valid grant and was accepted; without REPLAY_REJECTED a replayed request id
  was accepted with a fresh grant. The other two fell through to a later check
  with a different code.
* five handlers whose typed conversion was never asserted: with the handler
  gone, the raw OSError / ReadGuardError / ValueError escaped and every test
  still passed.

Each test below asserts the exact refusal code and has a positive control.
"""
from __future__ import annotations

import os
import pathlib
import socket
import sys
import tempfile
import unittest
import uuid

from udx_ref import fd_handoff, fd_reader, linux_ipc
from udx_ref.core import Refusal
from udx_ref.portal_boundary import PortalRejected, validate_chooser_result
from udx_ref.preview_gate import PreviewGate, PreviewProposal

LINUX = sys.platform.startswith('linux')


def _closed_fd() -> int:
    """A non-negative descriptor number that is not open."""
    fd = os.open(os.devnull, os.O_RDONLY)
    os.close(fd)
    return fd


class Clock:
    now = 100.0

    def __call__(self):
        return self.now


class PreviewGateReturnRefusals(unittest.TestCase):
    def setUp(self):
        self.gate = PreviewGate(clock=Clock())

    def grant(self):
        return self.gate.issue(human_approved=True, principal='p', session_id='s', resource_id='r',
                               frame_epoch=1, width=32, height=32)

    def proposal(self, **kw):
        args = dict(request_id=str(uuid.uuid4()), principal='p', session_id='s', resource_id='r',
                    frame_epoch=1, width=32, height=32, x=1, y=2)
        args.update(kw)
        return PreviewProposal(**args)

    def assertRefused(self, result, code):
        self.assertEqual((result.code, result.accepted), (code, False))

    def test_non_uuid_request_id_is_refused_and_does_not_consume_the_grant(self):
        grant = self.grant()
        for bad in ('not-a-uuid', '', str(uuid.uuid4()).upper(), 1):
            with self.subTest(bad=bad):
                self.assertRefused(self.gate.check_and_consume(grant, self.proposal(request_id=bad)),
                                   'INVALID_REQUEST')
        self.assertTrue(self.gate.check_and_consume(grant, self.proposal()).accepted)   # positive control

    def test_invalid_scope_is_reported_as_such_not_as_a_mismatch(self):
        grant = self.grant()
        for field, bad in (('principal', ''), ('session_id', 's s'), ('resource_id', None),
                           ('capability', 'input.pointer.real')):
            with self.subTest(field=field):
                self.assertRefused(self.gate.check_and_consume(grant, self.proposal(**{field: bad})),
                                   'INVALID_SCOPE')
        self.assertTrue(self.gate.check_and_consume(grant, self.proposal()).accepted)

    def test_replayed_request_id_is_refused_even_with_a_fresh_grant(self):
        first = self.proposal()
        self.assertTrue(self.gate.check_and_consume(self.grant(), first).accepted)
        fresh = self.grant()
        self.assertRefused(self.gate.check_and_consume(fresh, first), 'REPLAY_REJECTED')
        self.assertTrue(self.gate.check_and_consume(fresh, self.proposal()).accepted)    # grant still usable

    def test_malformed_grant_id_is_invalid_not_merely_absent(self):
        self.grant()
        for bad in ('nope', None, str(uuid.uuid4()).upper()):
            with self.subTest(bad=bad):
                self.assertRefused(self.gate.check_and_consume(bad, self.proposal()), 'INVALID_GRANT')
        self.assertRefused(self.gate.check_and_consume(str(uuid.uuid4()), self.proposal()), 'NO_ACTIVE_GRANT')


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX descriptors required')
class TypedHandlerConversions(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w28-')
        self.path = pathlib.Path(self.dir.name) / 'approved.bin'
        self.path.write_bytes(b'w28')

    def tearDown(self):
        self.dir.cleanup()

    def test_reader_on_a_closed_descriptor_is_invalid_fd_with_the_os_error_as_cause(self):
        with self.assertRaisesRegex(fd_reader.ReadGuardError, '^INVALID_FD$') as ctx:
            fd_reader.ApprovedFdReader(_closed_fd())
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        fd = os.open(self.path, os.O_RDONLY)
        try:
            with fd_reader.ApprovedFdReader(fd) as reader:
                self.assertEqual(reader.read(), b'w28')
        finally:
            os.close(fd)

    def test_grant_for_an_unreadable_handle_is_invalid_source_handle(self):
        from udx_ref.durable_grants import DurableGrantStore, GrantDenied
        store = DurableGrantStore(str(pathlib.Path(self.dir.name) / 'grants.db'))
        try:
            with self.assertRaisesRegex(GrantDenied, '^INVALID_SOURCE_HANDLE$'):
                store.issue(_closed_fd(), issuer_uid=os.getuid(), recipient_uid=os.getuid() + 1)
            fd = os.open(self.path, os.O_RDONLY)
            try:
                self.assertTrue(store.issue(fd, issuer_uid=os.getuid(), recipient_uid=os.getuid() + 1))
            finally:
                os.close(fd)
        finally:
            store.close()

    @unittest.skipUnless(LINUX and fd_handoff.supported(), 'Linux SO_PEERCRED / seqpacket required')
    def test_handoff_peer_query_failure_is_no_os_peer(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        b.close()
        self.assertGreater(fd_handoff._peer_uid(a), -1)                 # positive control: live peer
        a.close()                                                       # getsockopt -> EBADF
        with self.assertRaisesRegex(fd_handoff.HandoffError, '^NO_OS_PEER$') as ctx:
            fd_handoff._peer_uid(a)
        self.assertIsInstance(ctx.exception.__cause__, OSError)

    @unittest.skipUnless(LINUX and linux_ipc.supported(), 'Linux SO_PEERCRED required')
    def test_ipc_peer_query_failure_is_unauthenticated_peer(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertEqual(linux_ipc.peer_identity(a).subject, f'uid:{os.getuid()}')
        finally:
            b.close()
            a.close()
        with self.assertRaisesRegex(Refusal, 'UNAUTHENTICATED_PEER') as ctx:
            linux_ipc.peer_identity(a)
        self.assertIsInstance(ctx.exception.__cause__, OSError)


class PortalUriParseFailure(unittest.TestCase):
    def test_uri_that_urlsplit_cannot_parse_is_invalid_uri(self):
        ok = validate_chooser_result(0, {'uris': ['file:///home/u/doc.txt']})
        self.assertEqual(ok, 'file:///home/u/doc.txt')                  # positive control
        for bad in ('file://[::1/doc.txt', 'file://[zz]/doc.txt'):
            with self.subTest(bad=bad), self.assertRaisesRegex(PortalRejected, '^INVALID_URI$'):
                validate_chooser_result(0, {'uris': [bad]})


if __name__ == '__main__':
    unittest.main()
