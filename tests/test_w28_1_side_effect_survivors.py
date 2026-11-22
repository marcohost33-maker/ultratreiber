"""W28.1: the three refusals that only side-effect preserving mutants expose.

With the W27/W28 mutants ('if False:' / 'if True:') the condition itself
disappeared, and with it a send or a parse that the positive tests need. Those
tests failed and the sweep counted a kill. With '((cond) and False)' the
condition still runs, and three refusals turned out to have no negative test:

* fd_handoff.handle_once and credentialed_handoff.process_one: REPLY_FAILED on a
  short send (the Codex example on PR #8);
* core.decode_response: a request id that uuid.UUID parses but that is not the
  canonical lower-case 36-character form (upper case, braces, urn:uuid:, no
  hyphens). Before: removing the check accepted such an id in a response.
"""
import json
import os
import pathlib
import tempfile
import unittest
import uuid

from udx_ref import credentialed_handoff, fd_handoff
from udx_ref.core import VERSION, Refusal, decode_response
from udx_ref.sealed_snapshot import sealing_available

RID = '00000000-0000-4000-8000-00000000000a'


def _response(rid):
    return json.dumps({'version': VERSION, 'request_id': rid, 'status': 'OK', 'code': 'OK',
                       'data': {'object_id': 'sample-1', 'kind': 'fixture', 'size_bytes': 42}},
                      separators=(',', ':')).encode()


class ResponseRequestIdIsCanonical(unittest.TestCase):
    def test_parseable_but_noncanonical_ids_are_invalid_response(self):
        self.assertEqual(decode_response(_response(RID))['request_id'], RID)     # positive control
        for bad in (RID.upper(), '{' + RID + '}', 'urn:uuid:' + RID, RID.replace('-', '')):
            with self.subTest(bad=bad):
                self.assertNotEqual(str(uuid.UUID(bad)), bad)                   # parseable, not canonical
                with self.assertRaisesRegex(Refusal, '^INVALID_RESPONSE$'):
                    decode_response(_response(bad))


class ShortSend:
    """A real socket whose send() delivers one byte less than asked."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def send(self, data):
        return self._inner.send(data[:-1])


@unittest.skipUnless(fd_handoff.supported() and sealing_available(),
                     'Linux seqpacket and a sealed snapshot required')
class ShortReplyIsReplyFailed(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w281-')
        self.path = pathlib.Path(self.dir.name) / 'src'
        self.path.write_bytes(b'w28.1 reply')

    def tearDown(self):
        self.dir.cleanup()

    def _send(self, sender, client):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            sender(client, fd, str(uuid.uuid4()))
        finally:
            os.close(fd)

    def test_fd_handoff_short_reply(self):
        for wrap, expect_ok in ((lambda s: s, True), (ShortSend, False)):
            a, b = fd_handoff.private_pair()
            try:
                self._send(fd_handoff.send_approved_fd, a)
                server = wrap(b)
                if expect_ok:
                    self.assertEqual(fd_handoff.handle_once(server, expected_uid=os.getuid(),
                                                            owner_uid=os.getuid())['size'], 11)
                else:
                    with self.assertRaisesRegex(fd_handoff.HandoffError, '^REPLY_FAILED$'):
                        fd_handoff.handle_once(server, expected_uid=os.getuid(), owner_uid=os.getuid())
            finally:
                a.close()
                b.close()

    @unittest.skipUnless(credentialed_handoff.available(), 'Linux SO_PASSCRED required')
    def test_credentialed_short_reply(self):
        for wrap, expect_ok in ((lambda s: s, True), (ShortSend, False)):
            a, b = credentialed_handoff.credentialed_pair()
            try:
                self._send(credentialed_handoff.send_readonly_request, a)
                server = wrap(b)
                if expect_ok:
                    result = credentialed_handoff.process_one(server, expected_sender_uid=os.getuid(),
                                                              source_owner_uid=os.getuid())
                    self.assertEqual(result['size'], 11)
                else:
                    with self.assertRaisesRegex(credentialed_handoff.HandoffError, '^REPLY_FAILED$'):
                        credentialed_handoff.process_one(server, expected_sender_uid=os.getuid(),
                                                         source_owner_uid=os.getuid())
            finally:
                a.close()
                b.close()


if __name__ == '__main__':
    unittest.main()
