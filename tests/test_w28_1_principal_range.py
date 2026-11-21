"""W28.1 / UDX28-03: principal uids of the grant journal are exact uid_t values.

Before: ``issue`` accepted any non-negative int, so ``recipient_uid = 2**63``
raised OverflowError from SQLite instead of BAD_PRINCIPAL; ``claim`` checked
neither type nor range and compared with ``==``, so a float or bool equal to the
stored uid (``1000.0``, ``True``) matched. Now both refuse with BAD_PRINCIPAL.
"""
import os
import pathlib
import tempfile
import unittest
import uuid


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX store checks required')
class PrincipalRange(unittest.TestCase):
    def setUp(self):
        from udx_ref import durable_grants
        self.d = durable_grants
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w281-')
        self.path = pathlib.Path(self.dir.name) / 'src'
        self.path.write_bytes(b'w28.1')
        self.fd = os.open(self.path, os.O_RDONLY)
        self.uid = os.getuid()
        self.store = durable_grants.DurableGrantStore(str(pathlib.Path(self.dir.name) / 'g.db'))

    def tearDown(self):
        self.store.close()
        os.close(self.fd)
        self.dir.cleanup()

    def issue(self, recipient):
        return self.store.issue(self.fd, issuer_uid=self.uid, recipient_uid=recipient)

    def claim(self, gid, issuer, recipient):
        return self.store.claim(gid, self.fd, issuer_uid=issuer, recipient_uid=recipient,
                                request_id=str(uuid.uuid4()))

    def test_out_of_range_or_wrongly_typed_recipient_is_bad_principal_at_issue(self):
        for bad in (2**63, 10**30, self.d.MAX_UID + 1, -1, True, 1000.0, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(self.d.GrantDenied, '^BAD_PRINCIPAL$'):
                self.issue(bad)
        self.assertTrue(self.issue(self.d.MAX_UID))                      # edge: largest real uid

    def test_claim_refuses_equal_but_wrongly_typed_principals(self):
        recipient = self.uid + 1
        gid = self.issue(recipient)
        for rec in (float(recipient), 2**64 + recipient, None):
            with self.subTest(recipient=rec), self.assertRaisesRegex(self.d.GrantDenied, '^BAD_PRINCIPAL$'):
                self.claim(gid, self.uid, rec)
        # The issuer keeps its W27 contract: bound to the descriptor owner, BAD_OWNER.
        for issuer in (float(self.uid), True, -1):
            with self.subTest(issuer=issuer), self.assertRaisesRegex(self.d.GrantDenied, '^BAD_OWNER$'):
                self.claim(gid, issuer, recipient)
        self.assertIsNone(self.claim(gid, self.uid, recipient))           # positive control
        self.assertEqual(self.store.state(gid), 'INFLIGHT')

    def test_bool_principal_equal_to_one_is_refused(self):
        gid = self.issue(1)                                                # recipient uid 1 (any uid works)
        with self.assertRaisesRegex(self.d.GrantDenied, '^BAD_PRINCIPAL$'):
            self.claim(gid, self.uid, True)


if __name__ == '__main__':
    unittest.main()
