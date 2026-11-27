"""R13 delta reaudit of PR #13 at d5049ce (007acc2, 2026-11-26), native repository tests.

The reaudit tested a stand-in copy of the journal and a transport function
extracted from the diff. These tests run the same findings against the real
``udx_ref.delivery_receipts.ReceiptJournal`` and the real
``udx_ref.linux_ipc.serve_connection_acked``, with real SQLite.

Invariant: an ACK is booked as DELIVERED only against a valid canonical
digest, and every uncertain transaction (failed ROLLBACK, COMMIT that ended
the transaction with an error) latches the instance fail-stop without hiding
the primary cause.

- R13-NR03: decoded-object API (``acknowledge``) accepted an unknown version, an
  invalid verdict, an invalid request id (as a mismatch, i.e. a different
  terminal mutation) and a NULL ACK digest against a NULL stored digest. This
  is the direct API, not a wire bypass: ``decode_ack`` already validates.
  Corrupt stored digests (NULL, upper-case) latch the journal instead of being
  compared (also GPT-6.2 R12-NR01: NULL/noncanonical identical strings).
- R13-NR04: an unconditional ROLLBACK masked the primary RAISE(ROLLBACK)
  IntegrityError. A rollback SQLite already completed is a known state: the
  journal stays usable (negative control).
- R13-NR05: a failed ROLLBACK, or a COMMIT that raised after the transaction
  had ended, did not latch the instance.
- R13-NR06: after a storage failure at the ACK the acked lane reported UNACKED
  while the row stayed RESPONDING.

Journal tests run on every platform (POSIX: the real private store; elsewhere
the POSIX-only ``_secure_store`` is replaced by the identity). The transport
tests replace only the socket-facing helpers (peer credentials, framing); the
journal, digest, ACK and receipt codecs are the real ones. Every refusal
expected here is checked by assertion; an unexpected exception is turned into
an assertion failure, so a mutant is never "killed" by a crash.
"""
import os
import sqlite3
import struct
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from udx_ref import delivery_receipts as dr
from udx_ref import linux_ipc
from udx_ref.delivery_receipts import ACK_VERSION, ReceiptError, ReceiptJournal

POSIX = os.name == 'posix' and hasattr(os, 'getuid')
SUBJECT = 'uid:1000'
OTHER_SUBJECT = 'uid:1001'
DIGEST = 'a' * 64


def rid():
    return str(uuid.uuid4())


def open_journal(test):
    tmp = tempfile.TemporaryDirectory(prefix='udx-r13-')
    test.addCleanup(tmp.cleanup)
    if POSIX:
        os.chmod(tmp.name, 0o700)
    path = str(Path(tmp.name) / 'receipts.db')
    if POSIX:
        journal = ReceiptJournal(path)
    else:
        with mock.patch.object(dr, '_secure_store', lambda p: p):
            journal = ReceiptJournal(path)
    test.addCleanup(_close_quietly, journal)
    return journal, path


def _close_quietly(journal):
    try:
        journal.close()
    except Exception:
        pass


def stored(path, subject, request_id):
    """Row as committed on disk, read through a fresh connection."""
    fresh = sqlite3.connect(path)
    try:
        row = fresh.execute('SELECT state, response_sha256, reason FROM receipts '
                            'WHERE subject=? AND request_id=?', (subject, request_id)).fetchone()
        return tuple(row) if row else None
    finally:
        fresh.close()


def responding(journal, request_id, subject=SUBJECT, digest=DIGEST):
    journal.reserve(subject, request_id)
    journal.respond(subject, request_id, digest)


def ack(request_id, digest=DIGEST, verdict='ACCEPTED', version=ACK_VERSION):
    return {'version': version, 'request_id': request_id, 'response_sha256': digest, 'verdict': verdict}


def primary_of(exc):
    """The primary error: the exception itself, or the cause a typed wrapper names."""
    if isinstance(exc, sqlite3.Error):
        return exc
    return exc.__cause__


class Recorder:
    """Connection proxy: records statements; can fail ROLLBACK or report a COMMIT
    that SQLite applied as failed (the uncertain-commit case)."""

    def __init__(self, real, *, commit_reports_failure=False):
        self.real = real
        self.commit_reports_failure = commit_reports_failure
        self.statements = []

    def execute(self, sql, *args):
        self.statements.append(sql.strip().upper())
        result = self.real.execute(sql, *args)
        if self.commit_reports_failure and sql.strip().upper() == 'COMMIT':
            raise sqlite3.OperationalError('R13_INJECTED_COMMIT_ERROR_AFTER_APPLY')
        return result

    @property
    def in_transaction(self):
        return self.real.in_transaction

    def close(self):
        self.real.close()


class R13Case(unittest.TestCase):

    def refusal(self, fn, code):
        """Assert a typed ReceiptError with ``code``; anything else is an assertion failure."""
        try:
            fn()
        except ReceiptError as exc:
            self.assertEqual(exc.code, code)
            return exc
        except Exception as exc:  # noqa: BLE001 -- turned into an assertion
            self.fail(f'expected ReceiptError({code}), got {type(exc).__name__}: {exc}')
        self.fail(f'expected ReceiptError({code}), call succeeded')

    def raises(self, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            return exc
        self.fail('expected an exception, call succeeded')

    def returns(self, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            self.fail(f'expected a return value, got {type(exc).__name__}: {exc}')


class AckPositiveControls(R13Case):
    """Must hold on the original and on the fix."""

    def test_valid_ack_is_delivered(self):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r))), 'DELIVERED')
        self.assertEqual(stored(path, SUBJECT, r)[0], 'DELIVERED')

    def test_rejected_verdict_is_client_rejected(self):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r, verdict='REJECTED'))),
                         'CLIENT_REJECTED')

    def test_valid_mismatching_acks_are_recorded_unacked(self):
        journal, path = open_journal(self)
        r1, r2 = rid(), rid()
        responding(journal, r1)
        responding(journal, r2)
        self.refusal(lambda: journal.acknowledge(SUBJECT, r1, ack(r1, digest='b' * 64)), 'ACK_DIGEST_MISMATCH')
        self.refusal(lambda: journal.acknowledge(SUBJECT, r2, ack(rid())), 'ACK_REQUEST_MISMATCH')
        self.assertEqual(stored(path, SUBJECT, r1)[0], 'UNACKED')
        self.assertEqual(stored(path, SUBJECT, r2)[0], 'UNACKED')

    def test_ack_is_bound_to_its_subject(self):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        responding(journal, r, subject=OTHER_SUBJECT)
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r))), 'DELIVERED')
        self.assertEqual(stored(path, OTHER_SUBJECT, r)[0], 'RESPONDING')


class R13NR03InvalidAckChangesNothing(R13Case):

    def _refused_unchanged(self, bad, code):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        self.refusal(lambda: journal.acknowledge(SUBJECT, r, bad(r)), code)
        self.assertEqual(stored(path, SUBJECT, r), ('RESPONDING', DIGEST, None))
        # Positive control on the same row: the journal is still usable.
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r))), 'DELIVERED')

    def test_unknown_version(self):
        self._refused_unchanged(lambda r: ack(r, version='udx-ack/2'), 'UNSUPPORTED_ACK_VERSION')

    def test_invalid_verdict(self):
        self._refused_unchanged(lambda r: ack(r, verdict='BOGUS'), 'INVALID_ACK_VERDICT')

    def test_non_string_request_id_is_not_a_mismatch(self):
        self._refused_unchanged(lambda r: ack(42), 'INVALID_ACK_REQUEST_ID')

    def test_non_canonical_request_id_is_not_a_mismatch(self):
        self._refused_unchanged(lambda r: ack(r.upper()), 'INVALID_ACK_REQUEST_ID')

    def test_null_ack_digest(self):
        self._refused_unchanged(lambda r: ack(r, digest=None), 'INVALID_ACK_DIGEST')


class R13NR03CorruptStoredDigest(R13Case):
    """A stored digest that is not canonical lower-case hex is journal corruption:
    nothing is compared against it, the row stays, the instance latches."""

    def _corrupt(self, stored_value, ack_digest, code):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        journal.db.execute('UPDATE receipts SET response_sha256=? WHERE request_id=?', (stored_value, r))
        self.refusal(lambda: journal.acknowledge(SUBJECT, r, ack(r, digest=ack_digest)), code)
        self.assertEqual(stored(path, SUBJECT, r), ('RESPONDING', stored_value, None))
        return journal, r

    def test_null_ack_never_matches_null_stored_digest(self):
        self._corrupt(None, None, 'INVALID_ACK_DIGEST')

    def test_identical_noncanonical_strings_never_match(self):
        self._corrupt('A' * 64, 'A' * 64, 'INVALID_ACK_DIGEST')

    def test_null_stored_digest_latches_the_journal(self):
        journal, r = self._corrupt(None, DIGEST, 'JOURNAL_INVALID_STORED_DIGEST')
        self.refusal(lambda: journal.reserve(SUBJECT, rid()), 'JOURNAL_POISONED')

    def test_uppercase_stored_digest_latches_the_journal(self):
        journal, r = self._corrupt('A' * 64, DIGEST, 'JOURNAL_INVALID_STORED_DIGEST')
        self.refusal(lambda: journal.acknowledge(SUBJECT, r, ack(r)), 'JOURNAL_POISONED')


class R13NR04PrimaryErrorKept(R13Case):

    def test_trigger_rollback_keeps_the_integrity_error_and_does_not_latch(self):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        journal.db.execute("CREATE TRIGGER r13_fault BEFORE UPDATE ON receipts WHEN NEW.state='DELIVERED' "
                           "BEGIN SELECT RAISE(ROLLBACK, 'R13_PRIMARY'); END")
        exc = self.raises(lambda: journal.acknowledge(SUBJECT, r, ack(r)))
        self.assertIsInstance(primary_of(exc), sqlite3.IntegrityError)
        self.assertIn('R13_PRIMARY', str(primary_of(exc)))
        self.assertEqual(stored(path, SUBJECT, r), ('RESPONDING', DIGEST, None))
        # A rollback SQLite completed itself is a known state: no latch.
        journal.db.execute('DROP TRIGGER r13_fault')
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r))), 'DELIVERED')


class R13NR05UncertainTransactionLatches(R13Case):

    def test_failed_rollback_keeps_primary_and_latches(self):
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        journal.db.execute("CREATE TRIGGER r13_fault BEFORE UPDATE ON receipts "
                           "BEGIN SELECT RAISE(ABORT, 'R13_PRIMARY'); END")
        journal.db.set_authorizer(
            lambda action, arg1, *rest: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_TRANSACTION and arg1 == 'ROLLBACK' else sqlite3.SQLITE_OK)
        rec = journal.db = Recorder(journal.db)
        exc = self.raises(lambda: journal.acknowledge(SUBJECT, r, ack(r)))
        primary = primary_of(exc)
        self.assertIsInstance(primary, sqlite3.IntegrityError)
        self.assertIn('R13_PRIMARY', str(primary))
        notes = getattr(primary, '__notes__', None) or getattr(exc, '__notes__', None) or ()
        self.assertTrue(any('ROLLBACK_FAILED' in n for n in notes), notes)
        before = len(rec.statements)
        self.refusal(lambda: journal.acknowledge(SUBJECT, r, ack(r)), 'JOURNAL_POISONED')
        self.assertFalse([s for s in rec.statements[before:] if s.startswith('BEGIN')])
        self.assertEqual(stored(path, SUBJECT, r)[0], 'RESPONDING')

    def test_commit_error_after_the_transaction_ended_latches(self):
        journal, path = open_journal(self)
        r = rid()
        rec = journal.db = Recorder(journal.db, commit_reports_failure=True)
        exc = self.raises(lambda: journal.reserve(SUBJECT, r))
        self.assertIsInstance(primary_of(exc), sqlite3.OperationalError)
        self.assertIn('R13_INJECTED_COMMIT_ERROR_AFTER_APPLY', str(primary_of(exc)))
        rec.commit_reports_failure = False
        before = len(rec.statements)
        self.refusal(lambda: journal.reserve(SUBJECT, rid()), 'JOURNAL_POISONED')
        self.assertFalse([s for s in rec.statements[before:] if s.startswith('BEGIN')])

    def test_commit_refused_with_the_transaction_open_does_not_latch(self):
        """Negative control (deliberately narrower than the R13 stand-in, which
        latched here): COMMIT refused before it ran leaves the transaction open,
        the ROLLBACK succeeds, the state is known."""
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        journal.db.set_authorizer(
            lambda action, arg1, *rest: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_TRANSACTION and arg1 == 'COMMIT' else sqlite3.SQLITE_OK)
        self.raises(lambda: journal.acknowledge(SUBJECT, r, ack(r)))
        journal.db.set_authorizer(None)
        self.assertEqual(stored(path, SUBJECT, r)[0], 'RESPONDING')
        self.assertEqual(self.returns(lambda: journal.acknowledge(SUBJECT, r, ack(r))), 'DELIVERED')


class R13VariantGrantStoreCommit(R13Case):
    """Variant search (R13: "inspect shared durable_grants._tx, same rollback
    pattern"): the grant store shares the cleanup helper, so the same
    uncertain-COMMIT case must latch it too."""

    def test_grant_store_commit_error_after_the_transaction_ended_latches(self):
        from udx_ref import durable_grants
        from udx_ref.durable_grants import DurableGrantStore, GrantDenied
        tmp = tempfile.TemporaryDirectory(prefix='udx-r13g-')
        self.addCleanup(tmp.cleanup)
        if POSIX:
            os.chmod(tmp.name, 0o700)
        path = str(Path(tmp.name) / 'grants.db')
        if POSIX:
            store = DurableGrantStore(path)
        else:
            with mock.patch.object(durable_grants, '_secure_store', lambda p: p):
                store = DurableGrantStore(path)
        self.addCleanup(_close_quietly, store)
        gid = 'cd' * 20
        store.db.execute("INSERT INTO grants VALUES(?,1000,1000,1,2,3,4,5,?,'ISSUED',NULL)", (gid, 2**62))
        rec = store.db = Recorder(store.db, commit_reports_failure=True)
        exc = self.raises(lambda: store.revoke(gid))
        self.assertIsInstance(exc, sqlite3.OperationalError)
        rec.commit_reports_failure = False
        before = len(rec.statements)
        try:
            store.revoke(gid)
        except GrantDenied as again:
            self.assertEqual(str(again), 'JOURNAL_POISONED')
        except Exception as again:  # noqa: BLE001
            self.fail(f'expected GrantDenied(JOURNAL_POISONED), got {type(again).__name__}: {again}')
        else:
            self.fail('expected GrantDenied(JOURNAL_POISONED), call succeeded')
        self.assertFalse([s for s in rec.statements[before:] if s.startswith('BEGIN')])


class _Socket:
    def __init__(self):
        self.sent = []

    def settimeout(self, value):
        pass

    def sendall(self, data):
        self.sent.append(bytes(data))


class R13NR06AckedLaneReportsOnlyJournaledState(R13Case):
    """Real serve_connection_acked + real journal; socket-facing helpers replaced."""

    def run_lane(self, journal, r, ack_obj):
        response = b'{"r13":"response"}'
        ack_bytes = dr.encode_ack(ack_obj['request_id'], ack_obj['response_sha256'], ack_obj['verdict'])
        frames = [linux_ipc.HEADER.pack(len(ack_bytes)), ack_bytes]
        sock = _Socket()
        with mock.patch.object(linux_ipc, 'peer_identity', lambda conn: SimpleNamespace(subject=SUBJECT)), \
                mock.patch.object(linux_ipc, '_read_request', lambda conn, deadline: b'request'), \
                mock.patch.object(linux_ipc, 'decode_request', lambda raw: {'request_id': r}), \
                mock.patch.object(linux_ipc, '_encode_response', lambda obj: response), \
                mock.patch.object(linux_ipc, 'recv_exact', lambda conn, n, **kw: frames.pop(0)):
            result = self.returns(lambda: linux_ipc.serve_connection_acked(
                sock, SimpleNamespace(handle=lambda raw, peer: {}), journal))
        return result, sock.sent, dr.response_digest(response)

    def test_positive_control_delivered_and_receipt_sent(self):
        journal, path = open_journal(self)
        r = rid()
        digest = dr.response_digest(b'{"r13":"response"}')
        result, sent, _ = self.run_lane(journal, r, ack(r, digest=digest))
        self.assertEqual(result, 'DELIVERED')
        self.assertEqual(len(sent), 2)
        self.assertEqual(stored(path, SUBJECT, r)[0], 'DELIVERED')

    def test_mismatch_still_reports_unacked(self):
        journal, path = open_journal(self)
        r = rid()
        result, sent, _ = self.run_lane(journal, r, ack(r, digest='b' * 64))
        self.assertEqual(result, 'UNACKED')
        self.assertEqual(stored(path, SUBJECT, r)[0], 'UNACKED')

    def test_storage_failure_at_ack_is_not_reported_unacked(self):
        journal, path = open_journal(self)
        r = rid()
        journal.db.execute("CREATE TRIGGER r13_fault BEFORE UPDATE ON receipts WHEN NEW.state='DELIVERED' "
                           "BEGIN SELECT RAISE(ROLLBACK, 'R13_PRIMARY'); END")
        digest = dr.response_digest(b'{"r13":"response"}')
        result, sent, _ = self.run_lane(journal, r, ack(r, digest=digest))
        self.assertIsNone(result)
        self.assertEqual(len(sent), 1)          # response only, no receipt
        self.assertEqual(stored(path, SUBJECT, r)[0], 'RESPONDING')


if __name__ == '__main__':
    unittest.main(verbosity=2)
