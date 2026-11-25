"""R6 B2 (GPT-6 cross-family reaudit of PR #13 at d5049ce): receipt journal.

I1: the primary error of a ReceiptJournal transaction reaches the caller
unchanged (same _tx defect as B1).
I2: an ACK changes no row before it is completely validated, and the acked lane
never reports a state (UNACKED/DELIVERED/...) that the journal does not hold.

Journal tests run on every platform (POSIX: real private store; elsewhere the
POSIX-only ``_secure_store`` is replaced by the identity). Lane tests need the
Linux non-root SO_PEERCRED lane.
"""
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from udx_ref import delivery_receipts as dr
from udx_ref.delivery_receipts import ReceiptError, ReceiptJournal

POSIX = os.name == 'posix' and hasattr(os, 'getuid')
LINUX_IPC = sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED') and POSIX and os.geteuid() != 0
SUBJECT = 'uid:1000'
DIGEST = 'a' * 64


def rid():
    return str(uuid.uuid4())


class Clock:
    """Monotone fake clock; ``hooks`` maps a call number to a side effect / value."""

    def __init__(self, start=10**18, hooks=None):
        self.now = start
        self.calls = 0
        self.hooks = hooks or {}

    def __call__(self):
        self.calls += 1
        hook = self.hooks.get(self.calls)
        if hook is not None:
            value = hook()
            if value is not None:
                return value
        self.now += 1
        return self.now


class RollbackFails:
    def __init__(self, real):
        self.real = real

    def execute(self, sql, *args):
        if sql.strip().upper() == 'ROLLBACK':
            raise sqlite3.OperationalError('R6_INJECTED_ROLLBACK_FAILURE')
        return self.real.execute(sql, *args)

    @property
    def in_transaction(self):
        return self.real.in_transaction

    def close(self):
        self.real.close()


def open_journal(test, clock=None):
    tmp = tempfile.TemporaryDirectory(prefix='udx-r6b2-')
    test.addCleanup(tmp.cleanup)
    if POSIX:
        os.chmod(tmp.name, 0o700)
    path = str(Path(tmp.name) / 'receipts.db')
    clock = clock or Clock()
    if POSIX:
        journal = ReceiptJournal(path, clock_ns=clock)
    else:
        with mock.patch.object(dr, '_secure_store', lambda p: p):
            journal = ReceiptJournal(path, clock_ns=clock)
    test.addCleanup(journal.close)
    return journal, path


def stored(path, subject, request_id):
    fresh = sqlite3.connect(path)
    try:
        row = fresh.execute('SELECT state, reason FROM receipts WHERE subject=? AND request_id=?',
                            (subject, request_id)).fetchone()
        return tuple(row) if row else None
    finally:
        fresh.close()


def responding(journal, request_id):
    journal.reserve(SUBJECT, request_id)
    journal.respond(SUBJECT, request_id, DIGEST)


def ack(request_id, digest=DIGEST, verdict='ACCEPTED', version=dr.ACK_VERSION):
    return {'version': version, 'request_id': request_id, 'response_sha256': digest, 'verdict': verdict}


class LooksLikeStr(str):
    """A str subclass that compares equal to the wire value: not an exact JSON string."""


class ReceiptTxPrimaryError(unittest.TestCase):

    def test_trigger_rollback_surfaces_the_integrity_error(self):
        journal, path = open_journal(self)
        r = rid()
        journal.reserve(SUBJECT, r)
        journal.db.execute("CREATE TRIGGER r6_primary BEFORE UPDATE OF state ON receipts "
                           "BEGIN SELECT RAISE(ROLLBACK, 'R6_PRIMARY'); END")
        with self.assertRaises(sqlite3.Error) as cm:
            journal.respond(SUBJECT, r, DIGEST)
        self.assertIsInstance(cm.exception, sqlite3.IntegrityError)
        self.assertIn('R6_PRIMARY', str(cm.exception))
        self.assertFalse(getattr(cm.exception, '__notes__', None))
        self.assertFalse(journal.db.in_transaction)
        self.assertEqual(stored(path, SUBJECT, r), ('RESERVED', None))
        journal.db.execute('DROP TRIGGER r6_primary')
        journal.respond(SUBJECT, r, DIGEST)
        self.assertEqual(stored(path, SUBJECT, r), ('RESPONDING', None))

    def test_failed_rollback_keeps_primary_and_poisons_the_journal(self):
        journal, path = open_journal(self)
        r = rid()
        journal.reserve(SUBJECT, r)
        journal.db = RollbackFails(journal.db)
        primary = LookupError('R6_PRIMARY')
        with self.assertRaises(BaseException) as cm:
            with journal._tx():
                journal.db.execute("UPDATE receipts SET state='UNCERTAIN' WHERE request_id=?", (r,))
                raise primary
        self.assertIs(cm.exception, primary)
        self.assertTrue(any('JOURNAL_ROLLBACK_FAILED' in n for n in getattr(primary, '__notes__', ())))
        self.assertEqual(stored(path, SUBJECT, r), ('RESERVED', None))
        with self.assertRaises(Exception) as again:
            journal.respond(SUBJECT, r, DIGEST)
        self.assertIsInstance(again.exception, ReceiptError)
        self.assertEqual(again.exception.code, 'JOURNAL_POISONED')

    def test_commit_failure_keeps_primary_and_journal_usable(self):
        """Negative control: COMMIT fails with the transaction still open."""
        journal, path = open_journal(self)
        journal.db.execute('PRAGMA foreign_keys=ON')
        journal.db.execute('CREATE TABLE r6_parent(id INTEGER PRIMARY KEY)')
        journal.db.execute('CREATE TABLE r6_child(p INTEGER REFERENCES r6_parent(id) DEFERRABLE INITIALLY DEFERRED)')
        with self.assertRaises(sqlite3.Error) as cm:
            with journal._tx():
                journal.db.execute('INSERT INTO r6_child VALUES(7)')
        self.assertIsInstance(cm.exception, sqlite3.IntegrityError)
        self.assertFalse(journal.db.in_transaction)
        r = rid()
        responding(journal, r)
        self.assertEqual(stored(path, SUBJECT, r), ('RESPONDING', None))


class AckValidatedBeforeMutation(unittest.TestCase):

    def test_invalid_acks_change_no_row(self):
        journal, path = open_journal(self)
        cases = [
            ('verdict outside the enum', dict(verdict='BOGUS'), 'INVALID_ACK_VERDICT'),
            ('verdict null', dict(verdict=None), 'INVALID_ACK_VERDICT'),
            ('verdict str subclass', dict(verdict=LooksLikeStr('ACCEPTED')), 'INVALID_ACK_VERDICT'),
            ('unknown version', dict(version='udx-ack/0'), 'UNSUPPORTED_ACK_VERSION'),
            ('version str subclass', dict(version=LooksLikeStr(dr.ACK_VERSION)), 'UNSUPPORTED_ACK_VERSION'),
            ('request id not canonical', 'upper', 'INVALID_ACK_REQUEST_ID'),
            ('request id not a string', dict(request_id=7), 'INVALID_ACK_REQUEST_ID'),
            ('digest upper case', dict(digest='A' * 64), 'INVALID_ACK_DIGEST'),
            ('digest not a string', dict(digest=7), 'INVALID_ACK_DIGEST'),
        ]
        observed, expected = [], []
        for name, change, code in cases:
            r = rid()
            responding(journal, r)
            fields = {'request_id': r.upper()} if change == 'upper' else dict(change)
            obj = ack(**{'request_id': r, **fields})
            try:
                outcome = 'NO_REFUSAL:' + journal.acknowledge(SUBJECT, r, obj)
            except ReceiptError as exc:
                outcome = exc.code
            observed.append((name, outcome, stored(path, SUBJECT, r)))
            expected.append((name, code, ('RESPONDING', None)))
        self.assertEqual(observed, expected)

    def test_ack_is_snapshotted_before_the_transaction(self):
        """A caller-held dict changed while the transaction runs (here: from the
        clock callback inside it) must not decide the recorded verdict."""
        obj = {}
        clock = Clock(hooks={3: lambda: obj.__setitem__('verdict', 'ACCEPTED')})
        journal, path = open_journal(self, clock)
        r = rid()
        responding(journal, r)                     # clock calls 1 and 2
        obj.update(ack(r, verdict='REJECTED'))
        state = journal.acknowledge(SUBJECT, r, obj)   # clock call 3 flips the dict
        self.assertEqual((state, stored(path, SUBJECT, r)), ('CLIENT_REJECTED', ('CLIENT_REJECTED', None)))

    def test_valid_mismatching_ack_is_still_recorded(self):
        """Negative control (W31-DK5 semantics): a VALID ack for another digest is
        recorded as UNACKED and refused."""
        journal, path = open_journal(self)
        r = rid()
        responding(journal, r)
        with self.assertRaises(ReceiptError) as cm:
            journal.acknowledge(SUBJECT, r, ack(r, digest='b' * 64))
        self.assertEqual(cm.exception.code, 'ACK_DIGEST_MISMATCH')
        self.assertEqual(stored(path, SUBJECT, r), ('UNACKED', 'ACK_DIGEST_MISMATCH'))
        r2 = rid()
        responding(journal, r2)
        self.assertEqual(journal.acknowledge(SUBJECT, r2, ack(r2)), 'DELIVERED')


@unittest.skipUnless(LINUX_IPC, 'Linux non-root SO_PEERCRED lane unavailable')
class AckedLaneReportsOnlyJournaledState(unittest.TestCase):

    def setUp(self):
        from udx_ref import linux_ipc
        from udx_ref.core import Broker, FixtureAdapter, ObjectMetadata, Policy
        self.ipc = linux_ipc
        owner = f'uid:{os.geteuid()}'
        self.subject = owner
        self.broker = Broker(FixtureAdapter({'sample-1': ObjectMetadata('sample-1', owner, 42, 'fixture')}),
                             Policy({owner: {'udx.discover', 'udx.metadata.read'}}))

    def exchange(self, journal, r):
        import json
        from udx_ref.core import VERSION
        wire = json.dumps({'version': VERSION, 'request_id': r, 'capability': 'object.metadata.read',
                           'params': {'object_id': 'sample-1'}}).encode()
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        out = {}

        def target():
            with server:
                out['state'] = self.ipc.serve_connection_acked(server, self.broker, journal)
        t = threading.Thread(target=target)
        t.start()
        with client:
            client.settimeout(5)
            client.sendall(self.ipc.HEADER.pack(len(wire)) + wire)
            size = self.ipc.HEADER.unpack(self.ipc.recv_exact(client, 4, deadline=time.monotonic() + 2))[0]
            reply = self.ipc.recv_exact(client, size, deadline=time.monotonic() + 2)
            a = dr.encode_ack(r, dr.response_digest(reply), 'ACCEPTED')
            client.sendall(self.ipc.HEADER.pack(len(a)) + a)
        t.join(10)
        self.assertFalse(t.is_alive())
        return out['state']

    def test_clock_rollback_at_ack_is_not_reported_as_unacked(self):
        # reserve = clock call 1, respond = 2, acknowledge = 3 -> goes back in time.
        journal, path = open_journal(self, Clock(hooks={3: lambda: 5}))
        r = rid()
        state = self.exchange(journal, r)
        self.assertEqual(stored(path, self.subject, r), ('RESPONDING', None))
        self.assertIsNone(state)               # d5049ce: 'UNACKED', which the journal does not hold

    def test_not_responding_reports_the_stored_state(self):
        journal, path = open_journal(self)
        r = rid()
        real = journal.acknowledge

        def recovered_meanwhile(*args, **kwargs):
            journal.recover()                  # the row leaves RESPONDING before the ACK lands
            return real(*args, **kwargs)
        with mock.patch.object(journal, 'acknowledge', side_effect=recovered_meanwhile):
            state = self.exchange(journal, r)
        self.assertEqual(stored(path, self.subject, r), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))
        self.assertEqual(state, 'UNCERTAIN')   # d5049ce: 'UNACKED'

    def test_mismatch_still_reports_unacked(self):
        """Negative control: a committed mismatch is reported as UNACKED."""
        journal, path = open_journal(self)
        r = rid()
        with mock.patch.object(dr, 'response_digest', return_value='c' * 64):
            state = self.exchange(journal, r)
        self.assertEqual(stored(path, self.subject, r), ('UNACKED', 'ACK_DIGEST_MISMATCH'))
        self.assertEqual(state, 'UNACKED')


if __name__ == '__main__':
    unittest.main()
