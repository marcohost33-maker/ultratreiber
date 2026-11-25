"""R6 B1 (GPT-6 cross-family reaudit of PR #13 at d5049ce): DurableGrantStore._tx.

Invariant I1: the primary error of a transaction reaches the caller unchanged,
also when SQLite already ended the transaction (trigger RAISE(ROLLBACK)) or the
ROLLBACK itself fails; a cleanup error is at most a note. After an unknown
transaction state the store refuses further transactions (JOURNAL_POISONED).

Runs on every platform: on POSIX through the real private-store checks, elsewhere
the POSIX-only ``_secure_store`` is replaced by the identity (the transaction
code under test does not depend on it; W12 keeps the platform refusal itself).
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from udx_ref import durable_grants
from udx_ref.durable_grants import DurableGrantStore, GrantDenied

POSIX = os.name == 'posix' and hasattr(os, 'getuid')
GID = 'ab' * 20


class Clock:
    def __init__(self, start=10**18):
        self.now = start

    def __call__(self):
        self.now += 1
        return self.now


class RollbackFails:
    """Connection proxy whose ROLLBACK fails (a cleanup error SQLite can raise on I/O faults)."""

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


def open_store(test):
    tmp = tempfile.TemporaryDirectory(prefix='udx-r6b1-')
    test.addCleanup(tmp.cleanup)
    if POSIX:
        os.chmod(tmp.name, 0o700)
    path = str(Path(tmp.name) / 'grants.db')
    if POSIX:
        store = DurableGrantStore(path, clock_ns=Clock())
    else:
        with mock.patch.object(durable_grants, '_secure_store', lambda p: p):
            store = DurableGrantStore(path, clock_ns=Clock())
    test.addCleanup(store.close)
    store.db.execute("INSERT INTO grants VALUES(?,1000,1000,1,2,3,4,5,?,'ISSUED',NULL)", (GID, 2**62))
    return store, path


def stored_state(path):
    fresh = sqlite3.connect(path)          # independent reader: what is really committed
    try:
        return fresh.execute('SELECT state FROM grants WHERE grant_id=?', (GID,)).fetchone()[0]
    finally:
        fresh.close()


class GrantTxPrimaryError(unittest.TestCase):

    def test_trigger_rollback_surfaces_the_integrity_error(self):
        store, path = open_store(self)
        store.db.execute("CREATE TRIGGER r6_primary BEFORE UPDATE OF state ON grants "
                         "BEGIN SELECT RAISE(ROLLBACK, 'R6_PRIMARY'); END")
        with self.assertRaises(sqlite3.Error) as cm:
            store.revoke(GID)
        # d5049ce: OperationalError "cannot rollback - no transaction is active".
        self.assertIsInstance(cm.exception, sqlite3.IntegrityError)
        self.assertIn('R6_PRIMARY', str(cm.exception))
        # SQLite ended the transaction itself: no cleanup was needed or attempted.
        self.assertFalse(getattr(cm.exception, '__notes__', None))
        self.assertFalse(store.db.in_transaction)
        self.assertEqual(stored_state(path), 'ISSUED')
        # No unknown state here (SQLite rolled back itself): the store stays usable.
        store.db.execute('DROP TRIGGER r6_primary')
        store.revoke(GID)
        self.assertEqual(stored_state(path), 'REVOKED')

    def test_failed_rollback_keeps_primary_and_poisons_the_store(self):
        store, path = open_store(self)
        real = store.db
        store.db = RollbackFails(real)
        primary = LookupError('R6_PRIMARY')
        with self.assertRaises(BaseException) as cm:
            with store._tx():
                store.db.execute("UPDATE grants SET state='REVOKED' WHERE grant_id=?", (GID,))
                raise primary
        self.assertIs(cm.exception, primary)
        self.assertTrue(any('JOURNAL_ROLLBACK_FAILED' in n for n in getattr(primary, '__notes__', ())))
        # Unknown state is fail-closed: the uncommitted write is gone (connection
        # closed), and the store refuses every further transaction with a typed code.
        self.assertEqual(stored_state(path), 'ISSUED')
        with self.assertRaises(Exception) as again:
            store.revoke(GID)
        self.assertIsInstance(again.exception, GrantDenied)
        self.assertEqual(str(again.exception), 'JOURNAL_POISONED')

    def test_commit_failure_keeps_primary_and_store_usable(self):
        """Negative control: deferred FK fails at COMMIT while the transaction is
        still open; the ordinary ROLLBACK path runs and nothing is poisoned."""
        store, path = open_store(self)
        store.db.execute('CREATE TABLE r6_parent(id INTEGER PRIMARY KEY)')
        store.db.execute('CREATE TABLE r6_child(p INTEGER REFERENCES r6_parent(id) DEFERRABLE INITIALLY DEFERRED)')
        with self.assertRaises(sqlite3.Error) as cm:
            with store._tx():
                store.db.execute('INSERT INTO r6_child VALUES(7)')
        self.assertIsInstance(cm.exception, sqlite3.IntegrityError)
        self.assertFalse(store.db.in_transaction)
        store.revoke(GID)
        self.assertEqual(stored_state(path), 'REVOKED')

    def test_legitimate_transactions_commit(self):
        """Negative control: the ordinary path is unchanged."""
        store, path = open_store(self)
        store.revoke(GID)
        self.assertEqual(store.state(GID), 'REVOKED')
        self.assertEqual(stored_state(path), 'REVOKED')
        with self.assertRaises(GrantDenied) as cm:
            store.revoke(GID)
        self.assertEqual(str(cm.exception), 'NOT_REVOCABLE')
        self.assertFalse(store.db.in_transaction)


if __name__ == '__main__':
    unittest.main()
