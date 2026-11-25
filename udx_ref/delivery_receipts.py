"""W31: versioned delivery acknowledgement and durable receipts (research only).

Answers W23 P1 DELIVERY ("peer close is not processing") and the G4 durability
gate ("volatile deque/cache only") for the Linux AF_UNIX lane.

What an ACK means here, and nothing more: a client process (same UID, see
ADR-UDX-006) received exactly the response bytes whose SHA-256 it names, and
its strict decoder (``core.decode_response``) accepted (``ACCEPTED``) or refused
(``REJECTED``) them. It is NOT evidence that an application used the data, and a
same-UID process can forge it.

Receipt journal (SQLite WAL + ``synchronous=FULL``, per-user private file):

    reserve()  RESERVED     before dispatch: durable replay protection across restarts
    respond()  RESPONDING   digest committed BEFORE the first response byte is sent
    acknowledge()           -> DELIVERED (ACCEPTED) | CLIENT_REJECTED (REJECTED)
    unacknowledged()        -> UNACKED with a typed reason (missing, timeout, malformed, ...)
    recover()               RESERVED/RESPONDING left by a crash -> UNCERTAIN; never re-sent

Like ``durable_grants``: local resilience, NOT a tamper-proof ledger, and POSIX only.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager

from .core import Refusal, check_scalars_and_depth, reject_constant, reject_float, reject_int, unique_pairs
from .durable_grants import GrantDenied, _rollback_keep_primary, _secure_store

ACK_VERSION = 'udx-ack/1'
SCHEMA_VERSION = 1
MAX_ACK_BYTES = 256
VERDICTS = ('ACCEPTED', 'REJECTED')
STATES = ('RESERVED', 'RESPONDING', 'DELIVERED', 'CLIENT_REJECTED', 'UNACKED', 'UNCERTAIN')
OPEN_STATES = ('RESERVED', 'RESPONDING')
TERMINAL_STATES = ('DELIVERED', 'CLIENT_REJECTED', 'UNACKED', 'UNCERTAIN')
RECEIPT_STATES = ('DELIVERED', 'CLIENT_REJECTED')        # the only ones a server confirms
UNACK_REASONS = ('ACK_MISSING', 'ACK_TIMEOUT', 'ACK_MALFORMED', 'SEND_FAILED', 'DISPATCH_FAILED')
MAX_CLOCK_NS = 2**63 - 1
DEFAULT_MAX_RECEIPTS = 100_000
_HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
_SUBJECT = re.compile(r'[a-z][a-z0-9]*:[A-Za-z0-9._-]{1,128}\Z', re.ASCII)
_ACK_FIELDS = frozenset(('version', 'request_id', 'response_sha256', 'verdict'))
_RECEIPT_FIELDS = frozenset(('version', 'request_id', 'receipt'))


class ReceiptError(RuntimeError):
    """Typed refusal of the receipt layer; ``code`` is an upper-case reason."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def response_digest(raw) -> str:
    """SHA-256 (lower-case hex) of the exact response payload bytes (no length header)."""
    if type(raw) is not bytes:
        raise ReceiptError('INVALID_RESPONSE_BYTES')
    return hashlib.sha256(raw).hexdigest()


def _canonical_uuid(value) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _dumps(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=True).encode('ascii')


def _loads(raw, too_large: str, malformed: str):
    if type(raw) is not bytes:
        raise ReceiptError(malformed)
    if len(raw) > MAX_ACK_BYTES:
        raise ReceiptError(too_large)
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique_pairs,
                         parse_float=reject_float, parse_int=reject_int, parse_constant=reject_constant)
        check_scalars_and_depth(obj)
    except (Refusal, UnicodeDecodeError, ValueError, RecursionError):
        raise ReceiptError(malformed) from None
    return obj


def encode_ack(request_id: str, response_sha256: str, verdict: str) -> bytes:
    if not _canonical_uuid(request_id):
        raise ReceiptError('INVALID_ACK_REQUEST_ID')
    if type(response_sha256) is not str or not _HEX64.fullmatch(response_sha256):
        raise ReceiptError('INVALID_ACK_DIGEST')
    if verdict not in VERDICTS:
        raise ReceiptError('INVALID_ACK_VERDICT')
    return _dumps({'version': ACK_VERSION, 'request_id': request_id,
                   'response_sha256': response_sha256, 'verdict': verdict})


def decode_ack(raw) -> dict:
    """Strict ACK decoder: exact field set, canonical UUID, lower-case hex digest."""
    return _validate_ack(_loads(raw, 'ACK_TOO_LARGE', 'MALFORMED_ACK'))


def _validate_ack(obj) -> dict:
    """Complete ACK validation, shared by decode_ack and acknowledge (R6 B2, I2)."""
    if type(obj) is not dict or set(obj) != _ACK_FIELDS:
        raise ReceiptError('INVALID_ACK')
    if type(obj['version']) is not str or obj['version'] != ACK_VERSION:
        raise ReceiptError('UNSUPPORTED_ACK_VERSION')
    if not _canonical_uuid(obj['request_id']):
        raise ReceiptError('INVALID_ACK_REQUEST_ID')
    if type(obj['response_sha256']) is not str or not _HEX64.fullmatch(obj['response_sha256']):
        raise ReceiptError('INVALID_ACK_DIGEST')
    if type(obj['verdict']) is not str or obj['verdict'] not in VERDICTS:
        raise ReceiptError('INVALID_ACK_VERDICT')
    return obj


def encode_receipt(request_id: str, state: str) -> bytes:
    if not _canonical_uuid(request_id):
        raise ReceiptError('INVALID_RECEIPT')
    if state not in RECEIPT_STATES:
        raise ReceiptError('INVALID_RECEIPT')
    return _dumps({'version': ACK_VERSION, 'request_id': request_id, 'receipt': state})


def decode_receipt(raw, *, expected_request_id: str, verdict: str) -> str:
    """The server's confirmation must name this request and match the sent verdict."""
    obj = _loads(raw, 'RECEIPT_TOO_LARGE', 'INVALID_RECEIPT')
    if type(obj) is not dict or set(obj) != _RECEIPT_FIELDS or obj['version'] != ACK_VERSION:
        raise ReceiptError('INVALID_RECEIPT')
    if obj['request_id'] != expected_request_id:
        raise ReceiptError('RECEIPT_REQUEST_MISMATCH')
    expected = {'ACCEPTED': 'DELIVERED', 'REJECTED': 'CLIENT_REJECTED'}.get(verdict)
    if expected is None or obj['receipt'] != expected:
        raise ReceiptError('RECEIPT_STATE_MISMATCH')
    return obj['receipt']


def _check_key(subject, request_id):
    if type(subject) is not str or not _SUBJECT.fullmatch(subject):
        raise ReceiptError('BAD_SUBJECT')
    if not _canonical_uuid(request_id):
        raise ReceiptError('BAD_REQUEST_ID')


class ReceiptJournal:
    """Durable per-(subject, request_id) delivery receipts. One shared connection,
    transactions serialized by a lock (same pattern as DurableGrantStore)."""

    def __init__(self, db_path: str, *, clock_ns=None, max_receipts: int = DEFAULT_MAX_RECEIPTS):
        if type(max_receipts) is not int or not 1 <= max_receipts <= 10**7:
            raise ReceiptError('BAD_CAPACITY')
        try:
            self.path = _secure_store(db_path)
        except GrantDenied as exc:
            raise ReceiptError(str(exc)) from None
        self._tx_lock = threading.RLock()
        self._now = clock_ns if clock_ns is not None else time.time_ns
        self._max = max_receipts
        self.db = sqlite3.connect(self.path, timeout=3, isolation_level=None, check_same_thread=False)
        try:
            self.db.execute('PRAGMA busy_timeout=3000')
            if self.db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() != 'wal':
                raise ReceiptError('WAL_REQUIRED')
            self.db.execute('PRAGMA synchronous=FULL')
            if self.db.execute('PRAGMA synchronous').fetchone()[0] != 2:
                raise ReceiptError('FULL_SYNC_REQUIRED')
            states = ','.join("'%s'" % s for s in STATES)
            with self._tx():
                self.db.execute('CREATE TABLE IF NOT EXISTS receipt_meta (id INTEGER PRIMARY KEY CHECK(id=1), '
                                'schema_version INTEGER NOT NULL, ack_version TEXT NOT NULL)')
                self.db.execute(f'''CREATE TABLE IF NOT EXISTS receipts (
                  subject TEXT NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL,
                  response_sha256 TEXT, reason TEXT,
                  created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
                  PRIMARY KEY(subject, request_id), CHECK(state IN ({states})))''')
                self.db.execute('CREATE TABLE IF NOT EXISTS clock_guard (id INTEGER PRIMARY KEY CHECK(id=1), '
                                'high_ns INTEGER NOT NULL)')
                meta = self.db.execute('SELECT schema_version, ack_version FROM receipt_meta WHERE id=1').fetchone()
                if meta is None:
                    self.db.execute('INSERT INTO receipt_meta VALUES(1,?,?)', (SCHEMA_VERSION, ACK_VERSION))
                elif tuple(meta) != (SCHEMA_VERSION, ACK_VERSION):
                    raise ReceiptError('SCHEMA_MISMATCH')
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def _tx(self):
        with self._tx_lock:
            if getattr(self, '_poisoned', False):
                raise ReceiptError('JOURNAL_POISONED')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self.db.execute('COMMIT')
            except BaseException as primary:
                # R6 B2: never mask the primary error (see durable_grants).
                _rollback_keep_primary(self, primary)
                raise

    def _clock(self) -> int:
        now = self._now()
        if type(now) is not int or not 0 < now <= MAX_CLOCK_NS:
            raise ReceiptError('INVALID_CLOCK')
        last = self.db.execute('SELECT high_ns FROM clock_guard WHERE id=1').fetchone()
        if last is not None and now < last[0]:
            raise ReceiptError('CLOCK_ROLLBACK')
        self.db.execute('INSERT INTO clock_guard(id,high_ns) VALUES(1,?) '
                        'ON CONFLICT(id) DO UPDATE SET high_ns=excluded.high_ns', (now,))
        return now

    def _row(self, subject, request_id):
        return self.db.execute('SELECT state, response_sha256 FROM receipts WHERE subject=? AND request_id=?',
                               (subject, request_id)).fetchone()

    def _set(self, subject, request_id, state, now, reason=None):
        self.db.execute('UPDATE receipts SET state=?, reason=?, updated_ns=? WHERE subject=? AND request_id=?',
                        (state, reason, now, subject, request_id))

    def reserve(self, subject: str, request_id: str) -> None:
        """Before dispatch. A known (subject, request_id) is a replay, whatever its state."""
        _check_key(subject, request_id)
        with self._tx():
            now = self._clock()
            if self._row(subject, request_id) is not None:
                raise ReceiptError('REPLAY_REJECTED')
            if self.db.execute('SELECT count(*) FROM receipts').fetchone()[0] >= self._max:
                raise ReceiptError('JOURNAL_FULL')
            self.db.execute('INSERT INTO receipts VALUES(?,?,?,NULL,NULL,?,?)',
                            (subject, request_id, 'RESERVED', now, now))

    def respond(self, subject: str, request_id: str, response_sha256: str) -> None:
        """Write-ahead: the digest is durable before the first response byte leaves."""
        _check_key(subject, request_id)
        if type(response_sha256) is not str or not _HEX64.fullmatch(response_sha256):
            raise ReceiptError('BAD_DIGEST')
        with self._tx():
            now = self._clock()
            row = self._row(subject, request_id)
            if row is None or row[0] != 'RESERVED':
                raise ReceiptError('NOT_RESERVED')
            self.db.execute('UPDATE receipts SET state=?, response_sha256=?, updated_ns=? '
                            'WHERE subject=? AND request_id=?',
                            ('RESPONDING', response_sha256, now, subject, request_id))

    def acknowledge(self, subject: str, request_id: str, ack: dict) -> str:
        """Apply a decoded ACK. A mismatching ACK is recorded as UNACKED and refused.

        R6 B2 (I2): the ACK is copied and COMPLETELY validated before the
        transaction; an invalid ACK changes no row. Only a valid ACK that names
        another request or digest is recorded (UNACKED). The copy also pins the
        values: a caller-held dict changed during the transaction is not read.
        """
        _check_key(subject, request_id)
        if type(ack) is not dict:
            raise ReceiptError('INVALID_ACK')
        ack = _validate_ack(dict(ack))
        mismatch = None
        with self._tx():
            now = self._clock()
            row = self._row(subject, request_id)
            if row is None or row[0] != 'RESPONDING':
                raise ReceiptError('NOT_RESPONDING')
            if ack['request_id'] != request_id:
                mismatch = 'ACK_REQUEST_MISMATCH'
            elif ack['response_sha256'] != row[1]:
                mismatch = 'ACK_DIGEST_MISMATCH'
            if mismatch is not None:
                self._set(subject, request_id, 'UNACKED', now, mismatch)
                state = 'UNACKED'
            else:
                state = 'DELIVERED' if ack['verdict'] == 'ACCEPTED' else 'CLIENT_REJECTED'
                self._set(subject, request_id, state, now)
        if mismatch is not None:
            raise ReceiptError(mismatch)
        return state

    def unacknowledged(self, subject: str, request_id: str, reason: str) -> None:
        _check_key(subject, request_id)
        if reason not in UNACK_REASONS:
            raise ReceiptError('BAD_REASON')
        with self._tx():
            now = self._clock()
            row = self._row(subject, request_id)
            if row is None or row[0] not in OPEN_STATES:
                raise ReceiptError('NOT_OPEN')
            self._set(subject, request_id, 'UNACKED', now, reason)

    def recover(self) -> int:
        """Explicit supervisor-start operation: open receipts become UNCERTAIN. NEVER re-send."""
        with self._tx():
            now = self._clock()
            count = self.db.execute("SELECT count(*) FROM receipts WHERE state IN ('RESERVED','RESPONDING')"
                                    ).fetchone()[0]
            self.db.execute("UPDATE receipts SET state='UNCERTAIN', reason='RECOVERED_AFTER_CRASH', updated_ns=? "
                            "WHERE state IN ('RESERVED','RESPONDING')", (now,))
            return count

    def prune(self, older_than_ns: int) -> int:
        """Operator API: drop TERMINAL receipts last changed before ``older_than_ns``.
        A pruned request id is no longer a replay: retention = replay window."""
        if type(older_than_ns) is not int or not 0 < older_than_ns <= MAX_CLOCK_NS:
            raise ReceiptError('BAD_RETENTION')
        with self._tx():
            now = self._clock()
            if older_than_ns > now:
                raise ReceiptError('BAD_RETENTION')
            cur = self.db.execute("DELETE FROM receipts WHERE updated_ns < ? AND state IN "
                                  "('DELIVERED','CLIENT_REJECTED','UNACKED','UNCERTAIN')", (older_than_ns,))
            return cur.rowcount

    def state(self, subject: str, request_id: str):
        """(state, reason) or None; read-only, no clock tick."""
        with self._tx_lock:
            row = self.db.execute('SELECT state, reason FROM receipts WHERE subject=? AND request_id=?',
                                  (subject, request_id)).fetchone()
            return tuple(row) if row else None

    def close(self):
        with self._tx_lock:
            self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
