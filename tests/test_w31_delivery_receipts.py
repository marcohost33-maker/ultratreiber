"""W31: versioned delivery ACK and durable receipts (W23 P1 DELIVERY, G4).

Negative first: every refusal of udx_ref/delivery_receipts.py and of the new
acknowledged lane in udx_ref/linux_ipc.py has a test that fails when the
refusal is removed (guard sweep) and a positive control that passes through it.
"""
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from udx_ref import delivery_receipts as dr
from udx_ref.core import VERSION, Broker, FixtureAdapter, ObjectMetadata, Policy, Refusal
from udx_ref.delivery_receipts import ReceiptError, ReceiptJournal

POSIX = os.name == 'posix' and hasattr(os, 'getuid')
LINUX_IPC = sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED') and POSIX and os.geteuid() != 0
RID = '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b'
DIGEST = 'a' * 64
SUBJECT = 'uid:1000'


def rid():
    return str(uuid.uuid4())


class Clock:
    def __init__(self, start=10**18):
        self.now = start

    def __call__(self):
        self.now += 1
        return self.now


def private_dir(test):
    tmp = tempfile.TemporaryDirectory(prefix='udx-w31-')
    test.addCleanup(tmp.cleanup)
    os.chmod(tmp.name, 0o700)
    return Path(tmp.name)


def ack_obj(request_id=RID, digest=DIGEST, verdict='ACCEPTED', **extra):
    obj = {'version': dr.ACK_VERSION, 'request_id': request_id, 'response_sha256': digest, 'verdict': verdict}
    obj.update(extra)
    return obj


def raw(obj):
    return json.dumps(obj).encode()


class AckCodec(unittest.TestCase):
    def code(self, fn, *args, **kw):
        with self.assertRaises(ReceiptError) as cm:
            fn(*args, **kw)
        return cm.exception.code

    def test_round_trip_is_canonical(self):
        wire = dr.encode_ack(RID, DIGEST, 'ACCEPTED')
        self.assertEqual(wire, dr.encode_ack(RID, DIGEST, 'ACCEPTED'))
        self.assertLessEqual(len(wire), dr.MAX_ACK_BYTES)
        self.assertEqual(dr.decode_ack(wire), ack_obj())
        self.assertEqual(dr.decode_ack(dr.encode_ack(RID, DIGEST, 'REJECTED'))['verdict'], 'REJECTED')

    def test_digest_is_sha256_of_exact_bytes(self):
        self.assertEqual(dr.response_digest(b''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertNotEqual(dr.response_digest(b'{"a":1}'), dr.response_digest(b'{"a":1} '))
        self.assertEqual(self.code(dr.response_digest, '{}'), 'INVALID_RESPONSE_BYTES')
        self.assertEqual(self.code(dr.response_digest, bytearray(b'{}')), 'INVALID_RESPONSE_BYTES')

    def test_encode_refuses_bad_fields(self):
        self.assertEqual(self.code(dr.encode_ack, RID.upper(), DIGEST, 'ACCEPTED'), 'INVALID_ACK_REQUEST_ID')
        self.assertEqual(self.code(dr.encode_ack, 'x' * 36, DIGEST, 'ACCEPTED'), 'INVALID_ACK_REQUEST_ID')
        self.assertEqual(self.code(dr.encode_ack, RID, 'A' * 64, 'ACCEPTED'), 'INVALID_ACK_DIGEST')
        self.assertEqual(self.code(dr.encode_ack, RID, b'a' * 64, 'ACCEPTED'), 'INVALID_ACK_DIGEST')
        self.assertEqual(self.code(dr.encode_ack, RID, DIGEST, 'accepted'), 'INVALID_ACK_VERDICT')

    def test_decode_refuses_frame_level_faults(self):
        self.assertEqual(self.code(dr.decode_ack, ack_obj()), 'MALFORMED_ACK')                 # not bytes
        self.assertEqual(self.code(dr.decode_ack, b' ' * 257), 'ACK_TOO_LARGE')
        for bad in (b'{', b'\xff', b'{"a":1.5}', b'{"a":NaN}', b'{"a":1,"a":2}', b'{"a":"\\ud800"}',
                    b'[' * 20 + b']' * 20, b'{"a":9007199254740993}'):
            self.assertEqual(self.code(dr.decode_ack, bad), 'MALFORMED_ACK', bad)

    def test_decode_refuses_envelope_faults(self):
        self.assertEqual(self.code(dr.decode_ack, b'[]'), 'INVALID_ACK')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(extra=1))), 'INVALID_ACK')
        missing = ack_obj(); del missing['verdict']
        self.assertEqual(self.code(dr.decode_ack, raw(missing)), 'INVALID_ACK')
        self.assertEqual(self.code(dr.decode_ack, raw(dict(ack_obj(), version='udx-ack/2'))), 'UNSUPPORTED_ACK_VERSION')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(request_id=RID.upper()))), 'INVALID_ACK_REQUEST_ID')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(request_id=7))), 'INVALID_ACK_REQUEST_ID')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(digest='A' * 64))), 'INVALID_ACK_DIGEST')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(digest=['a']))), 'INVALID_ACK_DIGEST')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(verdict='OK'))), 'INVALID_ACK_VERDICT')
        self.assertEqual(self.code(dr.decode_ack, raw(ack_obj(verdict=['ACCEPTED']))), 'INVALID_ACK_VERDICT')

    def test_uuid_check_paths(self):
        self.assertTrue(dr._canonical_uuid(RID))
        self.assertFalse(dr._canonical_uuid(None))
        self.assertFalse(dr._canonical_uuid(RID + '0'))
        self.assertFalse(dr._canonical_uuid('g' * 8 + RID[8:]))       # 36 chars, not hex: ValueError path
        self.assertFalse(dr._canonical_uuid(RID.upper()))

    def test_receipt_codec(self):
        wire = dr.encode_receipt(RID, 'DELIVERED')
        self.assertEqual(dr.decode_receipt(wire, expected_request_id=RID, verdict='ACCEPTED'), 'DELIVERED')
        rej = dr.encode_receipt(RID, 'CLIENT_REJECTED')
        self.assertEqual(dr.decode_receipt(rej, expected_request_id=RID, verdict='REJECTED'), 'CLIENT_REJECTED')
        self.assertEqual(self.code(dr.encode_receipt, 'nope', 'DELIVERED'), 'INVALID_RECEIPT')
        self.assertEqual(self.code(dr.encode_receipt, RID, 'UNACKED'), 'INVALID_RECEIPT')
        dec = lambda w, **kw: dr.decode_receipt(w, **{'expected_request_id': RID, 'verdict': 'ACCEPTED', **kw})
        self.assertEqual(self.code(dec, b' ' * 300), 'RECEIPT_TOO_LARGE')
        self.assertEqual(self.code(dec, b'{'), 'INVALID_RECEIPT')
        self.assertEqual(self.code(dec, b'[]'), 'INVALID_RECEIPT')
        self.assertEqual(self.code(dec, raw({'version': 'x', 'request_id': RID, 'receipt': 'DELIVERED'})),
                         'INVALID_RECEIPT')
        self.assertEqual(self.code(dec, wire, expected_request_id=rid()), 'RECEIPT_REQUEST_MISMATCH')
        self.assertEqual(self.code(dec, wire, verdict='REJECTED'), 'RECEIPT_STATE_MISMATCH')
        self.assertEqual(self.code(dec, wire, verdict='MAYBE'), 'RECEIPT_STATE_MISMATCH')


@unittest.skipUnless(POSIX, 'receipt journal is POSIX only (like durable_grants)')
class Journal(unittest.TestCase):
    def setUp(self):
        self.dir = private_dir(self)
        self.path = str(self.dir / 'receipts.db')
        self.clock = Clock()
        self.j = ReceiptJournal(self.path, clock_ns=self.clock)
        self.addCleanup(self.j.close)

    def code(self, fn, *args, **kw):
        with self.assertRaises(ReceiptError) as cm:
            fn(*args, **kw)
        return cm.exception.code

    def flow(self, r=RID, digest=DIGEST):
        self.j.reserve(SUBJECT, r)
        self.j.respond(SUBJECT, r, digest)

    def test_happy_path_and_states(self):
        self.j.reserve(SUBJECT, RID)
        self.assertEqual(self.j.state(SUBJECT, RID), ('RESERVED', None))
        self.j.respond(SUBJECT, RID, DIGEST)
        self.assertEqual(self.j.state(SUBJECT, RID), ('RESPONDING', None))
        self.assertEqual(self.j.acknowledge(SUBJECT, RID, ack_obj()), 'DELIVERED')
        self.assertEqual(self.j.state(SUBJECT, RID), ('DELIVERED', None))
        other = rid()
        self.flow(other)
        self.assertEqual(self.j.acknowledge(SUBJECT, other, ack_obj(request_id=other, verdict='REJECTED')),
                         'CLIENT_REJECTED')
        self.assertIsNone(self.j.state(SUBJECT, rid()))

    def test_store_is_private_wal_full(self):
        info = os.lstat(self.path)
        self.assertEqual(info.st_mode & 0o777, 0o600)
        self.assertEqual(self.j.db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        self.assertEqual(self.j.db.execute('PRAGMA synchronous').fetchone()[0], 2)

    def test_store_refusals(self):
        self.assertEqual(self.code(ReceiptJournal, 'relative.db'), 'ABSOLUTE_STORE_PATH_REQUIRED')
        open_dir = self.dir / 'open'
        open_dir.mkdir(); os.chmod(open_dir, 0o755)
        self.assertEqual(self.code(ReceiptJournal, str(open_dir / 'r.db')), 'UNSAFE_STORE_DIRECTORY')
        for bad in (0, -1, True, 1.0, 10**7 + 1):
            self.assertEqual(self.code(ReceiptJournal, str(self.dir / 'c.db'), max_receipts=bad), 'BAD_CAPACITY', bad)
        ReceiptJournal(str(self.dir / 'one.db'), max_receipts=1).close()               # boundary admitted

    def test_wal_and_full_sync_are_required(self):
        real = sqlite3.connect

        class Proxy:
            def __init__(self, conn, fake):
                self.conn, self.fake = conn, fake

            def execute(self, sql, *a):
                if sql in self.fake:
                    return mock.Mock(fetchone=lambda: self.fake[sql])
                return self.conn.execute(sql, *a)

            def close(self):
                self.conn.close()

        for fake, code in (({'PRAGMA journal_mode=WAL': ('delete',)}, 'WAL_REQUIRED'),
                           ({'PRAGMA synchronous': (1,)}, 'FULL_SYNC_REQUIRED')):
            with mock.patch.object(dr.sqlite3, 'connect', lambda *a, fake=fake, **k: Proxy(real(*a, **k), fake)):
                self.assertEqual(self.code(ReceiptJournal, str(self.dir / ('p%s.db' % code))), code)

    def test_schema_version_is_pinned(self):
        self.j.db.execute('UPDATE receipt_meta SET schema_version=2 WHERE id=1')
        self.assertEqual(self.code(ReceiptJournal, self.path), 'SCHEMA_MISMATCH')
        self.j.db.execute("UPDATE receipt_meta SET schema_version=1, ack_version='udx-ack/0' WHERE id=1")
        self.assertEqual(self.code(ReceiptJournal, self.path), 'SCHEMA_MISMATCH')
        self.j.db.execute("UPDATE receipt_meta SET ack_version='udx-ack/1' WHERE id=1")
        ReceiptJournal(self.path).close()

    def test_replay_is_durable_across_reopen(self):
        self.flow()
        self.j.acknowledge(SUBJECT, RID, ack_obj())
        self.j.close()
        again = ReceiptJournal(self.path)
        self.addCleanup(again.close)
        self.assertEqual(self.code(again.reserve, SUBJECT, RID), 'REPLAY_REJECTED')
        again.reserve('uid:1001', RID)                         # key is (subject, request_id)

    def test_replay_in_every_state(self):
        for state_setup in ('RESERVED', 'RESPONDING', 'UNACKED'):
            r = rid()
            self.j.reserve(SUBJECT, r)
            if state_setup != 'RESERVED':
                self.j.respond(SUBJECT, r, DIGEST)
            if state_setup == 'UNACKED':
                self.j.unacknowledged(SUBJECT, r, 'ACK_TIMEOUT')
            self.assertEqual(self.code(self.j.reserve, SUBJECT, r), 'REPLAY_REJECTED', state_setup)

    def test_capacity_is_a_typed_refusal(self):
        small = ReceiptJournal(str(self.dir / 'small.db'), max_receipts=2)
        self.addCleanup(small.close)
        small.reserve(SUBJECT, rid()); small.reserve(SUBJECT, rid())
        self.assertEqual(self.code(small.reserve, SUBJECT, rid()), 'JOURNAL_FULL')

    def test_key_refusals(self):
        for subject in ('', 'uid', 'UID:1', 'uid:', 'uid:a b', 7, None, 'uid:' + 'x' * 129):
            self.assertEqual(self.code(self.j.reserve, subject, RID), 'BAD_SUBJECT', subject)
        for r in (RID.upper(), 'x', None, RID[:-1]):
            self.assertEqual(self.code(self.j.reserve, SUBJECT, r), 'BAD_REQUEST_ID', r)
        self.j.reserve('sid:S-1-5-21-1.2_3', RID)

    def test_respond_refusals(self):
        self.assertEqual(self.code(self.j.respond, SUBJECT, RID, DIGEST), 'NOT_RESERVED')
        self.j.reserve(SUBJECT, RID)
        for bad in ('A' * 64, 'a' * 63, None, b'a' * 64):
            self.assertEqual(self.code(self.j.respond, SUBJECT, RID, bad), 'BAD_DIGEST', bad)
        self.j.respond(SUBJECT, RID, DIGEST)
        self.assertEqual(self.code(self.j.respond, SUBJECT, RID, DIGEST), 'NOT_RESERVED')

    def test_ack_refusals_and_mismatch_is_recorded(self):
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, ack_obj()), 'NOT_RESPONDING')
        self.j.reserve(SUBJECT, RID)
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, ack_obj()), 'NOT_RESPONDING')
        self.j.respond(SUBJECT, RID, DIGEST)
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, 'ACK'), 'INVALID_ACK')
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, ack_obj(extra=1)), 'INVALID_ACK')
        self.assertEqual(self.j.state(SUBJECT, RID), ('RESPONDING', None))
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, ack_obj(digest='b' * 64)), 'ACK_DIGEST_MISMATCH')
        self.assertEqual(self.j.state(SUBJECT, RID), ('UNACKED', 'ACK_DIGEST_MISMATCH'))      # committed, not rolled back
        other = rid()
        self.flow(other)
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, other, ack_obj()), 'ACK_REQUEST_MISMATCH')
        self.assertEqual(self.j.state(SUBJECT, other), ('UNACKED', 'ACK_REQUEST_MISMATCH'))
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, other, ack_obj(request_id=other)), 'NOT_RESPONDING')

    def test_unacknowledged(self):
        self.assertEqual(self.code(self.j.unacknowledged, SUBJECT, RID, 'ACK_TIMEOUT'), 'NOT_OPEN')
        self.j.reserve(SUBJECT, RID)
        self.assertEqual(self.code(self.j.unacknowledged, SUBJECT, RID, 'BECAUSE'), 'BAD_REASON')
        self.j.unacknowledged(SUBJECT, RID, 'DISPATCH_FAILED')                    # from RESERVED
        self.assertEqual(self.j.state(SUBJECT, RID), ('UNACKED', 'DISPATCH_FAILED'))
        self.assertEqual(self.code(self.j.unacknowledged, SUBJECT, RID, 'ACK_TIMEOUT'), 'NOT_OPEN')
        other = rid()
        self.flow(other)
        self.j.unacknowledged(SUBJECT, other, 'ACK_MISSING')                     # from RESPONDING
        self.assertEqual(self.j.state(SUBJECT, other), ('UNACKED', 'ACK_MISSING'))

    def test_recover_marks_open_receipts_uncertain_only(self):
        a, b, c = rid(), rid(), rid()
        self.j.reserve(SUBJECT, a)
        self.flow(b)
        self.flow(c); self.j.acknowledge(SUBJECT, c, ack_obj(request_id=c))
        self.assertEqual(self.j.recover(), 2)
        self.assertEqual(self.j.state(SUBJECT, a), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))
        self.assertEqual(self.j.state(SUBJECT, b), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))
        self.assertEqual(self.j.state(SUBJECT, c), ('DELIVERED', None))
        self.assertEqual(self.j.recover(), 0)
        self.assertEqual(self.code(self.j.reserve, SUBJECT, a), 'REPLAY_REJECTED')   # never re-dispatched

    def test_clock_refusals(self):
        for bad in (0, -5, 1.5, None, True, dr.MAX_CLOCK_NS + 1, 2**1024):
            j = ReceiptJournal(str(self.dir / 'clk.db'), clock_ns=lambda bad=bad: bad)
            try:
                self.assertEqual(self.code(j.reserve, SUBJECT, rid()), 'INVALID_CLOCK', bad)
            finally:
                j.close()
        edge = ReceiptJournal(str(self.dir / 'edge.db'), clock_ns=lambda: dr.MAX_CLOCK_NS)
        self.addCleanup(edge.close)
        edge.reserve(SUBJECT, rid())
        self.flow()
        self.clock.now -= 1000
        self.assertEqual(self.code(self.j.acknowledge, SUBJECT, RID, ack_obj()), 'CLOCK_ROLLBACK')
        self.assertEqual(self.j.state(SUBJECT, RID), ('RESPONDING', None))

    def test_prune_only_terminal_and_old(self):
        old, open_, new = rid(), rid(), rid()
        self.flow(old); self.j.acknowledge(SUBJECT, old, ack_obj(request_id=old))
        self.j.reserve(SUBJECT, open_)
        cut = self.clock.now + 1
        self.flow(new); self.j.acknowledge(SUBJECT, new, ack_obj(request_id=new))
        self.assertEqual(self.j.prune(cut), 1)
        self.assertIsNone(self.j.state(SUBJECT, old))
        self.assertEqual(self.j.state(SUBJECT, open_)[0], 'RESERVED')
        self.assertEqual(self.j.state(SUBJECT, new)[0], 'DELIVERED')
        self.j.reserve(SUBJECT, old)                         # documented: retention = replay window
        for bad in (0, -1, 1.0, True, dr.MAX_CLOCK_NS + 1, self.clock.now + 10**9):
            self.assertEqual(self.code(self.j.prune, bad), 'BAD_RETENTION', bad)

    def test_concurrent_reserve_has_one_winner(self):
        results = []
        barrier = threading.Barrier(12)

        def worker():
            barrier.wait()
            try:
                self.j.reserve(SUBJECT, RID)
                results.append('OK')
            except ReceiptError as exc:
                results.append(exc.code)
        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ['OK'] + ['REPLAY_REJECTED'] * 11)


CRASH_CHILD = r'''
import sys
from udx_ref.delivery_receipts import ReceiptJournal
j = ReceiptJournal(sys.argv[1])
j.reserve('uid:1000', sys.argv[2])
j.respond('uid:1000', sys.argv[2], 'c' * 64)
j.reserve('uid:1000', sys.argv[3])
sys.stdout.write('READY\n'); sys.stdout.flush()
sys.stdin.read()
'''


@unittest.skipUnless(POSIX and hasattr(signal, 'SIGKILL'), 'POSIX process kill required')
class CrashRecovery(unittest.TestCase):
    def test_sigkill_between_respond_and_ack(self):
        d = private_dir(self)
        db = str(d / 'receipts.db')
        a, b = rid(), rid()
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        child = subprocess.Popen([sys.executable, '-c', CRASH_CHILD, db, a, b], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, env=env)
        try:
            self.assertEqual(child.stdout.readline(), b'READY\n')
            child.send_signal(signal.SIGKILL)
            self.assertEqual(child.wait(timeout=10), -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
            child.stdin.close(); child.stdout.close()
        with ReceiptJournal(db) as j:
            self.assertEqual(j.state('uid:1000', a), ('RESPONDING', None))     # write-ahead survived the kill
            self.assertEqual(j.recover(), 2)
            self.assertEqual(j.state('uid:1000', a), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))
            self.assertEqual(j.state('uid:1000', b), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))
            with self.assertRaises(ReceiptError) as cm:
                j.reserve('uid:1000', a)
            self.assertEqual(cm.exception.code, 'REPLAY_REJECTED')


def make_broker():
    owner = f'uid:{os.geteuid()}'
    return Broker(FixtureAdapter({'sample-1': ObjectMetadata('sample-1', owner, 42, 'fixture')}),
                  Policy({owner: {'udx.discover', 'udx.metadata.read'}}))


def request(request_id=None, **params):
    return json.dumps({'version': VERSION, 'request_id': request_id or rid(),
                       'capability': 'object.metadata.read',
                       'params': params or {'object_id': 'sample-1'}}).encode()


@unittest.skipUnless(LINUX_IPC, 'Linux non-root SO_PEERCRED lane unavailable')
class AckedLaneSocketpair(unittest.TestCase):
    """The server half runs serve_connection_acked on a real AF_UNIX socketpair
    (SO_PEERCRED works there); the test plays a scripted client."""

    def setUp(self):
        from udx_ref import linux_ipc
        self.ipc = linux_ipc
        self.dir = private_dir(self)
        self.journal = ReceiptJournal(str(self.dir / 'receipts.db'))
        self.addCleanup(self.journal.close)
        self.broker = make_broker()
        self.subject = f'uid:{os.geteuid()}'

    def run_server(self, script, ack_deadline=None):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        out = {}

        def target():
            with server:
                if ack_deadline is None:
                    out['state'] = self.ipc.serve_connection_acked(server, self.broker, self.journal)
                else:
                    with mock.patch.object(self.ipc, 'ACK_DEADLINE_S', ack_deadline):
                        out['state'] = self.ipc.serve_connection_acked(server, self.broker, self.journal)
        t = threading.Thread(target=target)
        t.start()
        with client:
            client.settimeout(5)
            out['client'] = script(client)
        t.join(10)
        self.assertFalse(t.is_alive())
        return out

    def send(self, conn, payload):
        conn.sendall(self.ipc.HEADER.pack(len(payload)) + payload)

    def recv(self, conn):
        size = self.ipc.HEADER.unpack(self.ipc.recv_exact(conn, 4, deadline=time.monotonic() + 2))[0]
        return self.ipc.recv_exact(conn, size, deadline=time.monotonic() + 2)

    def exchange(self, verdict='ACCEPTED', digest=None, ack_rid=None, request_id=None):
        r = request_id or rid()

        def script(conn):
            self.send(conn, request(r))
            reply = self.recv(conn)
            ack = dr.encode_ack(ack_rid or r, digest or dr.response_digest(reply), verdict)
            self.send(conn, ack)
            try:
                return reply, self.recv(conn)
            except ConnectionError:
                return reply, None
        return r, self.run_server(script)

    def test_delivered_with_receipt(self):
        r, out = self.exchange()
        reply, receipt = out['client']
        self.assertEqual(json.loads(reply)['code'], 'OK')
        self.assertEqual(out['state'], 'DELIVERED')
        self.assertEqual(dr.decode_receipt(receipt, expected_request_id=r, verdict='ACCEPTED'), 'DELIVERED')
        self.assertEqual(self.journal.state(self.subject, r), ('DELIVERED', None))

    def test_client_rejected(self):
        r, out = self.exchange(verdict='REJECTED')
        self.assertEqual(out['state'], 'CLIENT_REJECTED')
        self.assertEqual(dr.decode_receipt(out['client'][1], expected_request_id=r, verdict='REJECTED'),
                         'CLIENT_REJECTED')

    def test_wrong_digest_is_unacked_without_receipt(self):
        r, out = self.exchange(digest='0' * 64)
        self.assertEqual(out['state'], 'UNACKED')
        self.assertIsNone(out['client'][1])
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'ACK_DIGEST_MISMATCH'))

    def test_ack_for_another_request_is_unacked(self):
        r, out = self.exchange(ack_rid=rid())
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'ACK_REQUEST_MISMATCH'))
        self.assertIsNone(out['client'][1])

    def test_close_without_ack(self):
        r = rid()

        def script(conn):
            self.send(conn, request(r))
            return self.recv(conn)
        out = self.run_server(script)
        self.assertEqual(out['state'], 'UNACKED')
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'ACK_MISSING'))

    def test_ack_timeout(self):
        r = rid()

        def script(conn):
            self.send(conn, request(r))
            reply = self.recv(conn)
            conn.sendall(self.ipc.HEADER.pack(10)[:2])          # half a header, then silence
            time.sleep(0.6)
            return reply
        self.run_server(script, ack_deadline=0.2)
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'ACK_TIMEOUT'))

    def test_malformed_and_oversized_ack(self):
        for payload, header in ((b'{"version":"udx-ack/1"}', None), (b'', dr.MAX_ACK_BYTES + 1)):
            r = rid()

            def script(conn, payload=payload, header=header):
                self.send(conn, request(r))
                reply = self.recv(conn)
                if header is None:
                    self.send(conn, payload)
                else:
                    conn.sendall(self.ipc.HEADER.pack(header))
                return reply
            out = self.run_server(script)
            self.assertEqual(out['state'], 'UNACKED')
            self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'ACK_MALFORMED'))

    def test_replay_is_refused_before_dispatch(self):
        r, _ = self.exchange()
        reads = self.broker.adapter.read_count

        def script(conn):
            self.send(conn, request(r))
            return json.loads(self.recv(conn))
        out = self.run_server(script)
        self.assertEqual(out['client']['code'], 'REPLAY_REJECTED')
        self.assertEqual(out['client']['request_id'], r)
        self.assertIsNone(out['state'])
        self.assertEqual(self.broker.adapter.read_count, reads)          # adapter not reached

    def test_journal_full_is_refused_before_dispatch(self):
        small = ReceiptJournal(str(self.dir / 'small.db'), max_receipts=1)
        self.addCleanup(small.close)
        self.journal = small
        self.exchange()

        def script(conn):
            self.send(conn, request())
            return json.loads(self.recv(conn))
        out = self.run_server(script)
        self.assertEqual(out['client']['code'], 'JOURNAL_FULL')

    def test_request_without_id_is_answered_and_not_journaled(self):
        def script(conn):
            self.send(conn, b'{"broken":')
            return json.loads(self.recv(conn))
        out = self.run_server(script)
        self.assertEqual(out['client']['code'], 'MALFORMED_JSON')
        self.assertIsNone(out['client']['request_id'])
        self.assertIsNone(out['state'])
        self.assertEqual(self.journal.db.execute('SELECT count(*) FROM receipts').fetchone()[0], 0)

    def test_no_response_without_committed_receipt(self):
        r = rid()

        def script(conn):
            self.send(conn, request(r))
            try:
                return self.recv(conn)
            except ConnectionError:
                return None
        with mock.patch.object(self.journal, 'respond', side_effect=ReceiptError('CLOCK_ROLLBACK')):
            out = self.run_server(script)
        self.assertIsNone(out['client'])                                  # not one response byte
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'DISPATCH_FAILED'))

    def test_oversized_response_is_dispatch_failed(self):
        r = rid()
        with mock.patch.object(self.ipc, 'MAX_RESPONSE_BYTES', 10):
            out = self.run_server(lambda conn: (self.send(conn, request(r)), conn.recv(1))[1])
        self.assertEqual(out['client'], b'')
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'DISPATCH_FAILED'))

    def test_unusable_journal_leaves_receipt_open_for_recovery(self):
        r = rid()

        def script(conn):
            self.send(conn, request(r))
            return conn.recv(1)
        with mock.patch.object(self.journal, 'respond', side_effect=ReceiptError('INVALID_CLOCK')), \
                mock.patch.object(self.journal, 'unacknowledged', side_effect=ReceiptError('INVALID_CLOCK')):
            out = self.run_server(script)
        self.assertIsNone(out['state'])
        self.assertEqual(self.journal.state(self.subject, r), ('RESERVED', None))
        self.assertEqual(self.journal.recover(), 1)

    def test_send_failure_is_recorded(self):
        r = rid()
        real = self.ipc.HEADER

        class BrokenHeader:
            size = real.size
            unpack = staticmethod(real.unpack)

            @staticmethod
            def pack(n):
                raise BrokenPipeError('peer gone')

        with mock.patch.object(self.ipc, 'HEADER', BrokenHeader):
            self.run_server(lambda conn: (conn.sendall(real.pack(len(request(r))) + request(r)),
                                          conn.recv(1))[1])
        self.assertEqual(self.journal.state(self.subject, r), ('UNACKED', 'SEND_FAILED'))

    def test_unauthenticated_peer_is_dropped(self):
        with mock.patch.object(self.ipc, 'peer_identity', side_effect=Refusal('UNAUTHENTICATED_PEER')):
            out = self.run_server(lambda conn: conn.recv(1))
        self.assertIsNone(out['state'])
        self.assertEqual(out['client'], b'')

    def test_truncated_request_is_dropped(self):
        out = self.run_server(lambda conn: (conn.sendall(self.ipc.HEADER.pack(100) + b'{'),
                                            conn.shutdown(socket.SHUT_WR), conn.recv(1))[2])
        self.assertIsNone(out['state'])
        self.assertEqual(self.journal.db.execute('SELECT count(*) FROM receipts').fetchone()[0], 0)


@unittest.skipUnless(LINUX_IPC, 'Linux non-root kernel-credential lane unavailable')
class AckedLaneEndToEnd(unittest.TestCase):
    """Real server process (CLI), real client functions, server restart."""

    def setUp(self):
        self.dir = private_dir(self)
        self.runtime = self.dir / 'run'
        self.runtime.mkdir(); os.chmod(self.runtime, 0o700)
        self.store = self.dir / 'store'
        self.store.mkdir(); os.chmod(self.store, 0o700)
        self.db = str(self.store / 'receipts.db')
        self.sock = self.runtime / 'udx.sock'
        self.proc = None

    def start(self, max_connections=20):
        self.proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.linux_ipc', '--runtime-dir', str(self.runtime),
                                      '--max-connections', str(max_connections), '--receipt-journal', self.db],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(1000):
            if self.sock.exists():
                return
            if self.proc.poll() is not None:
                self.fail('server exited: ' + self.proc.communicate()[1].decode())
            time.sleep(0.01)
        self.fail('socket did not appear')

    def stop(self, sig=signal.SIGTERM):
        self.proc.send_signal(sig)
        try:
            self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill(); self.proc.communicate()
        if self.sock.exists():
            self.sock.unlink()

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.stop()

    def test_delivered_then_replay_refused_after_restart(self):
        from udx_ref.linux_ipc import request_on_socket_acked
        self.start()
        wire = request()
        result, receipt = request_on_socket_acked(self.sock, wire)
        self.assertEqual((result['code'], receipt), ('OK', 'DELIVERED'))
        self.stop()
        self.start()
        result, receipt = request_on_socket_acked(self.sock, wire)
        self.assertEqual(result['code'], 'REPLAY_REJECTED')
        self.assertEqual(receipt, 'NOT_CONFIRMED')                       # replay is never journaled twice
        self.stop()
        with ReceiptJournal(self.db) as j:
            self.assertEqual(j.state(f'uid:{os.geteuid()}', json.loads(wire)['request_id']), ('DELIVERED', None))

    def test_legacy_client_against_acked_server(self):
        from udx_ref.linux_ipc import request_on_socket
        # R6 B3: the running server owns the journal exclusively, so it is read
        # after a bounded run (one connection) has ended and closed it.
        self.start(max_connections=1)
        wire = request()
        self.assertEqual(request_on_socket(self.sock, wire)['code'], 'OK')    # response unchanged
        self.proc.communicate(timeout=10)
        self.assertEqual(self.proc.returncode, 0)
        with ReceiptJournal(self.db) as j:
            st = j.state(f'uid:{os.geteuid()}', json.loads(wire)['request_id'])
        self.assertEqual(st, ('UNACKED', 'ACK_MISSING'))

    def test_request_without_id_is_not_journaled(self):
        from udx_ref.linux_ipc import request_on_socket_acked
        self.start()
        result, receipt = request_on_socket_acked(self.sock, b'{"version":"udx/0.1"}')
        self.assertEqual((result['code'], receipt), ('INVALID_ENVELOPE', 'NOT_JOURNALED'))

    def test_rejected_response_is_acknowledged_then_raised(self):
        from udx_ref import linux_ipc
        self.start()
        wire = request()
        with mock.patch.object(linux_ipc, 'decode_response', side_effect=Refusal('INVALID_RESPONSE_DATA')):
            with self.assertRaises(Refusal) as cm:
                linux_ipc.request_on_socket_acked(self.sock, wire)
        self.assertEqual(cm.exception.code, 'INVALID_RESPONSE_DATA')
        self.stop()
        with ReceiptJournal(self.db) as j:
            self.assertEqual(j.state(f'uid:{os.geteuid()}', json.loads(wire)['request_id']),
                             ('CLIENT_REJECTED', None))

    def test_server_killed_before_ack_is_uncertain_after_restart(self):
        from udx_ref import linux_ipc
        self.start()
        wire = request()
        r = json.loads(wire)['request_id']
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.connect(str(self.sock))
            conn.sendall(linux_ipc.HEADER.pack(len(wire)) + wire)
            size = linux_ipc.HEADER.unpack(linux_ipc.recv_exact(conn, 4, deadline=time.monotonic() + 2))[0]
            linux_ipc.recv_exact(conn, size, deadline=time.monotonic() + 2)
            self.stop(signal.SIGKILL)                                    # crash before the ACK arrives
        with ReceiptJournal(self.db) as j:
            self.assertEqual(j.state(f'uid:{os.geteuid()}', r), ('RESPONDING', None))
        self.start()                                                     # serve_forever runs recover()
        result, receipt = linux_ipc.request_on_socket_acked(self.sock, wire)
        self.assertEqual(result['code'], 'REPLAY_REJECTED')
        self.stop()
        with ReceiptJournal(self.db) as j:
            self.assertEqual(j.state(f'uid:{os.geteuid()}', r), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))

    def test_client_refuses_bad_input_and_oversized_frames(self):
        from udx_ref import linux_ipc
        with self.assertRaises(ValueError):
            linux_ipc.request_on_socket_acked(self.sock, 'not bytes')
        with self.assertRaises(ValueError):
            linux_ipc.request_on_socket_acked(self.sock, b'x' * 5000)
        self.start()
        with mock.patch.object(linux_ipc, 'MAX_RESPONSE_BYTES', 10):
            with self.assertRaises(ValueError):
                linux_ipc.request_on_socket_acked(self.sock, request())


@unittest.skipUnless(LINUX_IPC, 'Linux lane unavailable')
class ClientReceiptChecks(unittest.TestCase):
    """The client half against a scripted server on a filesystem socket."""

    def serve(self, script):
        d = private_dir(self)
        path = d / 's.sock'
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(path)); listener.listen(1)

        def target():
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                script(conn)
        t = threading.Thread(target=target, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        return path

    def script_with_receipt(self, receipt_for):
        from udx_ref import linux_ipc

        def script(conn):
            size = linux_ipc.HEADER.unpack(linux_ipc.recv_exact(conn, 4, deadline=time.monotonic() + 2))[0]
            req = json.loads(linux_ipc.recv_exact(conn, size, deadline=time.monotonic() + 2))
            payload = linux_ipc._encode_response(make_broker().handle(json.dumps(req).encode(),
                                                 linux_ipc.PeerIdentity(f'uid:{os.geteuid()}', True)))
            conn.sendall(linux_ipc.HEADER.pack(len(payload)) + payload)
            asize = linux_ipc.HEADER.unpack(linux_ipc.recv_exact(conn, 4, deadline=time.monotonic() + 2))[0]
            linux_ipc.recv_exact(conn, asize, deadline=time.monotonic() + 2)
            body = receipt_for(req['request_id'])
            conn.sendall(linux_ipc.HEADER.pack(len(body)) + body)
        return script

    def test_receipt_for_another_request_is_refused(self):
        from udx_ref import linux_ipc
        path = self.serve(self.script_with_receipt(lambda r: dr.encode_receipt(rid(), 'DELIVERED')))
        with self.assertRaises(ReceiptError) as cm:
            linux_ipc.request_on_socket_acked(path, request())
        self.assertEqual(cm.exception.code, 'RECEIPT_REQUEST_MISMATCH')

    def test_oversized_receipt_is_refused(self):
        from udx_ref import linux_ipc
        path = self.serve(self.script_with_receipt(lambda r: b' ' * (dr.MAX_ACK_BYTES + 1)))
        with self.assertRaises(ReceiptError) as cm:
            linux_ipc.request_on_socket_acked(path, request())
        self.assertEqual(cm.exception.code, 'RECEIPT_TOO_LARGE')

    def test_huge_receipt_header_is_refused_without_reading(self):
        # Without the frame guard the client would try to read 2 GiB, hit EOF and
        # report NOT_CONFIRMED; with it the size alone is refused.
        from udx_ref import linux_ipc
        path = self.serve(self.script_with_header(2**31))
        with self.assertRaises(ReceiptError) as cm:
            linux_ipc.request_on_socket_acked(path, request())
        self.assertEqual(cm.exception.code, 'RECEIPT_TOO_LARGE')

    def script_with_header(self, size):
        from udx_ref import linux_ipc
        inner = self.script_with_receipt(lambda r: b'')

        def script(conn):
            real_sendall = conn.sendall
            calls = []

            def sendall(data):
                calls.append(data)
                if len(calls) == 2:                       # the receipt frame: header only, then EOF
                    return real_sendall(linux_ipc.HEADER.pack(size))
                return real_sendall(data)
            proxy = type('P', (), {'sendall': staticmethod(sendall), 'recv': conn.recv,
                                   'settimeout': conn.settimeout})()
            inner(proxy)
        return script

    def test_service_of_another_uid_is_refused(self):
        from udx_ref import linux_ipc
        path = self.serve(lambda conn: conn.recv(1))
        other = linux_ipc.PeerIdentity(f'uid:{os.geteuid() + 1}', True)
        with mock.patch.object(linux_ipc, 'peer_identity', return_value=other):
            with self.assertRaises(PermissionError):
                linux_ipc.request_on_socket_acked(path, request())

    def test_matching_receipt_is_delivered(self):
        from udx_ref import linux_ipc
        path = self.serve(self.script_with_receipt(lambda r: dr.encode_receipt(r, 'DELIVERED')))
        self.assertEqual(linux_ipc.request_on_socket_acked(path, request())[1], 'DELIVERED')


class LegacyLaneUnchanged(unittest.TestCase):
    def test_udx01_functions_keep_their_signature(self):
        import inspect
        from udx_ref import linux_ipc
        self.assertEqual(list(inspect.signature(linux_ipc.serve_connection).parameters), ['conn', 'broker'])
        self.assertEqual(list(inspect.signature(linux_ipc.request_on_socket).parameters), ['path', 'raw', 'timeout'])
        self.assertEqual(VERSION, 'udx/0.1')
        self.assertEqual(linux_ipc.ACK_DEADLINE_S, 1.0)
        self.assertEqual(dr.ACK_VERSION, 'udx-ack/1')


if __name__ == '__main__':
    unittest.main()
