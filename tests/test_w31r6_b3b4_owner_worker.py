"""R6 B3 + B4 (PR #13): journal ownership of the supervisor, observed worker faults.

I3 (B3): while a supervisor owns the receipt journal (from before recover()
until after the last worker), no second journal instance can open it or run
recover() on it; a second owner fails closed with JOURNAL_OWNER_BUSY before it
changes a row. Witness of the defect (R2): live.reserve -> second.recover()
turned the live row UNCERTAIN -> live.respond refused NOT_RESERVED.

I4 (B4): an unexpected exception in a worker is not left unobserved in its
Future: it is logged with a fixed code and no payload, no further request is
admitted (fail-closed), and the semaphore slot and the socket are released.

Every assertion that carries an invariant fails by assertion (not by a crash)
on the base d5049ce where the defect is reachable there.
"""
import json
import logging
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
from udx_ref.core import VERSION
from udx_ref.delivery_receipts import ReceiptError, ReceiptJournal

POSIX = os.name == 'posix' and hasattr(os, 'getuid')
LINUX_IPC = sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED') and POSIX and os.geteuid() != 0
SUBJECT = 'uid:1000'
ROOT = str(Path(__file__).resolve().parents[1])


def rid():
    return str(uuid.uuid4())


def private_dir(test):
    tmp = tempfile.TemporaryDirectory(prefix='udx-r6b3-')
    test.addCleanup(tmp.cleanup)
    os.chmod(tmp.name, 0o700)
    return Path(tmp.name)


def private_sub(base, name):
    d = base / name
    d.mkdir()
    os.chmod(d, 0o700)
    return d


def code_of(fn, *args, **kw):
    with unittest.TestCase().assertRaises(ReceiptError) as cm:
        fn(*args, **kw)
    return cm.exception.code


def request(request_id=None):
    return json.dumps({'version': VERSION, 'request_id': request_id or rid(),
                       'capability': 'object.metadata.read', 'params': {'object_id': 'sample-1'}}).encode()


class _Proxy:
    """sqlite3 connection stand-in: fakes or fails chosen statements, may fail close()."""

    def __init__(self, conn, fake=None, fail=None, close_error=None):
        self.conn, self.fake, self.fail, self.close_error = conn, fake or {}, fail or {}, close_error

    def execute(self, sql, *a):
        if sql in self.fail:
            raise self.fail[sql]
        if sql in self.fake:
            return mock.Mock(fetchone=lambda: self.fake[sql])
        return self.conn.execute(sql, *a)

    @property
    def in_transaction(self):
        return self.conn.in_transaction

    def close(self):
        self.conn.close()
        if self.close_error is not None:
            raise self.close_error


def sqlite_error(errorcode):
    exc = sqlite3.OperationalError('injected')
    exc.sqlite_errorcode = errorcode
    return exc


@unittest.skipUnless(POSIX, 'receipt journal is POSIX only')
class JournalOwner(unittest.TestCase):
    def setUp(self):
        self.dir = private_dir(self)
        self.path = str(private_sub(self.dir, 'store') / 'receipts.db')

    def owner(self, path=None):
        j = ReceiptJournal(path or self.path, exclusive_owner=True)
        self.addCleanup(j.close)
        return j

    def test_owner_excludes_second_instances_in_this_process(self):
        owner = self.owner()
        r = rid()
        owner.reserve(SUBJECT, r)
        t0 = time.monotonic()
        self.assertEqual(code_of(ReceiptJournal, self.path, exclusive_owner=True), 'JOURNAL_OWNER_BUSY')
        self.assertLess(time.monotonic() - t0, 2.0)              # a second owner does not wait
        self.assertEqual(code_of(ReceiptJournal, self.path), 'JOURNAL_OWNER_BUSY')      # legacy mode, too
        self.assertEqual(owner.state(SUBJECT, r), ('RESERVED', None))                  # not recovered
        owner.respond(SUBJECT, r, 'a' * 64)                                            # owner keeps working
        owner.close()
        with ReceiptJournal(self.path) as after:                                       # released by close()
            self.assertEqual(after.recover(), 1)
            self.assertEqual(after.state(SUBJECT, r), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))

    def test_owner_excludes_other_processes_and_path_aliases(self):
        owner = self.owner()
        owner.reserve(SUBJECT, rid())
        alias = self.dir / 'alias'
        os.symlink(self.dir, alias)              # another path to the same inode: the lock is per inode
        child =("import sys\nfrom udx_ref.delivery_receipts import ReceiptJournal, ReceiptError\n"
                 "for p in sys.argv[1:]:\n"
                 "    try:\n        ReceiptJournal(p, exclusive_owner=True).recover()\n        print('OPENED')\n"
                 "    except ReceiptError as e:\n        print(e.code)\n")
        out = subprocess.run([sys.executable, '-c', child, self.path, str(alias / 'store' / 'receipts.db')],
                             capture_output=True, text=True, timeout=30, cwd=ROOT,
                             env=dict(os.environ, PYTHONPATH=ROOT))
        self.assertEqual(out.stdout.split(), ['JOURNAL_OWNER_BUSY', 'JOURNAL_OWNER_BUSY'], out.stderr)

    def test_lock_dies_with_the_owner_process(self):
        r = rid()
        child = ("import sys, time\nfrom udx_ref.delivery_receipts import ReceiptJournal\n"
                 "j = ReceiptJournal(sys.argv[1], exclusive_owner=True)\nj.reserve('uid:1000', sys.argv[2])\n"
                 "print('READY', flush=True)\ntime.sleep(60)\n")
        proc = subprocess.Popen([sys.executable, '-c', child, self.path, r], stdout=subprocess.PIPE,
                                cwd=ROOT, env=dict(os.environ, PYTHONPATH=ROOT))
        try:
            self.assertEqual(proc.stdout.readline().strip(), b'READY')
            self.assertEqual(code_of(ReceiptJournal, self.path, exclusive_owner=True), 'JOURNAL_OWNER_BUSY')
        finally:
            proc.send_signal(signal.SIGKILL)
            proc.communicate()
        owner = self.owner()                    # a crashed owner does not block the restart
        self.assertEqual(owner.recover(), 1)
        self.assertEqual(owner.state(SUBJECT, r), ('UNCERTAIN', 'RECOVERED_AFTER_CRASH'))

    def test_owner_mode_must_be_a_bool(self):
        for bad in (1, 0, None, 'yes', 1.0):
            self.assertEqual(code_of(ReceiptJournal, self.path, exclusive_owner=bad), 'BAD_OWNER_MODE', bad)
        ReceiptJournal(self.path, exclusive_owner=False).close()                  # both modes admitted
        ReceiptJournal(self.path, exclusive_owner=True).close()

    def test_exclusive_locking_mode_is_verified(self):
        real = sqlite3.connect
        fake = {'PRAGMA locking_mode=EXCLUSIVE': ('normal',)}
        with mock.patch.object(dr.sqlite3, 'connect', lambda *a, **k: _Proxy(real(*a, **k), fake=fake)):
            self.assertEqual(code_of(ReceiptJournal, self.path, exclusive_owner=True), 'EXCLUSIVE_OWNER_REQUIRED')
        with ReceiptJournal(self.path, exclusive_owner=True) as j:                  # real SQLite admits it
            self.assertEqual(j.db.execute('PRAGMA locking_mode').fetchone()[0], 'exclusive')
            self.assertEqual(j.db.execute('PRAGMA busy_timeout').fetchone()[0], 0)
        with ReceiptJournal(self.path) as j:                                          # legacy mode unchanged
            self.assertEqual(j.db.execute('PRAGMA locking_mode').fetchone()[0], 'normal')
            self.assertEqual(j.db.execute('PRAGMA busy_timeout').fetchone()[0], 3000)

    def test_only_busy_and_locked_become_owner_busy(self):
        real = sqlite3.connect
        # base codes and extended codes (low byte = primary code); IOERR stays the raw error
        cases = ((5, 'JOURNAL_OWNER_BUSY'), (517, 'JOURNAL_OWNER_BUSY'), (261, 'JOURNAL_OWNER_BUSY'),
                 (6, 'JOURNAL_OWNER_BUSY'), (262, 'JOURNAL_OWNER_BUSY'), (10, None), (266, None), (8, None))
        for errorcode, expected in cases:
            fail = {'PRAGMA journal_mode=WAL': sqlite_error(errorcode)}
            with mock.patch.object(dr.sqlite3, 'connect', lambda *a, fail=fail, **k: _Proxy(real(*a, **k), fail=fail)):
                with self.assertRaises(Exception) as cm:
                    ReceiptJournal(self.path)
            if expected is None:
                self.assertIsInstance(cm.exception, sqlite3.OperationalError, errorcode)
            else:
                self.assertIsInstance(cm.exception, ReceiptError, errorcode)
                self.assertEqual(cm.exception.code, expected, errorcode)
                self.assertIs(cm.exception.__cause__, fail['PRAGMA journal_mode=WAL'])

    def test_close_failure_keeps_the_opening_error(self):
        # I1 variant in __init__: a failing close() must not replace the primary error.
        real = sqlite3.connect
        fake = {'PRAGMA journal_mode=WAL': ('delete',)}
        with mock.patch.object(dr.sqlite3, 'connect',
                               lambda *a, **k: _Proxy(real(*a, **k), fake=fake,
                                                      close_error=sqlite3.ProgrammingError('close'))):
            with self.assertRaises(Exception) as cm:
                ReceiptJournal(self.path)
        self.assertIsInstance(cm.exception, ReceiptError)
        self.assertEqual(cm.exception.code, 'WAL_REQUIRED')
        self.assertIn('JOURNAL_CLOSE_FAILED: ProgrammingError', getattr(cm.exception, '__notes__', []))


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []
        self.seen = threading.Event()

    def emit(self, record):
        self.records.append(record)
        self.seen.set()


@unittest.skipUnless(LINUX_IPC, 'Linux non-root SO_PEERCRED lane unavailable')
class SupervisorInProcess(unittest.TestCase):
    """serve_forever runs in a thread of this process; real AF_UNIX sockets."""

    def setUp(self):
        from udx_ref import linux_ipc
        self.ipc = linux_ipc
        self.dir = private_dir(self)
        self.runtime = private_sub(self.dir, 'run')
        self.db = str(private_sub(self.dir, 'store') / 'receipts.db')
        self.sock = self.runtime / 'udx.sock'
        self.log = _Capture()
        logger = logging.getLogger('udx_ref.linux_ipc')
        logger.addHandler(self.log)
        self.addCleanup(logger.removeHandler, self.log)

    def serve(self, max_connections):
        out = {}

        def target():
            try:
                self.ipc.serve_forever(str(self.runtime), max_connections=max_connections, receipt_journal=self.db)
                out['result'] = 'returned'
            except BaseException as exc:        # recorded for the assertions
                out['result'] = exc
        t = threading.Thread(target=target, daemon=True)
        t.start()
        self.addCleanup(self.drain, t)
        deadline = time.monotonic() + 10
        while not self.sock.exists():
            self.assertTrue(t.is_alive() and time.monotonic() < deadline, out)
            time.sleep(0.01)
        return t, out

    def drain(self, t):
        """Only after a failed assertion: unblock an accept() that still waits."""
        for _ in range(60):
            if not t.is_alive():
                return
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                    c.connect(str(self.sock))
            except OSError:
                pass
            t.join(0.2)

    def connect(self, wire=None):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(c.close)
        c.settimeout(5)
        c.connect(str(self.sock))
        wire = wire or request()
        c.sendall(self.ipc.HEADER.pack(len(wire)) + wire)
        return c

    @staticmethod
    def reply(c):
        """First reply bytes, b'' when the server closed the connection without a reply."""
        try:
            return c.recv(4)
        except ConnectionResetError:
            return b''

    def faulty_lane(self, faults=1):
        real = self.ipc.serve_connection_acked
        calls = []

        def lane(conn, broker, journal):
            calls.append(1)
            if len(calls) <= faults:
                raise ValueError('SECRET-REQUEST-DATA')
            return real(conn, broker, journal)
        return lane, calls

    def assert_fault_reported(self, out):
        self.assertIsInstance(out['result'], RuntimeError)
        self.assertEqual(str(out['result']), 'UDX_WORKER_FAULT')
        self.assertEqual([r.getMessage() for r in self.log.records], ['UDX_WORKER_FAULT: admission suspended'])
        self.assertTrue(all(r.levelno == logging.ERROR and r.exc_info is None for r in self.log.records))
        self.assertFalse(self.sock.exists())
        ReceiptJournal(self.db, exclusive_owner=True).close()             # journal released

    def test_worker_fault_is_logged_and_ends_admission(self):
        lane, calls = self.faulty_lane()
        slots = []

        class Slots(threading.BoundedSemaphore):
            def __init__(self, value):
                super().__init__(value)
                slots.append(self)
        with mock.patch.object(self.ipc, 'serve_connection_acked', lane), \
                mock.patch.object(self.ipc, 'BoundedSemaphore', Slots):
            t, out = self.serve(10)
            self.assertEqual(self.reply(self.connect()), b'')          # faulting worker: socket released
            self.assertTrue(self.log.seen.wait(5), 'worker fault was not reported')
            self.assertEqual(self.reply(self.connect()), b'')          # no further admission
            t.join(10)
            self.assertFalse(t.is_alive(), 'accept loop kept admitting after the fault')
        self.assertEqual(len(calls), 1)
        self.assert_fault_reported(out)
        self.assertEqual(slots[0]._value, self.ipc.MAX_WORKERS)        # slot released
        self.assertNotIn('SECRET', ' '.join(r.getMessage() for r in self.log.records))

    def test_fault_in_the_last_admitted_connection_is_reported(self):
        lane, calls = self.faulty_lane()
        with mock.patch.object(self.ipc, 'serve_connection_acked', lane):
            t, out = self.serve(1)
            self.assertEqual(self.reply(self.connect()), b'')
            t.join(10)
        self.assertFalse(t.is_alive())
        self.assert_fault_reported(out)

    def test_task_admitted_before_the_fault_is_not_served(self):
        lane, calls = self.faulty_lane()
        gates, submitted = [], threading.Semaphore(0)

        class GatedPool(self.ipc.ThreadPoolExecutor):
            def submit(self, fn, *a, **k):
                gate = threading.Event()
                gates.append(gate)

                def run():
                    gate.wait(10)
                    return fn(*a, **k)
                future = super().submit(run)
                submitted.release()
                return future
        with mock.patch.object(self.ipc, 'serve_connection_acked', lane), \
                mock.patch.object(self.ipc, 'ThreadPoolExecutor', GatedPool):
            t, out = self.serve(10)
            first, second = self.connect(), self.connect()
            self.assertTrue(submitted.acquire(timeout=5) and submitted.acquire(timeout=5))
            gates[0].set()                                             # the first worker faults ...
            self.assertTrue(self.log.seen.wait(5), 'worker fault was not reported')
            gates[1].set()                                             # ... then the admitted second starts
            self.assertEqual(self.reply(second), b'')
            self.assertEqual(len(calls), 1, 'a request was served after the worker fault')
            self.assertEqual(self.reply(self.connect()), b'')
            t.join(10)
        self.assertFalse(t.is_alive())
        self.assert_fault_reported(out)

    def test_without_fault_every_request_is_served_and_the_run_returns(self):
        t, out = self.serve(2)
        for _ in range(2):
            self.assertEqual(self.ipc.request_on_socket_acked(self.sock, request())[1], 'DELIVERED')
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertEqual(out['result'], 'returned')
        self.assertEqual(self.log.records, [])
        ReceiptJournal(self.db, exclusive_owner=True).close()

    def test_journal_is_released_when_startup_fails_after_opening_it(self):
        for name, patcher in (
                ('recover', lambda: mock.patch.object(self.ipc.ReceiptJournal, 'recover',
                                                      side_effect=ReceiptError('INVALID_CLOCK'))),
                ('bind', lambda: mock.patch.object(socket.socket, 'bind', side_effect=OSError('bind refused')))):
            with self.subTest(name), patcher():
                with self.assertRaises((ReceiptError, OSError)) as cm:
                    self.ipc.serve_forever(str(self.runtime), max_connections=1, receipt_journal=self.db)
                # the traceback (cm) keeps the frame alive: only an explicit close() releases the lock
                self.assertIsNotNone(cm.exception.__traceback__)
                ReceiptJournal(self.db, exclusive_owner=True).close()
                self.assertFalse(self.sock.exists())


@unittest.skipUnless(LINUX_IPC, 'Linux non-root kernel-credential lane unavailable')
class SupervisorProcesses(unittest.TestCase):
    """Real server processes (CLI) sharing one journal."""

    def setUp(self):
        self.dir = private_dir(self)
        self.db = str(private_sub(self.dir, 'store') / 'receipts.db')
        self.procs = []

    def start(self, name, max_connections=20, wait=True):
        runtime = private_sub(self.dir, name)
        proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.linux_ipc', '--runtime-dir', str(runtime),
                                 '--max-connections', str(max_connections), '--receipt-journal', self.db],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
                                env=dict(os.environ, PYTHONPATH=ROOT))
        self.procs.append(proc)
        self.addCleanup(self.stop, proc)
        sock = runtime / 'udx.sock'
        if wait:
            for _ in range(1000):
                if sock.exists():
                    break
                if proc.poll() is not None:
                    self.fail('server exited: ' + proc.communicate()[1].decode())
                time.sleep(0.01)
            else:
                self.fail('socket did not appear')
        return proc, sock

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()

    def test_second_journal_cannot_recover_a_live_receipt(self):
        from udx_ref import linux_ipc
        proc, sock = self.start('a', max_connections=1)
        wire = request()
        r = json.loads(wire)['request_id']
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(10)
            conn.connect(str(sock))
            conn.sendall(linux_ipc.HEADER.pack(len(wire)) + wire)
            size = linux_ipc.HEADER.unpack(linux_ipc.recv_exact(conn, 4, deadline=time.monotonic() + 5))[0]
            linux_ipc.recv_exact(conn, size, deadline=time.monotonic() + 5)
            # the receipt is RESPONDING now; a second journal must not reach it
            with self.assertRaises(ReceiptError) as cm:
                ReceiptJournal(self.db).recover()
            self.assertEqual(cm.exception.code, 'JOURNAL_OWNER_BUSY')
        proc.wait(timeout=10)                                     # bounded run ends, journal closed
        with ReceiptJournal(self.db) as j:
            self.assertEqual(j.state(f'uid:{os.geteuid()}', r), ('UNACKED', 'ACK_TIMEOUT'))

    def test_second_supervisor_fails_closed_and_the_first_keeps_serving(self):
        from udx_ref.linux_ipc import request_on_socket_acked
        _, sock_a = self.start('a')
        proc_b, sock_b = self.start('b', wait=False)
        try:
            _, err = proc_b.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            self.fail('second supervisor kept running on an owned journal')
        self.assertNotEqual(proc_b.returncode, 0)
        self.assertIn(b'JOURNAL_OWNER_BUSY', err)
        self.assertFalse(sock_b.exists())                         # it never listened
        self.assertEqual(request_on_socket_acked(sock_a, request())[1], 'DELIVERED')


if __name__ == '__main__':
    unittest.main()
