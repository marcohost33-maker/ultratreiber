"""W12 Windows named-pipe peer-SID probe: REAL Win32 runtime tests (ctypes).

Active only on Windows. Single interactive account, not elevated: a second
account, a real remote host and UAC/high-integrity interactions are NOT covered
here (see docs/W12_WINDOWS_LANE.md). Remote rejection is exercised through the
local SMB redirector (\\\\localhost\\pipe\\...), not through a second machine.
"""
from __future__ import annotations

import ctypes
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest
import uuid

from udx_ref import windows_pipe as wp

REPO = pathlib.Path(__file__).resolve().parents[1]
IS_WINDOWS = sys.platform == 'win32'
FILE_ALL_ACCESS = 0x001F01FF
BS = chr(92)


def _name() -> str:
    return wp.PIPE_PREFIX + 'UDX_W12_' + uuid.uuid4().hex


def _remote(name: str) -> str:
    return BS + BS + 'localhost' + BS + 'pipe' + BS + name[len(wp.PIPE_PREFIX):]


class _Client(threading.Thread):
    def __init__(self, target, *args, **kwargs):
        super().__init__(daemon=True)
        self._call = (target, args, kwargs)
        self.result = None

    def run(self):
        target, args, kwargs = self._call
        self.result = target(*args, **kwargs)


def _serve_with_client(srv, deadline, *client_args, **client_kwargs):
    c = _Client(wp.client_ping, srv.name, *client_args, **client_kwargs)
    c.start()
    r = srv.serve(deadline)
    c.join(10)
    return r, c


class PortableParityAndValidation(unittest.TestCase):
    """Runs on every platform: SDDL/constant parity with the C++ candidate and
    negative input validation."""

    CPP = (REPO / 'windows' / 'udx_sid_probe.cpp').read_text()

    def test_sddl_prefix_identical_to_cpp(self):
        self.assertIn('std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;";', self.CPP)
        sid = 'S-1-5-21-1-2-3-1001'
        self.assertEqual(wp.build_sddl(sid), 'D:P(A;;GA;;;SY)(A;;GA;;;' + sid + ')')

    def test_constants_identical_to_cpp(self):
        self.assertIn('UDX_W4_SID_PROBE', self.CPP)
        self.assertTrue(wp.DEFAULT_PIPE_NAME.endswith('UDX_W4_SID_PROBE'))
        self.assertIn('"PEER_OK"', self.CPP)
        self.assertEqual(wp.RESPONSE, b'PEER_OK')
        self.assertIn('TerminateProcess(GetCurrentProcess(), 30)', self.CPP)
        self.assertEqual(wp.REVERT_FAILURE_EXIT, 30)
        self.assertIn('required > 65536', self.CPP)
        self.assertEqual(wp.TOKEN_INFO_MAX, 65536)
        self.assertIn('1, 4096, 4096, 0, &sa', self.CPP)

    def test_sddl_injection_rejected(self):
        for bad in ['S-1-5-18)(A;;GA;;;WD', '', 'WD', 's-1-5-18', 'S-1-5-18 ', None, 18,
                    'S-1-5', 'S-1-5-18' + '-1' * 20]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'INVALID_SID_TEXT'):
                wp.build_sddl(bad)

    def test_deadline_validation(self):
        for bad in [0, -1, 0.0, float('nan'), float('inf'), True, False, '1', None, 300.0001]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'INVALID_DEADLINE'):
                wp.validate_deadline(bad)
        self.assertEqual(wp.validate_deadline(300), 300.0)

    def test_pipe_name_validation(self):
        for bad in ['', 'UDX', wp.PIPE_PREFIX, wp.PIPE_PREFIX + 'a' + BS + 'b',
                    wp.PIPE_PREFIX + 'a' + chr(0), wp.PIPE_PREFIX + 'x' * 260, None,
                    _remote(wp.PIPE_PREFIX + 'x')]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'INVALID_PIPE_NAME'):
                wp.validate_pipe_name(bad)


@unittest.skipUnless(IS_WINDOWS, 'Windows Win32 named pipes required')
class WindowsPipeRuntime(unittest.TestCase):
    def setUp(self):
        self.api = wp.default_api()
        self.sid = wp.current_user_sid()

    # (a) same user -> PEER_OK, cross-process, PID from the kernel
    def test_same_user_cross_process_peer_ok(self):
        name = _name()
        with wp.OneShotPipeServer(name) as srv:
            proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.windows_pipe', 'client', '--name', name],
                                    cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            r = srv.serve(10.0)
            out, err = proc.communicate(timeout=20)
        self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(json.loads(out)['response'], 'PEER_OK')
        self.assertEqual(r.verdict, 'PEER_OK')
        self.assertEqual(r.client_pid, proc.pid)
        self.assertEqual(r.client_sid, self.sid)
        self.assertEqual(r.impersonation_level, wp.SecurityImpersonation)
        self.assertTrue(r.response_sent)
        self.assertTrue(r.response_drained)

    def test_cli_server_exit_codes_match_cpp(self):
        name = _name()
        proc = subprocess.Popen([sys.executable, '-m', 'udx_ref.windows_pipe', 'server', '--name', name,
                                 '--deadline', '10'], cwd=REPO, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertIn('listening', proc.stdout.readline().decode())
            c = wp.client_ping(name)
            out, err = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(c.response, b'PEER_OK')
        self.assertEqual(proc.returncode, 0, err)
        result = json.loads(out.decode().strip().splitlines()[-1])
        self.assertEqual(result['client_pid'], os.getpid())

    def test_delegation_level_accepted(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, level='delegation')
        self.assertTrue(r.ok)
        self.assertEqual(c.result.response, b'PEER_OK')

    # (b) second instance with the same name
    def test_second_own_instance_refused(self):
        name = _name()
        with wp.OneShotPipeServer(name):
            with self.assertRaises(wp.PipeSetupError) as cm:
                wp.OneShotPipeServer(name)
        self.assertIn(cm.exception.errno, (wp.ERROR_ACCESS_DENIED, wp.ERROR_PIPE_BUSY))

    def test_squatted_name_refused_by_first_pipe_instance(self):
        # Attacker-style pre-created pipe: default DACL, unlimited instances.
        name = _name()
        squat = self.api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX, 0, 255, 4096, 4096, 0, None)
        self.assertNotIn(squat, (None, wp.INVALID_HANDLE_VALUE))
        try:
            with self.assertRaises(wp.PipeSetupError) as cm:
                wp.OneShotPipeServer(name)
            self.assertEqual(cm.exception.errno, wp.ERROR_ACCESS_DENIED)
        finally:
            self.api.CloseHandle(squat)

    # (c) impersonation level below SecurityImpersonation
    def test_identification_level_denied(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, level='identification')
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'IMPERSONATION_LEVEL_TOO_LOW'))
        # The identification token DID reveal the same SID: only the level guard denies.
        self.assertEqual(r.client_sid, self.sid)
        self.assertEqual(r.impersonation_level, wp.SecurityIdentification)
        self.assertEqual(c.result.response, b'')

    def test_anonymous_level_denied(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, level='anonymous')
        self.assertEqual((r.verdict, r.reason, r.winerror),
                         ('DENIED', 'OPEN_THREAD_TOKEN_FAILED', wp.ERROR_CANT_OPEN_ANONYMOUS))
        self.assertEqual(c.result.response, b'')

    def test_sid_mismatch_denied(self):
        # DACL still admits the current user; the expected SID is narrowed to SYSTEM.
        with wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18') as srv:
            r, c = _serve_with_client(srv, 5.0)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'SID_MISMATCH'))
        self.assertEqual(r.client_sid, self.sid)
        self.assertEqual(r.impersonation_level, wp.SecurityImpersonation)
        self.assertEqual(c.result.response, b'')

    # (d) DACL read back from the live handle
    def test_dacl_exactly_system_and_current_user(self):
        with wp.OneShotPipeServer(_name()) as srv:
            info = wp.inspect_dacl(srv.handle)
        self.assertTrue(info.protected)
        self.assertEqual(len(info.aces), 2)
        self.assertEqual([a.sid for a in info.aces], ['S-1-5-18', self.sid])
        for a in info.aces:
            self.assertEqual((a.ace_type, a.ace_flags, a.mask), (wp.ACCESS_ALLOWED_ACE_TYPE, 0, FILE_ALL_ACCESS))
        self.assertEqual(info.sddl, 'D:P(A;;FA;;;SY)(A;;FA;;;' + self.sid + ')')

    # (e) absolute deadline
    def test_silent_client_hits_deadline_without_hang(self):
        with wp.OneShotPipeServer(_name()) as srv:
            box = {}
            server = threading.Thread(target=lambda: box.setdefault('r', srv.serve(0.5)), daemon=True)
            client = _Client(wp.client_ping, srv.name, send=False, hold_s=4.0)
            client.start()
            t0 = time.monotonic()
            server.start()
            server.join(2.0)
            self.assertFalse(server.is_alive(), 'server did not return within deadline + 1.5 s')
            elapsed = time.monotonic() - t0
        r = box['r']
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'READ_TIMEOUT'))
        self.assertGreaterEqual(r.elapsed_s, 0.5)
        self.assertLess(elapsed, 1.5)

    def test_no_client_connect_deadline(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r = srv.serve(0.3)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'CONNECT_TIMEOUT'))
        self.assertGreaterEqual(r.elapsed_s, 0.3)
        self.assertLess(r.elapsed_s, 1.0)

    def test_client_never_reads_response_is_bounded(self):
        name = _name()
        with wp.OneShotPipeServer(name) as srv:
            def raw():
                h = self.api.CreateFileW(name, wp.GENERIC_READ | wp.GENERIC_WRITE, 0, None, wp.OPEN_EXISTING,
                                         wp.SECURITY_SQOS_PRESENT | wp.SECURITY_IMPERSONATION, None)
                buf = ctypes.create_string_buffer(b'U', 1)
                n = ctypes.c_ulong(0)
                self.api.WriteFile(h, buf, 1, ctypes.byref(n), None)
                time.sleep(3.0)
                self.api.CloseHandle(h)
            c = threading.Thread(target=raw, daemon=True)
            c.start()
            r = srv.serve(1.0)
        self.assertTrue(r.ok)
        self.assertTrue(r.response_sent)
        self.assertFalse(r.response_drained)
        self.assertLess(r.elapsed_s, 1.5)

    # Remote rejection via the local SMB redirector (not a second machine)
    def test_smb_loopback_client_rejected(self):
        # Control: a raw pipe WITHOUT PIPE_REJECT_REMOTE_CLIENTS is reachable via SMB.
        control = _name()
        h = self.api.CreateNamedPipeW(control, wp.PIPE_ACCESS_DUPLEX, 0, 1, 4096, 4096, 0, None)
        self.assertNotIn(h, (None, wp.INVALID_HANDLE_VALUE))
        try:
            ctl = wp.client_ping(_remote(control), send=False, connect_timeout_s=8.0)
        finally:
            self.api.CloseHandle(h)
        if ctl.open_error is not None:
            self.skipTest(f'SMB loopback to \\\\localhost\\pipe unavailable (winerror {ctl.open_error})')
        with wp.OneShotPipeServer(_name()) as srv:
            client = _Client(wp.client_ping, _remote(srv.name), connect_timeout_s=8.0)
            client.start()
            r = srv.serve(2.0)
            client.join(10)
        self.assertEqual(client.result.open_error, wp.ERROR_ACCESS_DENIED)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'CONNECT_TIMEOUT'))

    # Low integrity client (thread token lowered to S-1-16-4096) with a medium control
    def _client_with_thread_token(self, name, integrity_sid):
        api = self.api
        proc, dup = wp.wintypes.HANDLE(), wp.wintypes.HANDLE()
        self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY | wp.TOKEN_DUPLICATE,
                                             ctypes.byref(proc)))
        sid = ctypes.c_void_p()
        try:
            self.assertTrue(api.DuplicateTokenEx(proc, wp.TOKEN_QUERY | wp.TOKEN_IMPERSONATE | wp.TOKEN_ADJUST_DEFAULT,
                                                 None, wp.SecurityImpersonation, wp.TokenImpersonation,
                                                 ctypes.byref(dup)))
            if integrity_sid:
                self.assertTrue(api.ConvertStringSidToSidW(integrity_sid, ctypes.byref(sid)))
                label = wp.SID_AND_ATTRIBUTES(sid, wp.SE_GROUP_INTEGRITY)
                self.assertTrue(api.SetTokenInformation(dup, wp.TokenIntegrityLevel, ctypes.byref(label),
                                                        ctypes.sizeof(label) + 12))
            out = {}

            def run():
                if not api.SetThreadToken(None, dup):
                    out['err'] = api.last_error()
                    return
                try:
                    out['c'] = wp.client_ping(name, connect_timeout_s=2.0)
                finally:
                    if not api.RevertToSelf():
                        os._exit(31)
            t = threading.Thread(target=run, daemon=True)
            return t, out
        finally:
            if sid.value:
                api.LocalFree(sid)
            api.CloseHandle(proc)
            self._dup = dup

    def test_low_integrity_client_cannot_open_pipe(self):
        for il, expect_ok in ((None, True), ('S-1-16-4096', False)):
            with self.subTest(integrity=il or 'medium-control'):
                with wp.OneShotPipeServer(_name()) as srv:
                    t, out = self._client_with_thread_token(srv.name, il)
                    try:
                        t.start()
                        r = srv.serve(1.5)
                        t.join(5)
                    finally:
                        self.api.CloseHandle(self._dup)
                self.assertNotIn('err', out)
                if expect_ok:
                    self.assertTrue(r.ok)
                    self.assertEqual(out['c'].response, b'PEER_OK')
                else:
                    self.assertEqual(out['c'].open_error, wp.ERROR_ACCESS_DENIED)
                    self.assertEqual(r.reason, 'CONNECT_TIMEOUT')

    def test_server_thread_already_impersonating_refuses(self):
        api = self.api
        proc, dup = wp.wintypes.HANDLE(), wp.wintypes.HANDLE()
        self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY | wp.TOKEN_DUPLICATE,
                                             ctypes.byref(proc)))
        self.assertTrue(api.DuplicateTokenEx(proc, wp.TOKEN_QUERY | wp.TOKEN_IMPERSONATE, None,
                                             wp.SecurityImpersonation, wp.TokenImpersonation, ctypes.byref(dup)))
        api.CloseHandle(proc)
        with wp.OneShotPipeServer(_name()) as srv:
            self.assertTrue(api.SetThreadToken(None, dup))
            try:
                r = srv.serve(1.0)
            finally:
                self.assertTrue(api.RevertToSelf())
                api.CloseHandle(dup)
        self.assertEqual(r.reason, 'THREAD_ALREADY_IMPERSONATING')
        self.assertFalse(wp.thread_is_impersonating(api))


@unittest.skipUnless(IS_WINDOWS, 'Windows Win32 named pipes required')
class WindowsPipeFaultInjection(unittest.TestCase):
    """(f) Win32 failures injected at the api seam; real pipe, real client."""

    def _api(self):
        return wp.WinApi()        # fresh instance; the module default is never mutated

    def _run(self, api, deadline=3.0):
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            r, c = _serve_with_client(srv, deadline)
        self.assertFalse(wp.thread_is_impersonating(wp.default_api()))
        self.assertEqual(c.result.response, b'')
        self.assertEqual(r.verdict, 'DENIED')
        self.assertFalse(r.response_sent)
        return r

    def test_impersonate_failure_injected(self):
        api = self._api()

        def fail(_h):
            ctypes.set_last_error(wp.ERROR_CANNOT_IMPERSONATE)
            return 0
        api.ImpersonateNamedPipeClient = fail
        r = self._run(api)
        self.assertEqual((r.reason, r.winerror), ('IMPERSONATE_FAILED', wp.ERROR_CANNOT_IMPERSONATE))

    def test_open_thread_token_failure_after_impersonation_still_reverts(self):
        api = self._api()
        real_open, real_revert = api.OpenThreadToken, api.RevertToSelf
        calls = {'open': 0, 'revert': 0}

        def open_tok(*a):
            calls['open'] += 1
            if calls['open'] == 2:            # 1st = precondition check, 2nd = under impersonation
                ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
                return 0
            return real_open(*a)

        def revert():
            calls['revert'] += 1
            return real_revert()
        api.OpenThreadToken, api.RevertToSelf = open_tok, revert
        r = self._run(api)
        self.assertEqual((r.reason, r.winerror), ('OPEN_THREAD_TOKEN_FAILED', wp.ERROR_ACCESS_DENIED))
        self.assertEqual(calls['revert'], 1)

    def test_token_query_failure_injected(self):
        api = self._api()
        real = api.GetTokenInformation

        def gti(tok, klass, buf, size, req):
            if klass == wp.TokenImpersonationLevel:
                ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
                return 0
            return real(tok, klass, buf, size, req)
        api.GetTokenInformation = gti
        r = self._run(api)
        self.assertEqual(r.reason, 'TOKEN_QUERY_FAILED')

    def test_client_pid_failure_injected(self):
        api = self._api()

        def fail(_h, _p):
            ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
            return 0
        api.GetNamedPipeClientProcessId = fail
        r = self._run(api)
        self.assertEqual(r.reason, 'CLIENT_PID_FAILED')

    def test_read_happens_before_impersonation(self):
        api = self._api()
        log = []
        for fn in ('ReadFile', 'ImpersonateNamedPipeClient', 'RevertToSelf', 'WriteFile'):
            real = getattr(api, fn)
            setattr(api, fn, (lambda real, fn: lambda *a: (log.append(fn), real(*a))[1])(real, fn))
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            r, c = _serve_with_client(srv, 5.0)
        self.assertTrue(r.ok)
        self.assertEqual(log[:4], ['ReadFile', 'ImpersonateNamedPipeClient', 'RevertToSelf', 'WriteFile'])

    def test_revert_failure_terminates_process(self):
        script = (
            'import sys, threading, ctypes\n'
            'from udx_ref import windows_pipe as wp\n'
            'name = sys.argv[1]\n'
            'api = wp.WinApi()\n'
            'def bad():\n'
            '    ctypes.set_last_error(5)\n'
            '    return 0\n'
            'api.RevertToSelf = bad\n'
            'srv = wp.OneShotPipeServer(name, api=api)\n'
            'threading.Thread(target=wp.client_ping, args=(name,), daemon=True).start()\n'
            'r = srv.serve(5.0)\n'
            'print("RETURNED", r.verdict, flush=True)\n'
        )
        p = subprocess.run([sys.executable, '-c', script, _name()], cwd=REPO, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=30)
        self.assertEqual(p.returncode, wp.REVERT_FAILURE_EXIT, p.stderr)
        self.assertNotIn(b'RETURNED', p.stdout)

    def test_close_during_serve_defers_release_to_serving_thread(self):
        # Regression: a concurrent close() freed the SID buffer / closed the pipe
        # while serve() still used them (observed STATUS_HEAP_CORRUPTION 0xc0000374).
        api = self._api()
        closes, frees = [], []
        real_close, real_free = api.CloseHandle, api.LocalFree

        def rec_close(h):
            closes.append((h, threading.get_ident()))
            return real_close(h)

        def rec_free(p):
            v = p.value if isinstance(p, ctypes.c_void_p) else ctypes.cast(p, ctypes.c_void_p).value
            frees.append(v)
            return real_free(p)
        api.CloseHandle, api.LocalFree = rec_close, rec_free
        srv = wp.OneShotPipeServer(_name(), api=api)
        pipe_handle = srv.handle
        _Client(wp.client_ping, srv.name, send=False, hold_s=1.5).start()
        box = {}
        t = threading.Thread(target=lambda: box.update(tid=threading.get_ident(), r=srv.serve(5.0)),
                             daemon=True)
        t.start()
        time.sleep(0.3)                       # serve() is now blocked in the 1-byte read
        srv.close()
        t.join(2.0)
        self.assertFalse(t.is_alive(), 'serve() did not return after concurrent close()')
        self.assertEqual(box['r'].verdict, 'DENIED')
        self.assertEqual([tid for h, tid in closes if h == pipe_handle], [box['tid']])
        released = [v for v in frees if v]
        self.assertEqual(len(released), len(set(released)), 'double LocalFree')
        srv.close()                           # idempotent afterwards

    def test_single_use_and_invalid_override(self):
        with wp.OneShotPipeServer(_name()) as srv:
            srv.serve(0.05)
            with self.assertRaisesRegex(RuntimeError, 'SERVER_SINGLE_USE'):
                srv.serve(0.05)
        with self.assertRaisesRegex(ValueError, 'INVALID_SID_TEXT'):
            wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18)(A;;GA;;;WD')
        with wp.OneShotPipeServer(_name()) as srv:
            with self.assertRaisesRegex(ValueError, 'INVALID_DEADLINE'):
                srv.serve(float('nan'))


if __name__ == '__main__':
    unittest.main()
