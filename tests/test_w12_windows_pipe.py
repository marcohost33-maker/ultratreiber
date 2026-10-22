"""W12 Windows named-pipe peer-SID probe: REAL Win32 runtime tests (ctypes).

Active only on Windows. Single interactive account, not elevated: a second
account, a real remote host and UAC/high-integrity interactions are NOT covered
here (see docs/W12_WINDOWS_LANE.md). Remote rejection is exercised through the
local SMB redirector (\\\\localhost\\pipe\\...), not through a second machine.
"""
from __future__ import annotations

import ctypes
import gc
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest
import uuid
from unittest import mock

from udx_ref import windows_pipe as wp

REPO = pathlib.Path(__file__).resolve().parents[1]
IS_WINDOWS = sys.platform == 'win32'
FILE_ALL_ACCESS = 0x001F01FF
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
BS = chr(92)


def _name() -> str:
    return wp.PIPE_PREFIX + 'UDX_W12_' + uuid.uuid4().hex


def _canonical_sddl(sddl: str) -> str:
    """Round-trip an SDDL string through Windows (string -> descriptor -> string).

    The readback abbreviates well-known SIDs to their SDDL aliases: on a hosted
    CI runner the current user is the built-in Administrator (RID 500) and comes
    back as ``LA``. Comparing against the canonical form of the expected string
    keeps the exact-text check without hand-maintaining the alias table.
    """
    api = wp.default_api()
    sd = ctypes.c_void_p()
    if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, wp.SDDL_REVISION_1, ctypes.byref(sd), None):
        raise OSError(api.last_error(), 'ConvertStringSecurityDescriptorToSecurityDescriptorW failed')
    try:
        text = wp.wintypes.LPWSTR()
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, wp.SDDL_REVISION_1, wp.DACL_SECURITY_INFORMATION | wp.LABEL_SECURITY_INFORMATION,
                ctypes.byref(text), None):
            raise OSError(api.last_error(), 'ConvertSecurityDescriptorToStringSecurityDescriptorW failed')
        try:
            return text.value
        finally:
            api.LocalFree(text)
    finally:
        api.LocalFree(sd)


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
        # W13: Medium NW|NR label in both the C++ source and the port.
        # W17 (issue #2): explicit owner O:<user SID> in both.
        # W18: ACE mask 0x12008b (FILE_GENERIC_READ|FILE_WRITE_DATA) instead of GRGW.
        self.assertIn('std::wstring sddl = L"O:";\n    sddl += sid_text;\n', self.CPP)
        self.assertIn('    sddl += L"D:P(A;;0x12008b;;;SY)(A;;0x12008b;;;";\n    sddl += sid_text;\n', self.CPP)
        self.assertIn('sddl += L")(A;;0x12008b;;;OW)S:(ML;;NWNR;;;ME)";', self.CPP)
        sid = 'S-1-5-21-1-2-3-1001'
        self.assertEqual(wp.build_sddl(sid),
                         'O:' + sid + 'D:P(A;;0x12008b;;;SY)(A;;0x12008b;;;' + sid
                         + ')(A;;0x12008b;;;OW)S:(ML;;NWNR;;;ME)')

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

    def test_deadline_overflow_is_value_error(self):
        # Aegis P3-g: float(10**400) raised OverflowError past the typed check.
        for bad in (10 ** 400, -10 ** 400):
            with self.subTest(bad='±10**400'):
                try:
                    wp.validate_deadline(bad)
                except ValueError as exc:
                    self.assertEqual(str(exc), 'INVALID_DEADLINE')
                except Exception as exc:                       # noqa: BLE001
                    self.fail(f'untyped {type(exc).__name__}')
                else:
                    self.fail('accepted')
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
        self.assertEqual(r.impersonation_level, wp.SecurityIdentification)   # W13: never more
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

    def test_legacy_impersonation_level_client_still_accepted_by_server(self):
        # The server requires >= Identification; a raw W4-style client that grants
        # Impersonation is still identified correctly (client_ping never does this).
        name = _name()
        with wp.OneShotPipeServer(name) as srv:
            box = {}

            def raw():
                h = self.api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING,
                                         wp.SECURITY_SQOS_PRESENT | wp.SECURITY_IMPERSONATION, None)
                buf = ctypes.create_string_buffer(b'U', 8)
                n = ctypes.c_ulong(0)
                self.api.WriteFile(h, buf, 1, ctypes.byref(n), None)
                self.api.ReadFile(h, buf, 7, ctypes.byref(n), None)
                box['resp'] = buf.raw[:n.value]
                self.api.CloseHandle(h)
            t = threading.Thread(target=raw, daemon=True)
            t.start()
            r = srv.serve(5.0)
            t.join(5)
        self.assertTrue(r.ok)
        self.assertEqual(r.impersonation_level, wp.SecurityImpersonation)
        self.assertEqual(box['resp'], b'PEER_OK')

    def test_client_cannot_request_impersonation(self):
        for bad in ('impersonation', 'delegation', 'IDENTIFICATION', ''):
            with self.subTest(level=bad), self.assertRaisesRegex(ValueError, 'INVALID_LEVEL'):
                wp.client_sqos_flags(bad)
        flags = wp.client_sqos_flags()
        self.assertEqual(flags, wp.SECURITY_SQOS_PRESENT | wp.SECURITY_IDENTIFICATION | wp.SECURITY_EFFECTIVE_ONLY)
        self.assertFalse(flags & wp.SECURITY_CONTEXT_TRACKING)       # static tracking

    # (i) Aegis p1 regression: a squatting pipe owner learns at most Identification
    def test_squatter_sees_only_identification(self):
        name = _name()
        # W17: a same-user squatter can pick the user as owner, which is the
        # case the client's owner check cannot catch. Set it explicitly; the
        # default owner of an elevated administrator is BUILTIN\Administrators
        # (the client then refuses before writing, and this case never runs).
        sd = ctypes.c_void_p()
        self.assertTrue(self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            'O:' + self.sid + 'D:(A;;GA;;;' + self.sid + ')', wp.SDDL_REVISION_1, ctypes.byref(sd), None))
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            squat = self.api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX, 0, 255, 4096, 4096, 0,
                                              ctypes.byref(sa))
        finally:
            self.api.LocalFree(sd)
        self.assertNotIn(squat, (None, wp.INVALID_HANDLE_VALUE))
        try:
            client = _Client(wp.client_ping, name, response_timeout_s=1.0)
            client.start()
            self.api.ConnectNamedPipe(squat, None)
            buf = ctypes.create_string_buffer(1)
            n = ctypes.c_ulong(0)
            self.assertTrue(self.api.ReadFile(squat, buf, 1, ctypes.byref(n), None))
            self.assertTrue(self.api.ImpersonateNamedPipeClient(squat))
            try:
                tok = wp.wintypes.HANDLE()
                self.assertTrue(self.api.OpenThreadToken(self.api.GetCurrentThread(), wp.TOKEN_QUERY, True,
                                                         ctypes.byref(tok)))
                lvl, _ = wp._token_info(self.api, tok, wp.TokenImpersonationLevel)
                self.api.CloseHandle(tok)
            finally:
                self.assertTrue(self.api.RevertToSelf())
            self.assertLessEqual(ctypes.c_int.from_buffer(lvl, 0).value, wp.SecurityIdentification)
            client.join(4)
            self.assertFalse(client.is_alive(), 'client blocked on a silent squatter')
            self.assertEqual(client.result.reason, 'READ_TIMEOUT')
        finally:
            self.api.CloseHandle(squat)

    # (ii) client refuses a pipe whose owner is not the expected server SID
    def test_client_refuses_foreign_owner_without_writing(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 1.0, expected_server_sid='S-1-5-18')
        self.assertEqual((c.result.reason, c.result.sent), ('PIPE_OWNER_MISMATCH', False))
        self.assertEqual(c.result.pipe_owner, self.sid)
        self.assertEqual(r.verdict, 'DENIED')
        # Not a single byte arrived. Depending on whether the client closed before
        # or after the server's ConnectNamedPipe: CONNECT_FAILED (232) or a read error.
        self.assertIn(r.reason, ('CONNECT_FAILED', 'READ_FAILED', 'READ_TIMEOUT'))
        self.assertIsNone(r.client_pid)                              # set only after the 1-byte read

    def test_client_refuses_injected_foreign_owner(self):
        api = wp.WinApi()
        real = api.GetSecurityInfo
        foreign = ctypes.c_void_p()
        self.assertTrue(api.ConvertStringSidToSidW('S-1-5-19', ctypes.byref(foreign)))

        def gsi(*a):
            rc = real(*a)
            if rc == 0 and a[2] == wp.OWNER_SECURITY_INFORMATION:
                a[3]._obj.value = foreign.value          # owner pointer -> LocalService
            return rc
        api.GetSecurityInfo = gsi
        try:
            with wp.OneShotPipeServer(_name()) as srv:
                r, c = _serve_with_client(srv, 1.0, api=api)
        finally:
            api.LocalFree(foreign)
        self.assertEqual((c.result.reason, c.result.sent, c.result.pipe_owner),
                         ('PIPE_OWNER_MISMATCH', False, 'S-1-5-19'))
        self.assertFalse(r.ok)

    def test_server_pid_is_logged_not_decisive(self):
        api = wp.WinApi()

        def fail(_h, _p):
            ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
            return 0
        api.GetNamedPipeServerProcessId = fail
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, api=api)
        self.assertTrue(r.ok)
        self.assertEqual((c.result.reason, c.result.server_pid), ('OK', None))

    def test_client_owner_query_failure_is_typed(self):
        api = wp.WinApi()
        api.GetSecurityInfo = lambda *a: wp.ERROR_ACCESS_DENIED
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 1.0, api=api)
        self.assertEqual((c.result.reason, c.result.winerror, c.result.sent),
                         ('PIPE_OWNER_FAILED', wp.ERROR_ACCESS_DENIED, False))
        self.assertFalse(r.ok)

    def test_reject_remote_flag_reaches_create_named_pipe(self):
        # Tokio CVE-2023-22466 class: a later setter silently dropping the flag.
        api = wp.WinApi()
        seen = []
        real = api.CreateNamedPipeW

        def rec(*a):
            seen.append(a)
            return real(*a)
        api.CreateNamedPipeW = rec
        with wp.OneShotPipeServer(_name(), api=api):
            pass
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][2] & wp.PIPE_REJECT_REMOTE_CLIENTS)
        self.assertTrue(seen[0][1] & wp.FILE_FLAG_FIRST_PIPE_INSTANCE)
        self.assertEqual(seen[0][3], 1)                              # nMaxInstances

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

    # (iii) Identification client -> PEER_OK (W13 protocol); Anonymous below
    def test_identification_level_peer_ok(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, level='identification')
        self.assertEqual((r.verdict, r.reason), ('PEER_OK', 'OK'))
        self.assertEqual(r.client_sid, self.sid)
        self.assertEqual(r.impersonation_level, wp.SecurityIdentification)
        self.assertEqual((c.result.response, c.result.reason), (b'PEER_OK', 'OK'))

    def test_anonymous_level_denied(self):
        with wp.OneShotPipeServer(_name()) as srv:
            r, c = _serve_with_client(srv, 5.0, level='anonymous')
        self.assertEqual((r.verdict, r.reason, r.winerror),
                         ('DENIED', 'OPEN_THREAD_TOKEN_FAILED', wp.ERROR_CANT_OPEN_ANONYMOUS))
        self.assertEqual(c.result.response, b'')

    def test_sid_mismatch_denied(self):
        # DACL still admits the current user; the expected SID is narrowed to SYSTEM.
        with wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18', allow_foreign_expected_sid=True) as srv:
            r, c = _serve_with_client(srv, 5.0)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'SID_MISMATCH'))
        self.assertEqual(r.client_sid, self.sid)
        self.assertEqual(r.impersonation_level, wp.SecurityIdentification)
        self.assertEqual(c.result.response, b'')

    # (d) DACL read back from the live handle
    def test_dacl_exactly_system_and_current_user(self):
        with wp.OneShotPipeServer(_name()) as srv:
            info = wp.inspect_dacl(srv.handle)
        self.assertTrue(info.protected)
        self.assertEqual(len(info.aces), 3)
        # W17: third ACE = OWNER RIGHTS (S-1-3-4), replaces implicit owner rights.
        self.assertEqual([a.sid for a in info.aces], ['S-1-5-18', self.sid, 'S-1-3-4'])
        # W14 (E1010M-05): no ACE carries WRITE_DAC/WRITE_OWNER. W18: every ACE
        # is FILE_GENERIC_READ|FILE_WRITE_DATA, without the instance bit 0x4.
        self.assertEqual([(a.ace_type, a.ace_flags, a.mask) for a in info.aces],
                         [(wp.ACCESS_ALLOWED_ACE_TYPE, 0, wp.PIPE_ACE_MASK)] * 3)
        for ace in info.aces:
            self.assertFalse(ace.mask & (WRITE_DAC | WRITE_OWNER | wp.FILE_CREATE_PIPE_INSTANCE))
        expected = ('D:P(A;;0x12008b;;;SY)(A;;0x12008b;;;' + self.sid
                    + ')(A;;0x12008b;;;OW)S:AI(ML;;NWNR;;;ME)')
        self.assertEqual(info.sddl, _canonical_sddl(expected))

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
                h = self.api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING,
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

    def test_low_integrity_read_only_open_denied(self):
        # Aegis F-LOWIL: with only the implicit label (no-write-up), a Low-IL
        # process could open GENERIC_READ and occupy the single instance. The
        # explicit NW|NR label closes that; a Medium read-only open still works.
        api = self.api
        results = {}
        for label, il in (('medium', None), ('low', 'S-1-16-4096')):
            with wp.OneShotPipeServer(_name()) as srv:
                proc, dup = wp.wintypes.HANDLE(), wp.wintypes.HANDLE()
                self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY | wp.TOKEN_DUPLICATE,
                                                     ctypes.byref(proc)))
                self.assertTrue(api.DuplicateTokenEx(proc, wp.TOKEN_QUERY | wp.TOKEN_IMPERSONATE |
                                                     wp.TOKEN_ADJUST_DEFAULT, None, wp.SecurityImpersonation,
                                                     wp.TokenImpersonation, ctypes.byref(dup)))
                api.CloseHandle(proc)
                if il:
                    sid = ctypes.c_void_p()
                    self.assertTrue(api.ConvertStringSidToSidW(il, ctypes.byref(sid)))
                    lab = wp.SID_AND_ATTRIBUTES(sid, wp.SE_GROUP_INTEGRITY)
                    self.assertTrue(api.SetTokenInformation(dup, wp.TokenIntegrityLevel, ctypes.byref(lab),
                                                            ctypes.sizeof(lab) + 12))
                    api.LocalFree(sid)

                def run():
                    self.assertTrue(api.SetThreadToken(None, dup))
                    try:
                        h = api.CreateFileW(srv.name, wp.GENERIC_READ, 0, None, wp.OPEN_EXISTING, 0, None)
                        ok = h not in (None, wp.INVALID_HANDLE_VALUE)
                        results[label] = None if ok else api.last_error()
                        if ok:
                            api.CloseHandle(h)
                    finally:
                        if not api.RevertToSelf():
                            os._exit(31)
                t = threading.Thread(target=run, daemon=True)
                t.start()
                t.join(5)
                api.CloseHandle(dup)
        self.assertEqual(results, {'medium': None, 'low': wp.ERROR_ACCESS_DENIED})

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

    def test_async_exception_after_impersonation_still_reverts(self):
        # Aegis p3-1: an exception landing right after ImpersonateNamedPipeClient
        # returned (before any try) left the thread running as the client.
        api = self._api()
        real_imp = api.ImpersonateNamedPipeClient

        def imp_then_interrupt(h):
            if real_imp(h):
                raise KeyboardInterrupt('simulated async exception at call boundary')
            return 0
        api.ImpersonateNamedPipeClient = imp_then_interrupt
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            c = _Client(wp.client_ping, srv.name, response_timeout_s=2.0)
            c.start()
            with self.assertRaises(KeyboardInterrupt):
                srv.serve(3.0)
            still = wp.thread_is_impersonating(wp.default_api())
            if still:
                wp.default_api().RevertToSelf()          # keep the test runner sane
            c.join(5)
        self.assertFalse(still, 'server thread kept the client identity')
        self.assertNotEqual(c.result.response, b'PEER_OK')

    def test_exception_during_pending_io_cancels_before_release(self):
        # Aegis P2-b: a non-timeout exit while an I/O is pending must cancel it
        # (and wait/park) instead of dropping OVERLAPPED/buffer under the kernel.
        api = self._api()
        real_wait, real_cancel = api.WaitForSingleObject, api.CancelIoEx
        cancels, armed = [], {'on': True}

        def wait(ev, ms):
            if armed['on'] and ms > 0:
                armed['on'] = False
                raise KeyboardInterrupt('simulated async exception while I/O pending')
            return real_wait(ev, ms)

        def cancel(h, ov):
            cancels.append(ov is not None)
            return real_cancel(h, ov)
        api.WaitForSingleObject, api.CancelIoEx = wait, cancel
        parked_before = len(wp._PARKED)
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            _Client(wp.client_ping, srv.name, send=False, hold_s=1.0).start()
            with self.assertRaises(KeyboardInterrupt):
                srv.serve(3.0)
        self.assertIn(True, cancels, 'pending I/O was not cancelled by its owner')
        self.assertEqual(len(wp._PARKED), parked_before)        # cancel confirmed, nothing parked
        self.assertIsNone(srv.handle)

    def test_close_releases_handle_even_if_disconnect_raises(self):
        # Aegis P2-b: _handle was set to None BEFORE Disconnect/CloseHandle; an
        # exception in between leaked the handle (and kept the pipe name).
        api = self._api()
        closes = []
        real_close = api.CloseHandle

        def rec(h):
            closes.append(h.value if isinstance(h, ctypes.c_void_p) else h)
            return real_close(h)

        def boom(_h):
            raise RuntimeError('injected')
        api.CloseHandle = rec
        srv = wp.OneShotPipeServer(_name(), api=api)
        pipe = srv.handle
        api.DisconnectNamedPipe = boom
        with self.assertRaises(RuntimeError):
            srv.close()
        self.assertIn(pipe, closes)
        self.assertIsNone(srv.handle)
        wp.OneShotPipeServer(srv.name).close()                # name is free again

    def test_close_before_write_gives_no_peer_ok(self):
        # Aegis p3-2: close() landing after the abort check but before the write
        # I/O started (CancelIoEx had nothing to cancel) still produced PEER_OK.
        api = self._api()
        real_ev = api.CreateEventW
        calls = {'n': 0}
        holder = {}

        def ev(*a):
            calls['n'] += 1
            if calls['n'] == 3:                   # 1 connect, 2 ping read, 3 response write
                holder['srv'].close()
            return real_ev(*a)
        api.CreateEventW = ev
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            holder['srv'] = srv
            r, c = _serve_with_client(srv, 3.0, response_timeout_s=2.0)
        self.assertEqual(calls['n'] >= 3, True)
        self.assertEqual(r.verdict, 'DENIED')
        self.assertFalse(r.response_sent)
        self.assertNotEqual(c.result.response, b'PEER_OK')

    # W13 (Quella F2): token facts checked by the server
    def _patch_token_info(self, api, klass, value):
        real = api.GetTokenInformation

        def gti(tok, k, buf, size, req):
            rv = real(tok, k, buf, size, req)
            if rv and k == klass and buf is not None:
                if klass == wp.TokenIntegrityLevel:
                    sid = ctypes.c_void_p.from_buffer(buf, 0).value
                    count = api.GetSidSubAuthorityCount(sid).contents.value
                    api.GetSidSubAuthority(sid, count - 1).contents.value = value
                else:
                    ctypes.c_uint32.from_buffer(buf, 0).value = value
            return rv
        api.GetTokenInformation = gti

    def _run_with_token_fact(self, klass, value):
        api = self._api()
        srv = wp.OneShotPipeServer(_name(), api=api)     # own session read before patching
        self._patch_token_info(api, klass, value)
        with srv:
            r, c = _serve_with_client(srv, 3.0)
        self.assertEqual(c.result.response, b'')
        self.assertFalse(wp.thread_is_impersonating(wp.default_api()))
        return r

    def test_low_integrity_token_denied(self):
        r = self._run_with_token_fact(wp.TokenIntegrityLevel, 0x1000)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'INTEGRITY_TOO_LOW'))

    def test_appcontainer_token_denied(self):
        r = self._run_with_token_fact(wp.TokenIsAppContainer, 1)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'APPCONTAINER_CLIENT'))

    def test_restricted_flag_denied(self):
        r = self._run_with_token_fact(wp.TokenIsRestricted, 1)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'RESTRICTED_TOKEN'))

    def test_other_session_denied(self):
        r = self._run_with_token_fact(wp.TokenSessionId, wp.own_session_id() + 7)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'SESSION_MISMATCH'))

    def test_anonymous_level_value_denied(self):
        r = self._run_with_token_fact(wp.TokenImpersonationLevel, wp.SecurityAnonymous)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'IMPERSONATION_LEVEL_TOO_LOW'))

    def test_real_restricted_token_client_denied(self):
        api = wp.default_api()
        proc, rtok, imp = wp.wintypes.HANDLE(), wp.wintypes.HANDLE(), wp.wintypes.HANDLE()
        self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(),
                                             wp.TOKEN_QUERY | wp.TOKEN_DUPLICATE | 0x0001, ctypes.byref(proc)))
        user = ctypes.c_void_p()
        self.assertTrue(api.ConvertStringSidToSidW(wp.current_user_sid(), ctypes.byref(user)))
        restrict = wp.SID_AND_ATTRIBUTES(user, 0)
        try:
            self.assertTrue(api.CreateRestrictedToken(proc, 0, 0, None, 0, None, 1, ctypes.byref(restrict),
                                                      ctypes.byref(rtok)))
            self.assertTrue(api.DuplicateTokenEx(rtok, wp.TOKEN_QUERY | wp.TOKEN_IMPERSONATE, None,
                                                 wp.SecurityImpersonation, wp.TokenImpersonation,
                                                 ctypes.byref(imp)))
        finally:
            api.LocalFree(user)
            api.CloseHandle(proc)
            if rtok.value:
                api.CloseHandle(rtok)
        out = {}

        # Raw client with the W13 SQOS: this test isolates the SERVER guard.
        # (client_ping under this restricted token fails closed earlier with
        # PIPE_OWNER_FAILED/127 when GetSecurityInfo's provider DLL is not yet
        # loaded - observed when the test runs alone.)
        def run():
            if not api.SetThreadToken(None, imp):
                out['err'] = api.last_error()
                return
            try:
                h = api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING,
                                    wp.client_sqos_flags(), None)
                if h in (None, wp.INVALID_HANDLE_VALUE):
                    out['c'] = wp.ClientResult(api.last_error(), b'', False, 'OPEN_FAILED')
                    return
                try:
                    buf = ctypes.create_string_buffer(b'U', 8)
                    n = ctypes.c_ulong(0)
                    sent = bool(api.WriteFile(h, buf, 1, ctypes.byref(n), None))
                    got = ctypes.c_ulong(0)
                    ok = api.ReadFile(h, buf, 7, ctypes.byref(got), None)
                    out['c'] = wp.ClientResult(None, buf.raw[:got.value] if ok else b'', sent)
                finally:
                    api.CloseHandle(h)
            finally:
                if not api.RevertToSelf():
                    os._exit(31)
        name = _name()
        try:
            with wp.OneShotPipeServer(name) as srv:
                t = threading.Thread(target=run, daemon=True)
                t.start()
                r = srv.serve(3.0)
                t.join(5)
        finally:
            api.CloseHandle(imp)
        self.assertNotIn('err', out)
        self.assertIsNone(out['c'].open_error)                    # DACL admitted the restricted token
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'RESTRICTED_TOKEN'))
        self.assertEqual(out['c'].response, b'')

    def test_failed_cancel_does_not_extend_deadline_unbounded(self):
        # Deadline guard turned against itself: if CancelIoEx fails, the old code
        # blocked in GetOverlappedResult(bWait=TRUE) until the client went away.
        api = self._api()

        def cancel_fails(_h, _ov):
            ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
            return 0
        api.CancelIoEx = cancel_fails
        for _ in range(2):            # second round must prune the first parked entry
            with wp.OneShotPipeServer(_name(), api=api) as srv:
                _Client(wp.client_ping, srv.name, send=False, hold_s=5.0).start()
                r = srv.serve(0.3)
            self.assertEqual((r.verdict, r.reason), ('DENIED', 'READ_TIMEOUT'))
            self.assertLess(r.elapsed_s, 0.3 + wp.CANCEL_GRACE_MS / 1000 + 0.5)
        self.assertEqual(len(wp._PARKED), 1)

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

    def test_late_complete_write_counts_as_sent(self):
        # Aegis p3-3: write completed, but serve() re-checked after the deadline
        # and reported DENIED/WRITE_TIMEOUT while the client held PEER_OK.
        api = self._api()
        real_w = api.WriteFile

        def slow_write(*a):
            rv = real_w(*a)
            time.sleep(1.3)
            return rv
        api.WriteFile = slow_write
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            r, c = _serve_with_client(srv, 1.0)
        self.assertEqual(c.result.response, b'PEER_OK')
        self.assertEqual((r.verdict, r.response_sent), ('PEER_OK', True))

    def test_sid_text_failure_is_typed_denial(self):
        # Aegis p3-4: ConvertSidToStringSidW failing after the token query raised
        # OSError out of serve() instead of a typed DENIED.
        api = self._api()
        real_c = api.ConvertSidToStringSidW
        armed = {'on': False}

        def conv(*a):
            if armed['on']:
                ctypes.set_last_error(8)
                return 0
            return real_c(*a)
        api.ConvertSidToStringSidW = conv
        with wp.OneShotPipeServer(_name(), api=api) as srv:
            armed['on'] = True
            try:
                r, c = _serve_with_client(srv, 3.0)
            except OSError as exc:
                self.fail(f'serve() raised instead of a typed denial: {exc!r}')
        self.assertEqual((r.verdict, r.reason, r.winerror), ('DENIED', 'SID_TEXT_FAILED', 8))
        self.assertEqual(c.result.response, b'')

    def test_foreign_expected_sid_requires_flag(self):
        # Aegis P3-d: 'S-1-5-18' would switch acceptance to SYSTEM (DACL has SY).
        with self.assertRaisesRegex(ValueError, 'FOREIGN_EXPECTED_SID_REQUIRES_FLAG'):
            wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18')
        with self.assertRaisesRegex(ValueError, 'INVALID_FLAG'):
            wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18', allow_foreign_expected_sid=1)
        with wp.OneShotPipeServer(_name(), expected_sid=wp.current_user_sid()) as srv:
            self.assertEqual(srv.expected_sid, srv.server_sid)

    def test_no_allocation_leak_when_server_sid_text_invalid(self):
        # Aegis P3-f: build_sddl(server_sid) ran after ConvertStringSidToSidW.
        api = self._api()
        allocs, frees = [], []
        real_conv, real_free = api.ConvertStringSidToSidW, api.LocalFree

        def conv(text, out):
            rv = real_conv(text, out)
            if rv:
                allocs.append(out._obj.value)
            return rv

        def free(p):
            if isinstance(p, ctypes.c_void_p):
                frees.append(p.value)
            elif p is not None and not isinstance(p, int):
                frees.append(ctypes.cast(p, ctypes.c_void_p).value)
            else:
                frees.append(p)
            return real_free(p)
        api.ConvertStringSidToSidW, api.LocalFree = conv, free
        with mock.patch.object(wp, 'current_user_sid', return_value='S-1-0x5-1'):
            with self.assertRaisesRegex(ValueError, 'INVALID_SID_TEXT'):
                wp.OneShotPipeServer(_name(), expected_sid='S-1-5-18', allow_foreign_expected_sid=True, api=api)
        self.assertTrue(set(allocs) <= set(frees), (allocs, frees))
        # Failure AFTER the expected-SID allocation must release it as well.

        def sd_fail(*a):
            ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
            return 0
        api.ConvertStringSecurityDescriptorToSecurityDescriptorW = sd_fail
        with self.assertRaises(wp.PipeSetupError):
            wp.OneShotPipeServer(_name(), api=api)
        self.assertEqual(len(allocs), 1)
        self.assertTrue(set(allocs) <= set(frees), (allocs, frees))

    def test_dropped_server_releases_pipe_name(self):
        # Aegis P3-f: without close() the handle (and the name) stayed alive.
        name = _name()
        srv = wp.OneShotPipeServer(name)
        del srv
        gc.collect()
        try:
            wp.OneShotPipeServer(name).close()    # FIRST_PIPE_INSTANCE would refuse a live name
        except wp.PipeSetupError as exc:
            self.fail(f'pipe name still held by the dropped server: {exc!r}')

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
