"""W19 (ADR-UDX-006): same-SID trust domain and the loud pipe-name-occupied failure.

``SameSidTrustDomainPremise`` pins the premise the ADR rests on: a process of the
same user at the same integrity level gets write/thread access to another such
process from its default DACL, so authenticating the pipe server against it would
buy nothing. The control is the same kind of child with a DACL that grants only
SYNCHRONIZE: the identical open is then refused, i.e. the positive result comes
from the default DACL and not from a probe that cannot say no.

``PipeNameOccupied`` covers the availability boundary (ADR section 4): a name
created before the server starts is refused with PIPE_NAME_OCCUPIED / CLI exit 21
and never joined; a free unique name is the positive control; injected errors
check that the label never over-claims.

Active only on Windows; nothing here creates accounts, raises privileges or
writes into a foreign process (handles are opened and closed, never used).
"""
from __future__ import annotations

import ctypes
import json
import pathlib
import subprocess
import sys
import unittest
import uuid
from unittest import mock

from udx_ref import windows_pipe as wp

REPO = pathlib.Path(__file__).resolve().parents[1]
IS_WINDOWS = sys.platform == 'win32'

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
INJECT_ACCESS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
CREATE_NO_WINDOW = 0x08000000
SLEEPER = [sys.executable, '-c', 'import time; time.sleep(20)']


@unittest.skipUnless(IS_WINDOWS, 'Windows only')
class SameSidTrustDomainPremise(unittest.TestCase):
    def setUp(self):
        from ctypes import wintypes
        self.w = wintypes
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.k.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)

    def _open(self, pid):
        h = self.k.OpenProcess(INJECT_ACCESS, False, pid)
        err = None if h else ctypes.get_last_error()
        if h:
            self.k.CloseHandle(h)
        return bool(h), err

    def _child_with_sddl(self, sddl):
        """CreateProcessW with an explicit process security descriptor."""
        w = self.w

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR),
                        ('lpTitle', w.LPWSTR), ('dwX', w.DWORD), ('dwY', w.DWORD), ('dwXSize', w.DWORD),
                        ('dwYSize', w.DWORD), ('dwXCountChars', w.DWORD), ('dwYCountChars', w.DWORD),
                        ('dwFillAttribute', w.DWORD), ('dwFlags', w.DWORD), ('wShowWindow', w.WORD),
                        ('cbReserved2', w.WORD), ('lpReserved2', ctypes.c_void_p), ('hStdInput', w.HANDLE),
                        ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE),
                        ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]

        api = wp.default_api()
        sd = ctypes.c_void_p()
        self.assertTrue(api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, wp.SDDL_REVISION_1, ctypes.byref(sd), None))
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()
            cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline(SLEEPER))
            create = self.k.CreateProcessW
            create.argtypes = (w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
                               ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p)
            create.restype = w.BOOL
            ok = create(None, cmd, ctypes.byref(sa), None, False, CREATE_NO_WINDOW, None, None,
                        ctypes.byref(si), ctypes.byref(pi))
            self.assertTrue(ok, ctypes.get_last_error())
        finally:
            api.LocalFree(sd)
        self.k.CloseHandle(pi.hThread)
        return pi.hProcess, pi.dwProcessId

    def _stop(self, h):
        # The CreateProcess handle has PROCESS_ALL_ACCESS regardless of the DACL.
        self.k.TerminateProcess(h, 0)
        self.k.WaitForSingleObject(h, 5000)
        self.k.CloseHandle(h)

    def test_default_dacl_grants_same_user_inject_rights(self):
        child = subprocess.Popen(SLEEPER, creationflags=CREATE_NO_WINDOW)
        try:
            self.assertEqual(self._open(child.pid), (True, None))
        finally:
            child.kill()
            child.wait(10)

    def _debug_privilege_enabled(self) -> bool:
        """SeDebugPrivilege ignores the process DACL; with it ENABLED the control
        cannot say no, so it would prove nothing (elevated runners may differ)."""
        w = self.w
        a = ctypes.WinDLL('advapi32', use_last_error=True)

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('LowPart', w.DWORD), ('HighPart', w.LONG), ('Attributes', w.DWORD)]

        class PRIVILEGE_SET(ctypes.Structure):
            _fields_ = [('PrivilegeCount', w.DWORD), ('Control', w.DWORD),
                        ('Privilege', LUID_AND_ATTRIBUTES * 1)]

        ps = PRIVILEGE_SET(1, 1)
        luid = ps.Privilege[0]
        a.LookupPrivilegeValueW.argtypes = (w.LPCWSTR, w.LPCWSTR, ctypes.c_void_p)
        self.assertTrue(a.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid)))
        api = wp.default_api()
        tok = w.HANDLE()
        self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY, ctypes.byref(tok)))
        try:
            result = w.BOOL()
            a.PrivilegeCheck.argtypes = (w.HANDLE, ctypes.c_void_p, ctypes.POINTER(w.BOOL))
            self.assertTrue(a.PrivilegeCheck(tok, ctypes.byref(ps), ctypes.byref(result)))
            return bool(result.value)
        finally:
            api.CloseHandle(tok)

    def test_control_synchronize_only_dacl_refuses_the_same_open(self):
        if self._debug_privilege_enabled():
            self.skipTest('SeDebugPrivilege enabled: the DACL control cannot refuse')
        sid = wp.current_user_sid()
        h, pid = self._child_with_sddl('O:' + sid + 'D:P(A;;0x100000;;;' + sid + ')')
        try:
            self.assertEqual(self._open(pid), (False, wp.ERROR_ACCESS_DENIED))
        finally:
            self._stop(h)


def _name() -> str:
    return wp.PIPE_PREFIX + 'UDX_W19_' + uuid.uuid4().hex


def _cli_server(name, deadline='3'):
    return subprocess.Popen([sys.executable, '-m', 'udx_ref.windows_pipe', 'server', '--name', name,
                             '--deadline', deadline], cwd=REPO, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@unittest.skipUnless(IS_WINDOWS, 'Windows only')
class PipeNameOccupied(unittest.TestCase):
    """ADR-UDX-006 section 4: a name that exists before the server starts is
    reported loudly (PIPE_NAME_OCCUPIED / exit 21) and never joined. Real
    pre-created pipes; fault injection only for the 'label must not over-claim'
    cases."""

    def setUp(self):
        self.api = wp.default_api()
        self._squats = []

    def tearDown(self):
        for h in self._squats:
            self.api.CloseHandle(h)

    def _squat(self, name, max_instances=255):
        # Attacker-style pipe: default DACL; the same SID owns it.
        h = self.api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX, 0, max_instances, 4096, 4096, 0, None)
        self.assertNotIn(h, (None, wp.INVALID_HANDLE_VALUE), self.api.last_error())
        self._squats.append(h)
        return h

    # -- the signal ------------------------------------------------------
    def test_squatter_with_free_instances_gives_occupied_access_denied(self):
        name = _name()
        self._squat(name, 255)
        with self.assertRaises(wp.PipeNameOccupied) as cm:
            wp.OneShotPipeServer(name)
        self.assertEqual((cm.exception.errno, cm.exception.reason), (wp.ERROR_ACCESS_DENIED, 'PIPE_NAME_OCCUPIED'))
        self.assertIsInstance(cm.exception, wp.PipeSetupError)       # old callers keep working

    def test_squatter_with_one_instance_gives_occupied_pipe_busy(self):
        name = _name()
        self._squat(name, 1)
        with self.assertRaises(wp.PipeNameOccupied) as cm:
            wp.OneShotPipeServer(name)
        self.assertEqual(cm.exception.errno, wp.ERROR_PIPE_BUSY)

    def test_live_own_server_is_reported_occupied_too(self):
        # The server cannot tell a squatter from a second legitimate instance.
        name = _name()
        with wp.OneShotPipeServer(name):
            with self.assertRaises(wp.PipeNameOccupied):
                wp.OneShotPipeServer(name)

    def test_cli_exits_21_with_typed_json_and_never_listens(self):
        name = _name()
        squat = self._squat(name, 255)
        proc = _cli_server(name)
        out, err = proc.communicate(timeout=30)
        lines = out.decode().strip().splitlines()
        self.assertEqual(proc.returncode, wp.NAME_OCCUPIED_EXIT, (out, err))
        self.assertEqual(len(lines), 1, lines)                       # no 'listening' line
        self.assertEqual(json.loads(lines[0]), {'verdict': 'DENIED', 'reason': 'PIPE_NAME_OCCUPIED',
                                                'winerror': wp.ERROR_ACCESS_DENIED, 'name': name})
        self.assertNotIn(b'Traceback', err)
        # Not joined: the squatter's instance is untouched and still the one a
        # client reaches (ConnectNamedPipe -> already connected).
        c = self.api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING, 0, None)
        self.assertNotIn(c, (None, wp.INVALID_HANDLE_VALUE), self.api.last_error())
        try:
            self.assertFalse(self.api.ConnectNamedPipe(squat, None))
            self.assertEqual(self.api.last_error(), wp.ERROR_PIPE_CONNECTED)
        finally:
            self.api.CloseHandle(c)

    # -- positive control ---------------------------------------------------
    def test_control_free_unique_name_starts_and_serves(self):
        name = _name()
        self.assertFalse(wp.pipe_name_present(self.api, name))
        proc = _cli_server(name, deadline='10')
        try:
            self.assertIn('listening', proc.stdout.readline().decode())
            self.assertTrue(wp.pipe_name_present(self.api, name))
            c = wp.client_ping(name)
            out, err = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(c.response, b'PEER_OK')
        self.assertEqual(proc.returncode, 0, err)

    # -- the label must not over-claim ----------------------------------------
    def _api_create_fails(self, err):
        api = wp.WinApi()

        def fail(*a):
            ctypes.set_last_error(err)
            return wp.INVALID_HANDLE_VALUE
        api.CreateNamedPipeW = fail
        return api

    def test_access_denied_on_absent_name_stays_generic(self):
        # e.g. an AppContainer outside its namespace: ACCESS_DENIED, no pipe.
        with self.assertRaises(wp.PipeSetupError) as cm:
            wp.OneShotPipeServer(_name(), api=self._api_create_fails(wp.ERROR_ACCESS_DENIED))
        self.assertNotIsInstance(cm.exception, wp.PipeNameOccupied)
        self.assertEqual(cm.exception.errno, wp.ERROR_ACCESS_DENIED)

    def test_other_error_on_present_name_stays_generic(self):
        name = _name()
        self._squat(name)
        ERROR_INVALID_PARAMETER = 87
        with self.assertRaises(wp.PipeSetupError) as cm:
            wp.OneShotPipeServer(name, api=self._api_create_fails(ERROR_INVALID_PARAMETER))
        self.assertNotIsInstance(cm.exception, wp.PipeNameOccupied)

    def test_cli_generic_failure_is_not_exit_21(self):
        # Absent name + injected ACCESS_DENIED through the CLI entry point.
        with mock.patch.object(wp, 'default_api', return_value=self._api_create_fails(wp.ERROR_ACCESS_DENIED)):
            with self.assertRaises(wp.PipeSetupError) as cm:
                wp.main(['server', '--name', _name(), '--deadline', '1'])
        self.assertNotIsInstance(cm.exception, wp.PipeNameOccupied)

    # -- the namespace probe --------------------------------------------------
    def test_probe_matches_exactly_not_by_wildcard(self):
        name = _name()
        self._squat(name)
        self.assertTrue(wp.pipe_name_present(self.api, name))
        self.assertTrue(wp.pipe_name_present(self.api, name.lower()))   # namespace is case-insensitive
        self.assertFalse(wp.pipe_name_present(self.api, name[:-4] + '*'))
        self.assertFalse(wp.pipe_name_present(self.api, name[:-1] + '?'))
        self.assertFalse(wp.pipe_name_present(self.api, name + 'X'))

    def test_probe_does_not_consume_the_single_instance(self):
        name = _name()
        self._squat(name, 1)
        self.assertTrue(wp.pipe_name_present(self.api, name))
        # GetFileAttributes-style probes open the pipe and leave the only
        # instance busy; the namespace listing must not.
        c = self.api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING, 0, None)
        self.assertNotIn(c, (None, wp.INVALID_HANDLE_VALUE), self.api.last_error())
        self.api.CloseHandle(c)

    def test_probe_rejects_invalid_names(self):
        for bad in ('', 'UDX', wp.PIPE_PREFIX, wp.PIPE_PREFIX + 'a\\b', None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'INVALID_PIPE_NAME'):
                wp.pipe_name_present(self.api, bad)


if __name__ == '__main__':
    unittest.main()
