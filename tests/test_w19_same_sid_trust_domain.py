"""W19 (ADR-UDX-006): same-SID trust domain and the loud pipe-name-occupied failure.

``SameSidTrustDomainPremise`` pins the premise the ADR rests on: a process of the
same user at the same integrity level gets write/thread access to another such
process from its default DACL, so authenticating the pipe server against it would
buy nothing. The control is the same kind of child with a DACL that grants only
SYNCHRONIZE: the identical open is then refused, i.e. the positive result comes
from the default DACL and not from a probe that cannot say no.

Active only on Windows; nothing here creates accounts, raises privileges or
writes into a foreign process (handles are opened and closed, never used).
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import unittest

from udx_ref import windows_pipe as wp

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


if __name__ == '__main__':
    unittest.main()
