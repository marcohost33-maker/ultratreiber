"""W18 (UDX14-01 instance bit): no ACE of the pipe grants FILE_CREATE_PIPE_INSTANCE.

Open since W14: GRGW (0x12019f) contains FILE_APPEND_DATA, which for named pipes
is the same bit as FILE_CREATE_PIPE_INSTANCE (0x4). Microsoft: "FILE_GENERIC_WRITE
enables permission to create the pipe. To avoid this problem, use the individual
rights instead of using FILE_GENERIC_WRITE" (Named Pipe Security and Access Rights).
W18 grants and requests PIPE_ACE_MASK = FILE_GENERIC_READ | FILE_WRITE_DATA
(0x12008b) instead.

Creating the FIRST instance takes its descriptor from the security attributes and
is not checked against it; every FURTHER CreateNamedPipeW on an existing name is
checked and needs FILE_CREATE_PIPE_INSTANCE. The runtime tests therefore create a
two-instance fixture pipe (same parameters for both calls, so the only difference
between control and W18 is the ACE mask) and try the second instance:

* control: the W17 descriptor (GRGW) admits the second instance;
* W18: the same call fails with ERROR_ACCESS_DENIED.

The client side is discriminated the same way: a legacy GENERIC_READ|GENERIC_WRITE
open maps to FILE_GENERIC_WRITE (contains 0x4) and is refused by W18 but admitted
by the W17 control, while CLIENT_ACCESS opens W18.

Not covered (unchanged threat-model gate UDX14-08): a same-SID process that
creates the name BEFORE the real server is the first instance and picks its own
descriptor.
"""
from __future__ import annotations

import contextlib
import ctypes
import io
import json
import pathlib
import sys
import threading
import unittest
import uuid
from unittest import mock

from udx_ref import windows_pipe as wp

IS_WINDOWS = sys.platform == 'win32'
W17_SDDL = 'O:{sid}D:P(A;;GRGW;;;SY)(A;;GRGW;;;{sid})(A;;GRGW;;;OW)S:(ML;;NWNR;;;ME)'
GRGW_MASK = 0x0012019F
DELETE = 0x00010000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000


def _name() -> str:
    return wp.PIPE_PREFIX + 'UDX_W18_' + uuid.uuid4().hex


class PortableLeastPrivilegeMask(unittest.TestCase):
    def test_mask_is_generic_read_plus_write_data_only(self):
        self.assertEqual(wp.PIPE_ACE_MASK, 0x0012008B)
        self.assertEqual(int(wp.PIPE_ACE_SDDL, 16), wp.PIPE_ACE_MASK)
        self.assertEqual(wp.CLIENT_ACCESS, wp.PIPE_ACE_MASK)
        self.assertEqual(wp.FILE_GENERIC_READ, 0x00120089)
        for needed in (wp.FILE_READ_DATA, wp.FILE_WRITE_DATA, wp.READ_CONTROL, wp.SYNCHRONIZE):
            self.assertEqual(wp.PIPE_ACE_MASK & needed, needed)
        for absent in (wp.FILE_CREATE_PIPE_INSTANCE, wp.FILE_WRITE_EA, wp.FILE_WRITE_ATTRIBUTES,
                       DELETE, WRITE_DAC, WRITE_OWNER, wp.GENERIC_READ, wp.GENERIC_WRITE):
            self.assertEqual(wp.PIPE_ACE_MASK & absent, 0, hex(absent))

    def test_mask_is_grgw_minus_instance_and_attribute_writes(self):
        # Only rights are removed, none added, relative to the W17 GRGW mask.
        self.assertEqual(wp.PIPE_ACE_MASK | GRGW_MASK, GRGW_MASK)
        self.assertEqual(GRGW_MASK & ~wp.PIPE_ACE_MASK,
                         wp.FILE_CREATE_PIPE_INSTANCE | wp.FILE_WRITE_EA | wp.FILE_WRITE_ATTRIBUTES)

    def test_every_ace_carries_the_mask(self):
        sid = 'S-1-5-21-1-2-3-1001'
        sddl = wp.build_sddl(sid)
        dacl = sddl[sddl.index('D:'):sddl.index('S:')]
        aces = dacl[len('D:P'):].strip('()').split(')(')
        self.assertEqual(aces, ['A;;0x12008b;;;SY', 'A;;0x12008b;;;' + sid, 'A;;0x12008b;;;OW'])
        self.assertNotIn('GRGW', sddl)
        self.assertNotIn(';GA;', sddl)


class PortableCppCrossrunTool(unittest.TestCase):
    def test_non_windows_refuses_without_claim(self):
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
        try:
            import w18_cpp_crossrun as tool
        finally:
            sys.path.pop(0)
        if IS_WINDOWS:
            self.skipTest('non-Windows path only')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = tool.main([])
        report = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report['verdict'], 'NATIVE_WINDOWS_REQUIRED')
        self.assertFalse(report['release_authorized'])


@unittest.skipUnless(IS_WINDOWS, 'Windows runtime required')
class WindowsInstanceRight(unittest.TestCase):
    def setUp(self):
        self.api = wp.default_api()
        self.sid = wp.current_user_sid(self.api)

    def _create(self, name, sddl, max_instances):
        """Raw CreateNamedPipeW, identical parameters on every call; (handle|None, winerror)."""
        api = self.api
        sd = ctypes.c_void_p()
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, wp.SDDL_REVISION_1,
                                                                        ctypes.byref(sd), None):
            raise OSError(api.last_error(), 'ConvertStringSecurityDescriptorToSecurityDescriptorW failed')
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            mode = wp.PIPE_TYPE_BYTE | wp.PIPE_READMODE_BYTE | wp.PIPE_WAIT | wp.PIPE_REJECT_REMOTE_CLIENTS
            h = api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX, mode, max_instances, 4096, 4096, 0,
                                     ctypes.byref(sa))
            if h is None or h == wp.INVALID_HANDLE_VALUE:
                return None, api.last_error()
            return h, 0
        finally:
            api.LocalFree(sd)

    def _second_instance(self, sddl):
        """First instance (not access-checked), then a second one (access-checked)."""
        name = _name()
        first, err = self._create(name, sddl, 2)
        self.assertIsNotNone(first, 'first instance must always be creatable (winerror %s)' % err)
        try:
            second, err = self._create(name, sddl, 2)
            if second is not None:
                self.api.CloseHandle(second)
                return True, 0
            return False, err
        finally:
            self.api.CloseHandle(first)

    def test_further_instance_needs_the_dropped_bit(self):
        # Control: the W17 descriptor (GRGW contains 0x4) admits a second instance.
        self.assertEqual(self._second_instance(W17_SDDL.format(sid=self.sid)), (True, 0))
        # W18: identical call, only the ACE mask differs -> refused by the DACL.
        self.assertEqual(self._second_instance(wp.build_sddl(self.sid)), (False, wp.ERROR_ACCESS_DENIED))

    def _open(self, access, sddl_template=None):
        name = _name()
        if sddl_template is None:
            ctx = contextlib.nullcontext()
        else:
            ctx = mock.patch.object(wp, 'build_sddl',
                                    lambda sid: sddl_template.format(sid=wp.validate_sid_text(sid)))
        with ctx, wp.OneShotPipeServer(name):
            h = self.api.CreateFileW(name, access, 0, None, wp.OPEN_EXISTING, 0, None)
            if h is None or h == wp.INVALID_HANDLE_VALUE:
                return False, self.api.last_error()
            self.api.CloseHandle(h)
            return True, 0

    def test_generic_write_client_refused_client_access_admitted(self):
        legacy = wp.GENERIC_READ | wp.GENERIC_WRITE
        # Control: under W17 (GRGW) the legacy client open succeeds.
        self.assertEqual(self._open(legacy, W17_SDDL), (True, 0))
        # W18: GENERIC_WRITE -> FILE_GENERIC_WRITE includes 0x4 -> refused.
        self.assertEqual(self._open(legacy), (False, wp.ERROR_ACCESS_DENIED))
        # Positive control: the W18 client mask opens.
        self.assertEqual(self._open(wp.CLIENT_ACCESS), (True, 0))

    def test_client_ping_opens_with_client_access(self):
        seen = []
        api = wp.WinApi()
        real = api.CreateFileW

        def recording(name, access, *rest):
            seen.append(access)
            return real(name, access, *rest)
        api.CreateFileW = recording
        name = _name()
        with wp.OneShotPipeServer(name) as srv:
            client = []
            t = threading.Thread(target=lambda: client.append(wp.client_ping(name, api=api)), daemon=True)
            t.start()
            r = srv.serve(5.0)
            t.join(10)
        self.assertTrue(r.ok, r)
        self.assertEqual(client[0].reason, 'OK')
        self.assertEqual(set(seen), {wp.CLIENT_ACCESS})


if __name__ == '__main__':
    unittest.main()
