"""W25.2: the Python client refuses a pipe without an explicit mandatory label >= Medium.

Native (Windows) cases run in the CI suite jobs; the elevated runner sets the
labels explicitly, so the decision is exercised without needing a Low-IL creator
(the real Low-IL squatter runs in tools/w25_principal_matrix.py). The client
connects silently (send=False): a refusal happens BEFORE any byte is written.
"""
from __future__ import annotations

import ctypes
import sys
import unittest
import uuid

from udx_ref import windows_pipe as wp

IS_WINDOWS = sys.platform == 'win32'


@unittest.skipUnless(IS_WINDOWS, 'Windows runtime required')
class PipeLabelCheck(unittest.TestCase):
    def setUp(self):
        self.api = wp.default_api()
        self.sid = wp.current_user_sid(self.api)
        self.handles = []

    def tearDown(self):
        for h in self.handles:
            self.api.CloseHandle(h)

    def _pipe(self, label: str):
        name = wp.PIPE_PREFIX + 'UDX_W25L_' + uuid.uuid4().hex
        sd = ctypes.c_void_p()
        sddl = 'O:%sD:(A;;GA;;;%s)%s' % (self.sid, self.sid, label)
        self.assertTrue(self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, wp.SDDL_REVISION_1, ctypes.byref(sd), None))
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            h = self.api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX | wp.FILE_FLAG_FIRST_PIPE_INSTANCE,
                                          0, 1, 4096, 4096, 0, ctypes.byref(sa))
        finally:
            self.api.LocalFree(sd)
        self.assertNotIn(h, (None, wp.INVALID_HANDLE_VALUE), self.api.last_error())
        self.handles.append(h)
        return name, h

    def test_low_label_is_refused_before_writing(self):
        name, h = self._pipe('S:(ML;;NW;;;LW)')
        self.assertEqual(wp.pipe_label_rid(self.api, h), (0x1000, 0))
        r = wp.client_ping(name, send=False, connect_timeout_s=2.0)
        self.assertEqual((r.reason, r.sent, r.pipe_label, r.pipe_owner), ('PIPE_LABEL_TOO_LOW', False, 0x1000, self.sid))

    def test_medium_label_passes_the_label_check(self):
        name, h = self._pipe('S:(ML;;NWNR;;;ME)')
        self.assertEqual(wp.pipe_label_rid(self.api, h), (0x2000, 0))
        r = wp.client_ping(name, send=False, hold_s=0.0, connect_timeout_s=2.0)
        self.assertEqual((r.reason, r.sent), ('SILENT_HOLD', False))

    def test_inherit_only_label_is_refused(self):
        # Aegis W25.2: an INHERIT_ONLY label ACE does not apply to the pipe object
        # itself. The kernel keeps OICIIO on a pipe (bare IO is dropped, measured),
        # so the RID alone reads Medium; the client must not count it.
        name, h = self._pipe('S:(ML;OICIIO;NWNR;;;ME)')
        info, rc = wp.pipe_label_info(self.api, h)
        self.assertEqual((rc, info[0], bool(info[1] & wp.INHERIT_ONLY_ACE)), (0, 0x2000, True))
        r = wp.client_ping(name, send=False, hold_s=0.0, connect_timeout_s=2.0)
        self.assertEqual((r.reason, r.sent, r.pipe_label), ('PIPE_LABEL_INHERIT_ONLY', False, 0x2000))

    def test_label_without_no_write_up_is_refused(self):
        # Aegis W25.2: a Medium label whose policy lacks NO_WRITE_UP does not stop
        # a lower-integrity writer, so it must not count as the Medium label.
        name, h = self._pipe('S:(ML;;NR;;;ME)')
        self.assertEqual(wp.pipe_label_info(self.api, h), ((0x2000, 0, 0x2), 0))
        r = wp.client_ping(name, send=False, hold_s=0.0, connect_timeout_s=2.0)
        self.assertEqual((r.reason, r.sent, r.pipe_label), ('PIPE_LABEL_NO_WRITE_UP_MISSING', False, 0x2000))

    def test_production_label_is_effective_and_no_write_up(self):
        with wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_W25L_' + uuid.uuid4().hex) as srv:
            self.assertEqual(wp.pipe_label_info(self.api, srv.handle), ((0x2000, 0, 0x3), 0))

    def test_production_server_pipe_carries_medium(self):
        with wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_W25L_' + uuid.uuid4().hex) as srv:
            self.assertEqual(wp.pipe_label_rid(self.api, srv.handle), (0x2000, 0))

    def test_label_query_failure_is_typed(self):
        name, _ = self._pipe('S:(ML;;NWNR;;;ME)')
        api = wp.WinApi()
        real = api.GetSecurityInfo

        def gsi(*a):
            if a[2] == wp.LABEL_SECURITY_INFORMATION:
                return wp.ERROR_ACCESS_DENIED
            return real(*a)
        api.GetSecurityInfo = gsi
        r = wp.client_ping(name, send=False, connect_timeout_s=2.0, api=api)
        self.assertEqual((r.reason, r.winerror, r.sent), ('PIPE_LABEL_FAILED', wp.ERROR_ACCESS_DENIED, False))


if __name__ == '__main__':
    unittest.main()
