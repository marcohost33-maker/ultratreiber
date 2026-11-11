"""UT6-02 (cross-family A7-R2): client and server bind the SAME identity.

Before: the server required the client's integrity level to EQUAL its own
(Aegis W25.2-P2, INTEGRITY_MISMATCH), but the client only required the pipe's
mandatory label to be ``>= Medium``, and every server labelled its pipe Medium
whatever its own level. A Medium client therefore accepted an elevated server's
pipe and wrote to it; the asymmetry was confirmed as a design gap.

Now:
  * server: the label ACE is built from the server token's OWN level
    (``build_sddl(sid, own_rid)``; Medium -> ME, High -> HI, anything else ->
    ``ValueError('UNSUPPORTED_INTEGRITY_LEVEL')`` before any allocation);
  * client: the label must EQUAL the client's own EFFECTIVE level
    (``PIPE_LABEL_MISMATCH``); an unreadable own level is ``OWN_INTEGRITY_FAILED``
    and nothing is opened.

Native cases read the REAL process/thread token and the REAL kernel label of a
real pipe. Levels this host cannot create (a Medium process cannot label above
Medium) are injected at one seam each -- either the client's own-level read
(``GetTokenInformation(TokenIntegrityLevel)``) or the label read
(``pipe_label_info``) -- never both, so every case has one real side. On the
elevated CI runner (own level High) the same cases meet a real High label.

Kept out of tests/test_w12_windows_pipe.py (byte-pinned W14 source).
"""
from __future__ import annotations

import ctypes
import pathlib
import sys
import threading
import unittest
import uuid
from unittest import mock

from udx_ref import windows_pipe as wp

ROOT = pathlib.Path(__file__).resolve().parents[1]
IS_WINDOWS = sys.platform == 'win32'
SID = 'S-1-5-21-1-2-3-1001'


class PortableLabelParity(unittest.TestCase):
    def test_label_sddl_maps_exactly_the_supported_levels(self):
        self.assertEqual(wp.label_sddl(0x2000), 'S:(ML;;NWNR;;;ME)')
        self.assertEqual(wp.label_sddl(0x3000), 'S:(ML;;NWNR;;;HI)')
        self.assertEqual(wp.LABEL_SDDL_ALIASES, {0x2000: 'ME', 0x3000: 'HI'})

    def test_label_sddl_refuses_every_other_value(self):
        for bad in (None, True, False, 0, -1, 0x1000, 0x1fff, 0x2001, 0x2100, 0x2fff, 0x4000, 0x5000,
                    '8192', 8192.0, b'\x00\x20', [0x2000], 2 ** 64):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'UNSUPPORTED_INTEGRITY_LEVEL'):
                wp.label_sddl(bad)

    def test_build_sddl_label_follows_the_level_and_nothing_else(self):
        medium, high = wp.build_sddl(SID, 0x2000), wp.build_sddl(SID, 0x3000)
        self.assertEqual(wp.build_sddl(SID), medium)          # reviewed W14/W18 one-argument form
        self.assertTrue(medium.endswith(')S:(ML;;NWNR;;;ME)'))
        self.assertTrue(high.endswith(')S:(ML;;NWNR;;;HI)'))
        self.assertEqual(medium[:medium.index('S:')], high[:high.index('S:')])   # owner + DACL identical
        with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_INTEGRITY_LEVEL'):
            wp.build_sddl(SID, 0x1000)
        # SID validation still comes first (no SDDL fragment smuggling, W12)
        with self.assertRaisesRegex(ValueError, 'INVALID_SID_TEXT'):
            wp.build_sddl('S-1-5-18)(A;;GA;;;WD', 0x1000)

    def test_source_wiring(self):
        # portable pins of the decisive lines (runtime: WindowsLabelParity below)
        src = (ROOT / 'udx_ref' / 'windows_pipe.py').read_text(encoding='utf-8')
        for needle in ('        self.sddl = build_sddl(self.server_sid, self._own_integrity)\n',
                       '    own_rid, err = effective_integrity_rid(api)\n',
                       "            reason, err, label = _verify_pipe_label(api, h, own_rid)\n",
                       "    if type(own_rid) is not int or rid != own_rid:\n"
                       "        return 'PIPE_LABEL_MISMATCH', 0, rid\n"):
            self.assertEqual(src.count(needle), 1, needle)
        body = src[src.index('def client_ping('):src.index('def main(')]
        self.assertLess(body.index('effective_integrity_rid(api)'), body.index('api.CreateFileW('))
        init = src[src.index('class OneShotPipeServer'):src.index('def __del__')]
        self.assertLess(init.index('build_sddl(self.server_sid, self._own_integrity)'),
                        init.index('ConvertStringSidToSidW'))


def _patch_own_level(api, rid):
    """Every TokenIntegrityLevel read on this api object reports ``rid`` (the
    client's own-level seam; the pipe's kernel label stays real)."""
    real = api.GetTokenInformation

    def gti(tok, k, buf, size, req):
        rv = real(tok, k, buf, size, req)
        if rv and k == wp.TokenIntegrityLevel and buf is not None:
            sid = ctypes.c_void_p.from_buffer(buf, 0).value
            count = api.GetSidSubAuthorityCount(sid).contents.value
            api.GetSidSubAuthority(sid, count - 1).contents.value = rid
        return rv
    api.GetTokenInformation = gti


@unittest.skipUnless(IS_WINDOWS, 'Windows Win32 named pipes required')
class WindowsLabelParity(unittest.TestCase):
    def setUp(self):
        self.api = wp.default_api()
        self.sid = wp.current_user_sid(self.api)
        self.own = wp.own_integrity_rid(self.api)           # REAL token: Medium here, High on the runner
        self.handles = []

    def tearDown(self):
        for h in self.handles:
            self.api.CloseHandle(h)

    def _pipe(self, label: str):
        """A real pipe owned by this user with the given SACL (owner check passes)."""
        name = wp.PIPE_PREFIX + 'UDX_UT602_' + uuid.uuid4().hex
        sd = ctypes.c_void_p()
        self.assertTrue(self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            'O:%sD:(A;;GA;;;%s)%s' % (self.sid, self.sid, label), wp.SDDL_REVISION_1, ctypes.byref(sd), None))
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            h = self.api.CreateNamedPipeW(name, wp.PIPE_ACCESS_DUPLEX | wp.FILE_FLAG_FIRST_PIPE_INSTANCE,
                                          0, 1, 4096, 4096, 0, ctypes.byref(sa))
        finally:
            self.api.LocalFree(sd)
        self.assertNotIn(h, (None, wp.INVALID_HANDLE_VALUE), self.api.last_error())
        self.handles.append(h)
        return name, h

    def _ping_silent(self, name, api=None):
        return wp.client_ping(name, send=False, hold_s=0.0, connect_timeout_s=2.0, api=api)

    # -- negative control: equal levels on both sides, nothing injected --------
    def test_equal_real_levels_pass(self):
        name, h = self._pipe(wp.label_sddl(self.own))
        self.assertEqual(wp.pipe_label_rid(self.api, h), (self.own, 0))      # real kernel label
        self.assertEqual(wp.effective_integrity_rid(self.api), (self.own, 0))  # real token
        r = self._ping_silent(name)
        self.assertEqual((r.reason, r.sent, r.pipe_label), ('SILENT_HOLD', False, None))

    def test_real_server_and_real_client_complete_the_handshake(self):
        with wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_UT602_' + uuid.uuid4().hex) as srv:
            self.assertTrue(srv.sddl.endswith(')' + wp.label_sddl(self.own)))
            box = {}
            t = threading.Thread(target=lambda: box.update(c=wp.client_ping(srv.name)), daemon=True)
            t.start()
            r = srv.serve(3.0)
            t.join(10)
        self.assertEqual((r.verdict, r.reason, box['c'].reason, box['c'].response),
                         ('PEER_OK', 'OK', 'OK', b'PEER_OK'))

    def test_equal_level_through_the_patched_seam_passes(self):
        # positive control for the own-level seam itself
        name, _ = self._pipe(wp.label_sddl(self.own))
        api = wp.WinApi()
        _patch_own_level(api, self.own)
        self.assertEqual(self._ping_silent(name, api).reason, 'SILENT_HOLD')

    # -- the elevated/medium pair, one real side each -------------------------
    def test_client_refuses_a_label_above_its_real_level(self):
        # real client token (Medium here); the pipe reports one level higher
        # (a Medium process cannot create a High label; the label read is injected)
        name, _ = self._pipe(wp.label_sddl(self.own))
        higher = self.own + 0x1000
        with mock.patch.object(wp, 'pipe_label_info', lambda api, h: ((higher, 0, 0x3), 0)):
            r = self._ping_silent(name)
        self.assertEqual((r.reason, r.sent, r.pipe_label), ('PIPE_LABEL_MISMATCH', False, higher))

    def test_client_refuses_a_real_label_below_or_above_its_level(self):
        # real kernel label at the host's level; the client's own level is
        # reported one step higher (elevated client vs Medium server) or lower
        # (on the runner: a Medium client vs the real High label)
        # one fresh single-instance pipe per case: a connected-and-closed
        # instance stays busy until the server end disconnects
        for own in (self.own + 0x1000, self.own - 0x1000, wp.SECURITY_MANDATORY_HIGH_RID + 0x100):
            with self.subTest(own=hex(own)):
                name, _ = self._pipe(wp.label_sddl(self.own))
                api = wp.WinApi()
                _patch_own_level(api, own)
                r = self._ping_silent(name, api)
                self.assertEqual((r.reason, r.sent, r.pipe_label), ('PIPE_LABEL_MISMATCH', False, self.own))

    def test_low_and_untrusted_clients_refuse_a_medium_or_higher_label(self):
        for own in (0x1000, 0x0):                            # Low, Untrusted
            with self.subTest(own=hex(own)):
                name, _ = self._pipe(wp.label_sddl(self.own))
                api = wp.WinApi()
                _patch_own_level(api, own)
                r = self._ping_silent(name, api)
                self.assertEqual((r.reason, r.sent), ('PIPE_LABEL_MISMATCH', False))

    def test_missing_and_low_labels_stay_too_low(self):
        # no SACL at all: the pipe carries no explicit label ACE
        name, _ = self._pipe('')
        self.assertEqual(self._ping_silent(name).reason, 'PIPE_LABEL_TOO_LOW')
        name, _ = self._pipe('S:(ML;;NW;;;LW)')
        self.assertEqual(self._ping_silent(name).reason, 'PIPE_LABEL_TOO_LOW')

    # -- the own level must be readable, else nothing is opened ---------------
    def test_unreadable_own_level_refuses_before_opening(self):
        name, _ = self._pipe(wp.label_sddl(self.own))
        api = wp.WinApi()
        real = api.GetTokenInformation
        opened = []
        real_open = api.CreateFileW

        def gti(tok, k, buf, size, req):
            if k == wp.TokenIntegrityLevel:
                ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
                return 0
            return real(tok, k, buf, size, req)

        def cfw(*a):
            opened.append(a[0])
            return real_open(*a)
        api.GetTokenInformation = gti
        api.CreateFileW = cfw
        r = self._ping_silent(name, api)
        self.assertEqual((r.reason, r.winerror, r.sent, r.open_error), ('OWN_INTEGRITY_FAILED', 5, False, None))
        self.assertEqual(opened, [])

    def test_thread_token_query_failure_is_not_a_fallback(self):
        # Any OpenThreadToken error other than ERROR_NO_TOKEN must not silently
        # fall back to the process level (that would not be the effective level).
        api = wp.WinApi()

        def ott(*a):
            ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
            return 0
        api.OpenThreadToken = ott
        self.assertEqual(wp.effective_integrity_rid(api), (None, wp.ERROR_ACCESS_DENIED))
        name, _ = self._pipe(wp.label_sddl(self.own))
        self.assertEqual(self._ping_silent(name, api).reason, 'OWN_INTEGRITY_FAILED')

    def test_effective_level_is_the_thread_token_when_impersonating(self):
        # REAL kernel tokens: a duplicate of this process token lowered to Low IL
        # is set as the thread token; the effective level must follow it.
        api = self.api
        proc, dup = wp.wintypes.HANDLE(), wp.wintypes.HANDLE()
        self.assertTrue(api.OpenProcessToken(api.GetCurrentProcess(),
                                             wp.TOKEN_QUERY | wp.TOKEN_DUPLICATE, ctypes.byref(proc)))
        try:
            self.assertTrue(api.DuplicateTokenEx(proc, wp.TOKEN_QUERY | wp.TOKEN_IMPERSONATE
                                                 | wp.TOKEN_ADJUST_DEFAULT, None, wp.SecurityImpersonation,
                                                 wp.TokenImpersonation, ctypes.byref(dup)))
        finally:
            api.CloseHandle(proc)
        low = ctypes.c_void_p()
        self.assertTrue(api.ConvertStringSidToSidW('S-1-16-4096', ctypes.byref(low)))
        try:
            tml = wp.SID_AND_ATTRIBUTES(low, wp.SE_GROUP_INTEGRITY)
            self.assertTrue(api.SetTokenInformation(dup, wp.TokenIntegrityLevel, ctypes.byref(tml),
                                                    ctypes.sizeof(tml) + 12))      # S-1-16-4096 = 12 bytes
            box = {}

            def body():
                if not api.SetThreadToken(None, dup):
                    box['err'] = api.last_error()
                    return
                try:
                    box['eff'] = wp.effective_integrity_rid(api)
                finally:
                    box['reverted'] = bool(api.RevertToSelf())
                box['after'] = wp.effective_integrity_rid(api)
            t = threading.Thread(target=body, daemon=True)
            t.start()
            t.join(10)
        finally:
            api.LocalFree(low)
            api.CloseHandle(dup)
        self.assertNotIn('err', box)
        self.assertEqual((box['eff'], box['reverted'], box['after']), ((0x1000, 0), True, (self.own, 0)))

    # -- server: the label is the server's own level -------------------------
    def test_server_with_an_unsupported_own_level_refuses_to_start(self):
        for rid in (0x2100, 0x1000, 0x4000):
            with self.subTest(rid=hex(rid)):
                api = wp.WinApi()
                _patch_own_level(api, rid)
                with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_INTEGRITY_LEVEL'):
                    wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_UT602_' + uuid.uuid4().hex, api=api)

    def test_server_label_is_its_real_own_level(self):
        with wp.OneShotPipeServer(wp.PIPE_PREFIX + 'UDX_UT602_' + uuid.uuid4().hex) as srv:
            self.assertEqual(wp.pipe_label_info(self.api, srv.handle), ((self.own, 0, 0x3), 0))


if __name__ == '__main__':
    unittest.main()
