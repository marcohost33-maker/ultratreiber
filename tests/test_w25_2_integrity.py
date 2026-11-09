"""Aegis W25.2-P2: the server requires the client's integrity level to EQUAL its own.

ADR-UDX-006 section 1: same SID AND same integrity level is one trust domain.
Up to W25.2 both servers only required ">= Medium", so a client ABOVE the
server's level (e.g. an elevated client and a Medium server) was accepted.

Kept out of tests/test_w12_windows_pipe.py on purpose: that file's bytes are
pinned to the reviewed W14 source (tools/w15_windows_evidence.py,
PINNED_NATIVE_TEST_SHA256, EXPECTED_NATIVE_COUNT = 47).
"""
from __future__ import annotations

import ctypes
import sys
import threading
import unittest
import uuid

from udx_ref import windows_pipe as wp

IS_WINDOWS = sys.platform == 'win32'


def _name() -> str:
    return wp.PIPE_PREFIX + 'UDX_W252I_' + uuid.uuid4().hex


def _serve_with_client(srv, deadline):
    box = {}
    t = threading.Thread(target=lambda: box.update(r=wp.client_ping(srv.name)), daemon=True)
    t.start()
    r = srv.serve(deadline)
    t.join(10)
    return r, box.get('r')


@unittest.skipUnless(IS_WINDOWS, 'Windows Win32 named pipes required')
class ServerIntegrityEquality(unittest.TestCase):
    def _patch_integrity(self, api, rid):
        """Every TokenIntegrityLevel read on this api object reports ``rid``."""
        real = api.GetTokenInformation

        def gti(tok, k, buf, size, req):
            rv = real(tok, k, buf, size, req)
            if rv and k == wp.TokenIntegrityLevel and buf is not None:
                sid = ctypes.c_void_p.from_buffer(buf, 0).value
                count = api.GetSidSubAuthorityCount(sid).contents.value
                api.GetSidSubAuthority(sid, count - 1).contents.value = rid
            return rv
        api.GetTokenInformation = gti

    def _serve(self, client_rid):
        api = wp.WinApi()                                  # fresh; the module default is never mutated
        srv = wp.OneShotPipeServer(_name(), api=api)      # own level read BEFORE patching
        self._patch_integrity(api, client_rid)
        with srv:
            r, c = _serve_with_client(srv, 3.0)
        self.assertFalse(wp.thread_is_impersonating(wp.default_api()))
        return r, c

    def test_equal_integrity_is_served(self):
        # positive control for the same seam: the patched read path itself serves
        r, c = self._serve(wp.own_integrity_rid())
        self.assertEqual((r.verdict, r.reason, c.response), ('PEER_OK', 'OK', b'PEER_OK'))

    def test_higher_integrity_token_denied(self):
        # +0x100 is above the own RID on every host (Medium 0x2000 -> 0x2100, High 0x3000 -> 0x3100)
        r, c = self._serve(wp.own_integrity_rid() + 0x100)
        self.assertEqual((r.verdict, r.reason, r.response_sent), ('DENIED', 'INTEGRITY_MISMATCH', False))
        self.assertEqual(c.response, b'')

    def test_below_medium_keeps_its_reason(self):
        r, _ = self._serve(0x1000)
        self.assertEqual((r.verdict, r.reason), ('DENIED', 'INTEGRITY_TOO_LOW'))

    def test_server_without_own_integrity_refuses_to_start(self):
        # fail-closed: no server whose own integrity level is unknown
        api = wp.WinApi()
        real = api.GetTokenInformation

        def gti(tok, k, buf, size, req):
            if k == wp.TokenIntegrityLevel:
                ctypes.set_last_error(wp.ERROR_ACCESS_DENIED)
                return 0
            return real(tok, k, buf, size, req)
        api.GetTokenInformation = gti
        with self.assertRaises(OSError):
            wp.OneShotPipeServer(_name(), api=api)


if __name__ == '__main__':
    unittest.main()
