"""W30: C++ cancel path (exit 31, completion in the race) and boundary race campaigns.

Portable part: (1) the production token stream of windows/udx_bounded_pipe_io.hpp
is identical to the W24 header once the test-only fault-injection blocks are
removed, i.e. the shipped code did not change; (2) the fault-injection hooks
exist only inside those blocks and only in the header; (3) the fail-closed
verdicts of tools/w30_cpp_cancel_race.py. Native evidence: CI job
``cpp-candidate``, step "Cancel path + race campaigns". A local cross-compile of
all three variants runs only if mingw-w64 is installed.
"""
from __future__ import annotations

import hashlib
import math
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
WIN = REPO / 'windows'
HEADER_PATH = WIN / 'udx_bounded_pipe_io.hpp'
sys.path.insert(0, str(REPO / 'tools'))
try:
    import w30_cpp_cancel_race as tool
    import w18_cpp_crossrun as w18
finally:
    sys.path.pop(0)

# sha256 of production_tokens() of the W24 header (ed6a7c1, blob unchanged until
# W30). If the shipped code changes on purpose, this pin must change with it.
W24_PRODUCTION_TOKENS_SHA256 = '5be8c38b9f48f9bb022d6919f20681b563a2067969ea3048d7ca02db09e37779'
FI_GUARDS = ('UDX_FI_', 'UDX_FAULT_INJECTION_BUILD')


def production_tokens(text: str) -> str:
    """The header as a production build sees it: // comments dropped, every
    #if/#else/#endif block whose condition names a fault-injection macro reduced
    to its #else branch (or nothing), whitespace collapsed. Other directives are
    kept verbatim. Nested blocks are handled with a stack."""
    out, stack = [], []
    for raw in text.splitlines():
        st = raw.split('//', 1)[0].strip()
        if st.startswith('#if'):
            fi = any(g in st for g in FI_GUARDS)
            stack.append([fi, False])
            if not fi:
                out.append(st)
            continue
        if st.startswith('#else') and stack:
            stack[-1][1] = True
            if not stack[-1][0]:
                out.append(st)
            continue
        if st.startswith('#endif') and stack:
            fi, _ = stack.pop()
            if not fi:
                out.append(st)
            continue
        if all((not fi) or in_else for fi, in_else in stack):
            out.append(st)
    return re.sub(r'\s+', ' ', ' '.join(x for x in out if x)).strip()


HEADER = HEADER_PATH.read_text(encoding='utf-8')


class ProductionCodeUnchanged(unittest.TestCase):
    def test_production_token_stream_equals_w24(self):
        digest = hashlib.sha256(production_tokens(HEADER).encode()).hexdigest()
        self.assertEqual(digest, W24_PRODUCTION_TOKENS_SHA256)

    def test_no_fault_injection_symbol_survives_in_production(self):
        prod = production_tokens(HEADER)
        for symbol in ('UDX_FI_', 'fi_mark', 'FaultInjectionBanner', 'Sleep(', 'fputs', 'cstdio'):
            self.assertNotIn(symbol, prod)
        self.assertIn('CancelIoEx(handle, &ov);', prod)

    def test_stripper_is_not_vacuous(self):
        # Control: with the FI guards treated as ordinary #if, the stream differs,
        # so the pin above really depends on removing those blocks.
        self.assertNotEqual(production_tokens(HEADER), re.sub(r'\s+', ' ', ' '.join(
            line.split('//', 1)[0].strip() for line in HEADER.splitlines())).strip())
        self.assertIn('Sleep(UDX_FI_PRE_CANCEL_SLEEP_MS);', HEADER)
        self.assertIn('fi_mark("UDX_FI_CANCEL_SKIPPED");', HEADER)

    def test_sources_and_ci_never_define_fault_injection(self):
        for name in ('udx_sid_probe.cpp', 'udx_sid_client.cpp'):
            self.assertNotIn('UDX_FI', (WIN / name).read_text(encoding='utf-8'), name)
        self.assertNotIn('/D', w18.CL_FLAGS)
        self.assertEqual(tool.CL_FLAGS, w18.CL_FLAGS)
        self.assertEqual(tool.VARIANTS['production'], '')
        ci = (REPO / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        self.assertNotIn('UDX_FI', ci)
        self.assertIn('python tools/w30_cpp_cancel_race.py', ci)

    def test_fault_injection_announces_itself(self):
        self.assertIn('static const FaultInjectionBanner fault_injection_banner;', HEADER)
        self.assertIn('fi_mark("UDX_FAULT_INJECTION_BUILD")', HEADER)
        self.assertEqual(tool.BANNER, 'UDX_FAULT_INJECTION_BUILD')
        # Markers named by the tool are the ones the header prints.
        for marker in ('UDX_FI_CANCEL_SKIPPED', 'UDX_FI_DIE_CANCEL_UNCERTAIN',
                       'UDX_FI_COMPLETED_IN_RACE bytes>0', 'UDX_FI_COMPLETED_IN_RACE bytes=0'):
            self.assertIn(marker, HEADER)
            self.assertIn(marker, tool.FI_MARKERS)

    def test_fi_sleep_matches_harness_timing(self):
        m = re.search(r"'/DUDX_FI_PRE_CANCEL_SLEEP_MS=(\d+)'", (REPO / 'tools' / 'w30_cpp_cancel_race.py').read_text())
        self.assertEqual(int(m.group(1)) / 1000, tool.FI_SLEEP_S)
        # The race cases send at 1.75 s with a 1.0 s budget: after the deadline,
        # before the cancel at budget + FI sleep, with >= 0.5 s margin each side.
        self.assertGreaterEqual(1.75 - 1.0, 0.5)
        self.assertGreaterEqual(1.0 + tool.FI_SLEEP_S - 1.75, 0.5)


class Verdicts(unittest.TestCase):
    OK_ERR = 'UDX_FAULT_INJECTION_BUILD\nUDX_FI_CANCEL_SKIPPED\nUDX_FI_DIE_CANCEL_UNCERTAIN\n'
    RACE_ERR = 'UDX_FAULT_INJECTION_BUILD\nUDX_FI_COMPLETED_IN_RACE bytes>0\n'

    def test_markers_are_whole_lines(self):
        self.assertTrue(tool.markers_ok('a\nUDX_X\n', ('UDX_X',)))
        self.assertFalse(tool.markers_ok('prefix UDX_X\n', ('UDX_X',)))
        self.assertFalse(tool.markers_ok('UDX_X\nUDX_Y\n', ('UDX_X',), ('UDX_Y',)))
        self.assertFalse(tool.markers_ok(None, ()))

    def test_exit31_verdict(self):
        self.assertTrue(tool.exit31_verdict(31, 1.85, self.OK_ERR, 0.8))
        for code, t, err in [(22, 1.85, self.OK_ERR),                  # cancel worked (production-like)
                             (31, 0.9, self.OK_ERR),                   # grace not waited
                             (31, tool.LIMIT_S + 0.1, self.OK_ERR),    # unbounded
                             (31, 1.85, 'UDX_FAULT_INJECTION_BUILD\n'),  # died for another reason
                             (None, 1.85, self.OK_ERR), (True, 1.85, self.OK_ERR),
                             (31, math.nan, self.OK_ERR), (31, -1, self.OK_ERR)]:
            with self.subTest(code=code, t=t):
                self.assertFalse(tool.exit31_verdict(code, t, err, 0.8))

    def test_race_verdict(self):
        self.assertTrue(tool.race_verdict(22, 2.6, self.RACE_ERR, b''))
        for code, err, rec in [(0, self.RACE_ERR, b'PEER_OK'),          # race completion taken as success
                               (22, self.RACE_ERR, b'PEER_OK'),
                               (22, 'UDX_FAULT_INJECTION_BUILD\n', b''),  # race branch not reached
                               (22, self.RACE_ERR.replace('bytes>0', 'bytes=0'), b''),
                               (22, self.RACE_ERR + 'UDX_FI_DIE_CANCEL_UNCERTAIN\n', b''),
                               (22, self.RACE_ERR, 'x'), (None, self.RACE_ERR, b'')]:
            with self.subTest(code=code, rec=rec):
                self.assertFalse(tool.race_verdict(code, 2.6, err, rec))

    def test_server_run_oracle(self):
        b = 0.4
        self.assertTrue(tool.server_run_ok(0.05, b, 0, 0.1, b'PEER_OK'))
        self.assertTrue(tool.server_run_ok(0.75, b, 22, 0.4, b''))
        self.assertTrue(tool.server_run_ok(0.41, b, 23, 0.4, b'PEER_OK'))   # inside the band
        self.assertTrue(tool.server_run_ok(0.39, b, 22, 0.4, b''))          # inside the band
        for args in [(0.05, b, 22, 0.4, b''),            # early ping must be served
                     (0.75, b, 0, 0.8, b'PEER_OK'),      # late ping must be refused
                     (0.75, b, 23, 0.8, b'PEER_OK'),
                     (0.3, b, 0, 0.3, b''),              # 0 without delivery
                     (0.5, b, 22, 0.4, b'PEER_OK'),      # PEER_OK after the deadline
                     (0.3, b, 0, 0.3, b'PEER'),          # fragment
                     (0.41, b, 23, 0.4, b'PEER'),        # fragment, in the band
                     (0.3, b, 31, 1.4, b''), (0.3, b, None, 20.0, b''),
                     (0.3, b, 0, tool.LIMIT_S + 1, b'PEER_OK'), (0.3, b, 0, 0.3, 'PEER_OK')]:
            with self.subTest(args=args):
                self.assertFalse(tool.server_run_ok(*args))

    def test_client_run_oracle(self):
        b = 0.4
        self.assertTrue(tool.client_run_ok(0.1, b, 0, 0.2))
        self.assertTrue(tool.client_run_ok(1.1, b, 22, 0.5))
        self.assertTrue(tool.client_run_ok(0.6, b, 0, 0.6))     # inside the band: either
        self.assertTrue(tool.client_run_ok(0.6, b, 22, 0.5))
        for args in [(0.1, b, 22, 0.5), (1.1, b, 0, 1.2), (0.6, b, 3, 0.5), (0.6, b, 31, 1.5),
                     (0.6, b, None, 20.0), (0.6, b, 0, tool.LIMIT_S + 1)]:
            with self.subTest(args=args):
                self.assertFalse(tool.client_run_ok(*args))

    def test_campaign_requires_both_sides_and_exact_count(self):
        good = [{'exit': 0, 'ok': True}] * 50 + [{'exit': 22, 'ok': True}] * 50
        self.assertTrue(tool.campaign_verdict(good, 100, (0, 22)))
        one_sided = [{'exit': 0, 'ok': True}] * 95 + [{'exit': 22, 'ok': True}] * 5
        self.assertFalse(tool.campaign_verdict(one_sided, 100, (0, 22)))
        self.assertFalse(tool.campaign_verdict(good[:99], 100, (0, 22)))
        self.assertFalse(tool.campaign_verdict(good[:-1] + [{'exit': 22, 'ok': False}], 100, (0, 22)))
        self.assertFalse(tool.campaign_verdict(good[:-1] + [{'exit': 31, 'ok': True}], 100, (0, 22)))
        self.assertFalse(tool.campaign_verdict(None, 100, (0, 22)))

    def test_seeded_offsets_cover_both_forced_zones(self):
        b = tool.CAMPAIGN_BUDGET_MS / 1000
        srv = tool.campaign_offsets()
        cli = tool.campaign_offsets(tool.CAMPAIGN_SEED + 1, bounds=tool.CLIENT_OFFSETS_S)
        self.assertEqual(srv, tool.campaign_offsets())          # deterministic
        self.assertEqual(len(srv), tool.CAMPAIGN_RUNS)
        self.assertGreaterEqual(sum(x <= b - tool.GUARD_S for x in srv), tool.MIN_PER_SIDE)
        self.assertGreaterEqual(sum(x >= b + tool.GUARD_S for x in srv), tool.MIN_PER_SIDE)
        self.assertGreaterEqual(sum(x <= b - tool.GUARD_S for x in cli), tool.MIN_PER_SIDE)
        self.assertGreaterEqual(sum(x >= b + tool.CLIENT_LATE_S for x in cli), tool.MIN_PER_SIDE)

    def test_all_cases_pass_exact(self):
        good = {k: {'ok': True} for k in tool.EXPECTED_CASES}
        self.assertTrue(tool.all_cases_pass(good))
        self.assertFalse(tool.all_cases_pass(dict(good, extra={'ok': True})))
        self.assertFalse(tool.all_cases_pass({k: v for k, v in good.items() if k != 'fi_banner'}))
        self.assertFalse(tool.all_cases_pass(dict(good, fi_controls={'ok': 1})))

    def test_non_windows_refuses_without_claim(self):
        if sys.platform == 'win32':
            self.skipTest('non-Windows path only')
        import contextlib
        import io
        import json
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = tool.main([])
        report = json.loads(buf.getvalue())
        self.assertEqual((code, report['verdict'], report['release_authorized']),
                         (2, 'NATIVE_WINDOWS_REQUIRED', False))


MINGW = shutil.which('x86_64-w64-mingw32-g++')


@unittest.skipUnless(MINGW, 'mingw-w64 not installed (optional local type check; CI uses MSVC natively)')
class OptionalCrossCompileAllVariants(unittest.TestCase):
    def test_every_variant_compiles_warning_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            for variant, define in tool.VARIANTS.items():
                for src in ('udx_sid_probe.cpp', 'udx_sid_client.cpp'):
                    args = [MINGW, '-std=c++17', '-municode', '-Wall', '-Wextra', '-Werror', '-Wconversion',
                            '-Wshadow', '-Wno-unknown-pragmas']
                    if define:
                        args.append('-D' + define[len('/D'):])
                    args += ['-o', str(pathlib.Path(tmp) / (variant + src + '.exe')), str(WIN / src), '-ladvapi32']
                    with self.subTest(variant=variant, src=src):
                        r = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                           timeout=300)
                        self.assertEqual(r.returncode, 0, r.stderr[-2000:])


if __name__ == '__main__':
    unittest.main()
