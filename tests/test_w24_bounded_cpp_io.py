"""W24: bounded overlapped I/O in the C++ candidates (UDX14-04 / UDX-W21-01 / UDX22-01).

Portable part: source guards on windows/*.cpp + udx_bounded_pipe_io.hpp, the
fail-closed verdict of the native harness (tools/w18_cpp_crossrun.py) and the
argument grammar. The native evidence (MSVC /W4 /WX build, stall cases on a real
Windows kernel) comes from the CI job ``cpp-candidate``; these tests are NOT a
substitute for it. A local cross-compile with mingw-w64 runs only if present.
"""
from __future__ import annotations

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
sys.path.insert(0, str(REPO / 'tools'))
try:
    import w18_cpp_crossrun as tool
finally:
    sys.path.pop(0)
from udx_ref import windows_pipe as wp


def _code(path: pathlib.Path) -> str:
    """Source without // comments (comments may name APIs that must not be called)."""
    return '\n'.join(line.split('//', 1)[0] for line in path.read_text(encoding='utf-8').splitlines())


def _calls(code: str, api: str) -> list[str]:
    """Full argument text of every ``api(...)`` call (balanced parentheses)."""
    out = []
    for m in re.finditer(r'\b' + api + r'\(', code):
        depth, i = 1, m.end()
        while depth and i < len(code):
            depth += {'(': 1, ')': -1}.get(code[i], 0)
            i += 1
        out.append(code[m.end():i - 1])
    return out


PROBE = _code(WIN / 'udx_sid_probe.cpp')
CLIENT = _code(WIN / 'udx_sid_client.cpp')
HEADER = _code(WIN / 'udx_bounded_pipe_io.hpp')


class BoundedSourceGuards(unittest.TestCase):
    def test_both_sources_use_the_shared_header(self):
        for code in (PROBE, CLIENT):
            self.assertIn('#include "udx_bounded_pipe_io.hpp"', code)

    def test_no_flush_file_buffers_call(self):
        # FlushFileBuffers on a pipe server waits until the client has read
        # everything: unbounded (W23 PR-4). Mentioned in comments only.
        for code in (PROBE, CLIENT, HEADER):
            self.assertEqual(_calls(code, 'FlushFileBuffers'), [])

    def test_every_pipe_io_call_is_overlapped(self):
        # Each ReadFile/WriteFile/ConnectNamedPipe passes the OVERLAPPED of
        # udx::bounded_io as last argument; a null OVERLAPPED would block.
        for name, code in (('probe', PROBE), ('client', CLIENT)):
            for api in ('ReadFile', 'WriteFile', 'ConnectNamedPipe'):
                for args in _calls(code, api):
                    with self.subTest(file=name, call=api + '(' + args + ')'):
                        self.assertTrue(args.replace(' ', '').endswith(',ov'), args)
            self.assertNotIn('ReadFileEx', code)
        self.assertEqual(len(_calls(PROBE, 'ConnectNamedPipe')), 1)
        self.assertEqual(len(_calls(PROBE, 'ReadFile')), 2)        # request + peer-close drain
        self.assertEqual(len(_calls(PROBE, 'WriteFile')), 1)
        self.assertEqual(len(_calls(CLIENT, 'WriteFile')), 1)
        self.assertEqual(len(_calls(CLIENT, 'ReadFile')), 1)

    def test_handles_are_opened_overlapped(self):
        (create,) = _calls(PROBE, 'CreateNamedPipeW')
        self.assertIn('FILE_FLAG_OVERLAPPED', create)
        self.assertIn('FILE_FLAG_FIRST_PIPE_INSTANCE', create)
        self.assertIn('| FILE_FLAG_OVERLAPPED;', CLIENT)
        (open_call,) = _calls(CLIENT, 'CreateFileW')
        self.assertIn('flags', open_call)

    def test_one_deadline_per_exchange(self):
        # W23 PR-1: one absolute budget across connect, request, reply and close.
        for code in (PROBE, CLIENT):
            self.assertEqual(code.count('const udx::Deadline deadline(budget_ms);'), 1)
            self.assertEqual(len(re.findall(r'udx::Deadline\s+\w+\(', code)), 1)
        self.assertIn('GetTickCount64()', HEADER)                   # monotonic
        self.assertNotIn('GetTickCount()', HEADER)                  # 32-bit, wraps after 49.7 days

    def test_cancel_waits_for_completion_and_never_blocks_unbounded(self):
        self.assertIn('CancelIoEx(handle, &ov);', HEADER)
        self.assertLess(HEADER.index('CancelIoEx(handle, &ov);'),
                        HEADER.index('GetOverlappedResultEx(handle, &ov, &n, kCancelGraceMs, FALSE)'))
        self.assertNotIn('INFINITE', HEADER)
        self.assertEqual(_calls(HEADER, 'GetOverlappedResult'), [])  # bWait=TRUE could block forever
        for args in _calls(HEADER, 'GetOverlappedResultEx'):
            self.assertTrue(args.replace(' ', '').endswith(',FALSE'), args)   # not alertable
        # Uncertain cancellation: the process ends, the stack frame is never released.
        self.assertIn('TerminateProcess(GetCurrentProcess(), kExitCancelUncertain);', HEADER)
        self.assertIn('[[noreturn]] inline void die_cancel_uncertain()', HEADER)

    def test_cancel_path_never_reports_success_and_dies_when_unsettled(self):
        start = HEADER.index('inline IoResult cancel_and_settle(')
        body = HEADER[start:HEADER.index('inline IoResult await_completion(')]
        # W23: an I/O that completed in the cancel race is still a timeout.
        self.assertNotIn('IoStatus::ok', body)
        self.assertNotIn('IoStatus::failure', body)
        # Still pending after the grace -> the process ends; it never returns.
        self.assertIn('if (err == WAIT_TIMEOUT || err == ERROR_IO_INCOMPLETE || !HasOverlappedIoCompleted(&ov))\n'
                      '        die_cancel_uncertain();', body)
        # A failed wait with the I/O still pending must go through the cancel path.
        wait = HEADER[HEADER.index('inline IoResult await_completion('):HEADER.index('template <class Start>')]
        self.assertIn('if (HasOverlappedIoCompleted(&ov)) return {IoStatus::failure, n, err};\n'
                      '            return cancel_and_settle(handle, ov);', wait)
        self.assertIn('if (deadline.expired()) return cancel_and_settle(handle, ov);', wait)

    def test_constants_match_python_lane_and_harness(self):
        def const(name):
            m = re.search(r'constexpr (?:DWORD|int) ' + name + r' = (\d+);', HEADER)
            self.assertIsNotNone(m, name)
            return int(m.group(1))
        self.assertEqual(const('kCancelGraceMs'), wp.CANCEL_GRACE_MS)
        self.assertEqual(const('kMaxBudgetMs'), int(wp.MAX_DEADLINE_S * 1000))
        self.assertEqual(const('kExitTimeout'), tool.EXIT_TIMEOUT)
        self.assertEqual(const('kExitPeerNotClosed'), tool.EXIT_PEER_NOT_CLOSED)
        self.assertEqual(const('kExitBadArguments'), tool.EXIT_BAD_ARGUMENTS)
        self.assertEqual(const('kExitCancelUncertain'), 31)
        self.assertEqual(tool.reference_parse_budget([]), const('kDefaultBudgetMs'))
        self.assertEqual(tool.reference_parse_budget(['--budget-ms', str(const('kMinBudgetMs'))]),
                         const('kMinBudgetMs'))
        # Exit codes do not collide with the existing ones (20, 21, 30, 10-15).
        self.assertFalse({22, 23, 24, 31} & {10, 11, 12, 13, 14, 15, 20, 21, 30})

    def test_server_writes_peer_ok_only_after_authorization_and_deadline_check(self):
        auth = PROBE.index('if (!authorized) {')
        late = PROBE.index('if (deadline.expired())')
        (write,) = [m.start() for m in re.finditer(r'\bWriteFile\(', PROBE)]
        self.assertLess(auth, late)
        self.assertLess(late, write)
        self.assertLess(PROBE.index('RevertToSelf()'), write)

    def test_peer_closed_requires_eof_not_data(self):
        self.assertIn('drain.status == udx::IoStatus::failure', PROBE)
        self.assertIn('(drain.error == ERROR_BROKEN_PIPE || drain.error == ERROR_NO_DATA)', PROBE)
        self.assertIn('return peer_closed ? 0 : udx::kExitPeerNotClosed;', PROBE)

    def test_parse_happens_before_any_pipe_object_exists(self):
        self.assertLess(PROBE.index('udx::parse_budget(argc, argv, budget_ms)'), PROBE.index('CreateNamedPipeW('))
        self.assertLess(CLIENT.index('udx::parse_budget(argc, argv, budget_ms)'), CLIENT.index('CreateFileW('))

    def test_client_open_retry_is_bounded(self):
        loop = CLIENT[CLIENT.index('for (;;) {'):CLIENT.index('PSID owner = nullptr;')]
        self.assertIn('deadline.expired()', loop)
        self.assertIn('ERROR_FILE_NOT_FOUND', loop)
        self.assertIn('ERROR_PIPE_BUSY', loop)


class HarnessVerdict(unittest.TestCase):
    def test_stall_verdict_is_fail_closed(self):
        lim = tool.STALL_LIMIT_S
        self.assertTrue(tool.stall_verdict(22, 1.6, 22))
        self.assertTrue(tool.stall_verdict(23, lim, 23))
        for code, elapsed, expected in [
                (22, lim + 0.001, 22),          # too slow: exited because the holder let go
                (20, 1.6, 22),                  # W20 behaviour after the holder closed
                (0, 1.6, 22), (23, 1.6, 22), (22, 1.6, 23),
                (None, 1.6, 22),                # harness had to kill it
                (True, 1.6, 1), (22.0, 1.6, 22), ('22', 1.6, 22),
                (22, -0.1, 22), (22, math.nan, 22), (22, math.inf, 22), (22, None, 22), (22, '1', 22)]:
            with self.subTest(code=code, elapsed=elapsed, expected=expected):
                self.assertFalse(tool.stall_verdict(code, elapsed, expected))

    def test_timing_margins_separate_bounded_from_holder_release(self):
        budget_s = tool.STALL_BUDGET_MS / 1000
        grace_s = wp.CANCEL_GRACE_MS / 1000
        self.assertLess(budget_s + grace_s, tool.STALL_LIMIT_S)       # a bounded binary fits
        self.assertLess(tool.STALL_LIMIT_S + 2.0, tool.HOLD_S)        # waiting for the holder never fits
        self.assertLess(tool.HOLD_S, tool.TIMEOUT_S)

    def test_all_cases_pass_requires_exact_set(self):
        good = {k: {'ok': True} for k in tool.EXPECTED_CASES}
        self.assertTrue(tool.all_cases_pass(good))
        self.assertEqual(len(tool.EXPECTED_CASES), 11)
        missing = dict(good)
        missing.pop('cpp_server_drain_stall')
        extra = dict(good, bonus={'ok': True})
        failed = dict(good, cpp_client_silent_server={'ok': False})
        truthy = dict(good, cpp_server_read_stall={'ok': 1})
        for bad in (missing, extra, failed, truthy, {}, None, [], dict(good, cpp_bad_arguments=None)):
            with self.subTest(bad=bad if not isinstance(bad, dict) else sorted(set(good) ^ set(bad))):
                self.assertFalse(tool.all_cases_pass(bad))

    def test_reference_parser_rejects_every_bad_argument_vector(self):
        for args in tool.BAD_ARGUMENTS:
            with self.subTest(args=args):
                self.assertIsNone(tool.reference_parse_budget(list(args)))
        for args, ms in ((['--budget-ms', '100'], 100), (['--budget-ms', '300000'], 300000),
                         (['--budget-ms', str(tool.STALL_BUDGET_MS)], tool.STALL_BUDGET_MS)):
            self.assertEqual(tool.reference_parse_budget(args), ms)
        for bad in (None, ('--budget-ms', '1500'), ['--budget-ms', 1500], ['--budget-ms', '１５００'],
                    ['--budget-ms', ' 1500'], ['--BUDGET-MS', '1500']):
            self.assertIsNone(tool.reference_parse_budget(bad))


class DocumentationDrift(unittest.TestCase):
    """W21 N1 / UDX-W21-02 / UDX22-04: no current document may repeat superseded
    status claims; historical snapshots stay, but are marked as such."""

    def _read(self, rel):
        return (REPO / rel).read_text(encoding='utf-8')

    def test_security_policy_has_no_superseded_claims(self):
        s = self._read('SECURITY.md')
        for stale in ('have never been compiled', 'no second-account', 'current wave W20'):
            self.assertNotIn(stale, s)
        self.assertIn('G2-App remains FAIL/OPEN', s)
        self.assertIn('Same user SID is\nnot the same application identity', s)

    def test_historical_gate_files_are_marked(self):
        for rel in ('docs/NEXT_GATES.md', 'docs/W5_RELEASE_GATES.md'):
            head = self._read(rel)[:600]
            self.assertIn('Historical snapshot', head, rel)
            self.assertIn('No gate was set to PASS\n> retroactively.', head, rel)
        # The W5 table itself is not rewritten: G2-App and G2-Windows stay FAIL/OPEN there.
        w5 = self._read('docs/W5_RELEASE_GATES.md')
        self.assertIn('| G2-App security | OS-enforced *application* identity for same UID | none | FAIL/OPEN |', w5)

    def test_adr_links_the_open_product_gate(self):
        adr = self._read('docs/ADR-UDX-006.md')
        self.assertIn('G2-App remains FAIL/OPEN', adr)
        self.assertIn('out of scope for\n> research, not fixed for a product', adr)

    def test_version_is_consistent(self):
        cff = re.search(r'^version: "([0-9.]+)"$', self._read('CITATION.cff'), re.M).group(1)
        # W25: the wave number follows the version minor (0.25.0 -> W25), so the
        # check no longer pins W24; README, SECURITY.md and CITATION.cff must agree.
        wave = 'W%d' % int(cff.split('.')[1])
        self.assertIn('Current wave: %s (version %s)' % (wave, cff), self._read('README.md'))
        self.assertIn('current wave %s, %s' % (wave, cff), self._read('SECURITY.md'))


MINGW = shutil.which('x86_64-w64-mingw32-g++')


@unittest.skipUnless(MINGW, 'mingw-w64 not installed (optional local type check; CI uses MSVC natively)')
class OptionalCrossCompile(unittest.TestCase):
    def test_sources_compile_warning_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            for src in ('udx_sid_probe.cpp', 'udx_sid_client.cpp'):
                with self.subTest(src=src):
                    r = subprocess.run([MINGW, '-std=c++17', '-municode', '-Wall', '-Wextra', '-Werror',
                                        '-Wconversion', '-Wshadow', '-Wno-unknown-pragmas', '-o',
                                        str(pathlib.Path(tmp) / (src + '.exe')), str(WIN / src), '-ladvapi32'],
                                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
                    self.assertEqual(r.returncode, 0, r.stderr[-2000:])


if __name__ == '__main__':
    unittest.main()
