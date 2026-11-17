"""W27 (UDX14-06): the fd-handoff demo separates process start-up from the
protocol exchange. Each test injects one fault into the child and requires the
typed outcome of exactly that phase.

The measured cause of the flake is in ``evidence/W27_FD_HANDOFF_LOAD.json``:
start-up time of the child interpreter was charged to the 2 s protocol timeout.
"""
import json, pathlib, subprocess, sys, time, unittest

from udx_ref.fd_handoff import supported

REPO = pathlib.Path(__file__).resolve().parent.parent
DEMO = REPO / 'tools' / 'demo_w8_fd_handoff.py'
PROTOCOL_TIMEOUT_S = 2.0          # udx_ref.fd_handoff.private_pair, unchanged by W27
HANG_GUARD_S = 60                 # outer bound only; a hang is reported as a failure, not as an error


@unittest.skipUnless(supported(), 'Linux SCM_RIGHTS / seqpacket required')
class StartupIsNotChargedToTheProtocol(unittest.TestCase):
    def demo(self, *args):
        started = time.monotonic()
        try:
            r = subprocess.run([sys.executable, str(DEMO), *args], cwd=str(REPO), capture_output=True,
                               text=True, timeout=HANG_GUARD_S)
        except subprocess.TimeoutExpired:
            self.fail(f'demo did not return within {HANG_GUARD_S} s: {args}')
        elapsed = time.monotonic() - started
        try:
            out = json.loads(r.stdout)
        except ValueError:
            self.fail(f'no JSON line on stdout (exit {r.returncode}): {r.stdout[:200]!r} {r.stderr[-300:]!r}')
        return r.returncode, out, elapsed

    def test_private_pair_keeps_its_two_second_timeout(self):
        from udx_ref.fd_handoff import private_pair
        a, b = private_pair()
        try:
            self.assertEqual((a.gettimeout(), b.gettimeout()), (PROTOCOL_TIMEOUT_S, PROTOCOL_TIMEOUT_S))
        finally:
            a.close(); b.close()

    def test_adopted_descriptor_is_nonblocking_although_python_reports_blocking(self):
        # OS fact behind the second W27 finding: settimeout() sets O_NONBLOCK on the
        # shared open file description; an adopted socket object does not show it.
        import os, socket
        from udx_ref.fd_handoff import private_pair
        a, b = private_pair()
        adopted = socket.socket(fileno=os.dup(b.fileno()))
        try:
            self.assertIsNone(adopted.gettimeout())
            with self.assertRaises(BlockingIOError):
                adopted.recv(1)
            adopted.settimeout(0.2)
            with self.assertRaises(TimeoutError):
                adopted.recv(1)
        finally:
            adopted.close(); a.close(); b.close()

    def test_child_waits_for_a_parent_that_sends_late(self):
        # Without its own timeout the child dies with BlockingIOError as soon as it
        # looks at the empty queue; the parent then reports PROTOCOL_BrokenPipeError.
        code, out, _ = self.demo('--parent-send-delay', '0.5', '--lifecycle')
        self.assertEqual(code, 0, out)
        self.assertEqual((out.get('child_exit'), out.get('fixture_only')), (0, True))
        self.assertGreaterEqual(out['phases_ms']['protocol_ms'], 500.0)

    def test_slow_child_start_is_not_charged_to_the_protocol_timeout(self):
        # 2.3 s start-up > 2.0 s protocol timeout: the pre-W27 parent failed here
        # with "TimeoutError: timed out" in recv_status.
        code, out, _ = self.demo('--child-start-delay', '2.3', '--lifecycle')
        self.assertEqual(code, 0, out)
        self.assertEqual((out.get('child_exit'), out.get('fixture_only')), (0, True))
        self.assertGreaterEqual(out['phases_ms']['startup_ms'], 2300.0)
        self.assertLess(out['phases_ms']['protocol_ms'], PROTOCOL_TIMEOUT_S * 1000)

    def test_child_that_never_becomes_ready_is_typed_bounded_and_reaped(self):
        code, out, elapsed = self.demo('--child-start-delay', '8', '--startup-budget', '0.4')
        self.assertEqual(code, 3, out)
        self.assertEqual((out.get('error'), out.get('phase'), out.get('child_reaped')),
                         ('CHILD_NOT_READY', 'startup', True))
        self.assertNotIn('result', out)
        self.assertLess(elapsed, 6.0)         # below the 8 s the child would have slept

    def test_child_that_exits_before_ready_is_not_reported_as_ready(self):
        code, out, _ = self.demo('--child-fault', 'exit_before_ready')
        self.assertEqual(code, 4, out)
        self.assertEqual((out.get('error'), out.get('phase')), ('CHILD_EXITED_BEFORE_READY', 'startup'))
        self.assertNotIn('result', out)

    def test_ready_but_silent_child_still_hits_the_two_second_protocol_timeout(self):
        # Positive control for the protocol timeout: readiness must not make the
        # exchange unbounded, and the bound must still be the library's 2 s.
        code, out, elapsed = self.demo('--child-fault', 'ready_then_silent')
        self.assertEqual(code, 5, out)
        self.assertEqual((out.get('error'), out.get('phase'), out.get('child_reaped')),
                         ('PROTOCOL_TIMEOUT', 'protocol', True))
        self.assertGreaterEqual(elapsed, PROTOCOL_TIMEOUT_S)
        self.assertLess(elapsed, 15.0)        # far below the 30 s the child would have slept

    def test_fault_injection_arguments_are_bounded(self):
        for bad in (['--child-start-delay', '-1'], ['--child-start-delay', 'nan'],
                    ['--child-start-delay', '31'], ['--startup-budget', '0'],
                    ['--startup-budget', 'inf'], ['--child-fault', 'kill_parent'],
                    ['--parent-send-delay', '1.5'], ['--parent-send-delay', '-0.1']):
            with self.subTest(bad=bad):
                r = subprocess.run([sys.executable, str(DEMO), *bad], cwd=str(REPO), capture_output=True,
                                   text=True, timeout=HANG_GUARD_S)
                self.assertEqual(r.returncode, 2, r.stderr[-200:])
                self.assertEqual(r.stdout, '')


class LoadToolPureParts(unittest.TestCase):
    """tools/w27_fd_handoff_load.py: classification and summary (portable)."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(REPO / 'tools'))
        try:
            import w27_fd_handoff_load
        finally:
            sys.path.pop(0)
        cls.tool = w27_fd_handoff_load

    def test_failure_classes(self):
        c = self.tool.classify
        self.assertEqual(c(0, '{"child_exit": 0}', ''), 'OK')
        self.assertEqual(c(3, '{"error": "CHILD_NOT_READY"}', ''), 'CHILD_NOT_READY')
        self.assertEqual(c(1, '', 'Traceback ...\nTimeoutError: timed out\n'), 'TimeoutError')
        self.assertEqual(c(1, '', 'BlockingIOError: [Errno 11]'), 'BlockingIOError')
        self.assertEqual(c(1, 'not json', 'something else'), 'OTHER')
        self.assertEqual(c(1, '{"error": ""}', ''), 'OTHER')
        self.assertEqual(c(None, '', ''), 'RUN_GUARD_TIMEOUT')

    def test_summary_counts_failures_and_runs_over_the_old_test_timeout(self):
        runs = [{'wall_s': 1.0, 'class': 'OK', 'phases_ms': {'startup_ms': 10.0, 'protocol_ms': 1.0}},
                {'wall_s': 6.0, 'class': 'TimeoutError'},
                {'wall_s': 5.5, 'class': 'OK', 'phases_ms': {'startup_ms': 30.0, 'protocol_ms': 3.0}}]
        out = self.tool.summarize(runs)
        self.assertEqual((out['runs'], out['failed'], out['over_old_test_timeout']), (3, 1, 2))
        self.assertEqual(out['classes'], {'OK': 2, 'TimeoutError': 1})
        self.assertEqual((out['wall_s_median'], out['wall_s_max']), (5.5, 6.0))
        self.assertEqual(out['startup_ms'], {'median': 20.0, 'max': 30.0})
        self.assertNotIn('teardown_ms', out)


if __name__ == '__main__':
    unittest.main()
