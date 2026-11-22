"""W28 (A7-R6 U6-2): the start-up phase of the fd-handoff demo, completed.

W27 already covers: a child that never becomes ready (typed, bounded by the
start-up budget, reaped), a child that exits before READY (typed), and a child
that is ready and then silent (still the 2 s protocol timeout). Cross-family
review asked whether a hostile child can use the 60 s start-up budget to block.
It can block for at most that budget - a liveness bound, never authority, and
the child is killed and reaped. Two corners were untested:

* a child that dies before READY must be detected at once through EOF on the
  ready pipe, not after the 60 s budget. That holds only because the parent
  closes its copy of the pipe's write end after the spawn; a regression there
  would silently turn every early crash into a 60 s stall.
* a child that writes a wrong ready byte and then stalls must be refused at
  once as BAD_READY_BYTE, killed and reaped.
"""
import json, pathlib, subprocess, sys, time, unittest

from udx_ref.fd_handoff import supported
from udx_ref.sealed_snapshot import sealing_available

REPO = pathlib.Path(__file__).resolve().parent.parent
DEMO = REPO / 'tools' / 'demo_w8_fd_handoff.py'
HANG_GUARD_S = 60
PROMPT_S = 10.0                   # far below the default 60 s start-up budget


@unittest.skipUnless(supported(), 'Linux SCM_RIGHTS / seqpacket required')
class StartupMatrix(unittest.TestCase):
    def demo(self, *args):
        started = time.monotonic()
        try:
            r = subprocess.run([sys.executable, str(DEMO), *args], cwd=str(REPO), capture_output=True,
                               text=True, timeout=HANG_GUARD_S)
        except subprocess.TimeoutExpired:
            self.fail(f'demo did not return within {HANG_GUARD_S} s: {args}')
        return r.returncode, json.loads(r.stdout), time.monotonic() - started

    def test_early_exit_is_detected_through_eof_not_after_the_budget(self):
        code, out, elapsed = self.demo('--child-fault', 'exit_before_ready')     # default 60 s budget
        self.assertEqual((code, out.get('error'), out.get('phase')), (4, 'CHILD_EXITED_BEFORE_READY', 'startup'))
        self.assertTrue(out.get('child_reaped'))
        self.assertLess(elapsed, PROMPT_S)

    def test_wrong_ready_byte_is_refused_at_once_and_the_child_reaped(self):
        code, out, elapsed = self.demo('--child-fault', 'bad_ready_byte')        # child would stall 30 s
        self.assertEqual((code, out.get('error'), out.get('phase')), (4, 'BAD_READY_BYTE', 'startup'))
        self.assertTrue(out.get('child_reaped'))
        self.assertNotIn('result', out)
        self.assertLess(elapsed, PROMPT_S)

    @unittest.skipUnless(sealing_available(), 'the server side needs a sealed snapshot')
    def test_positive_control_normal_run(self):
        code, out, _ = self.demo()
        self.assertEqual(code, 0, out)
        self.assertEqual(out.get('child_exit'), 0)


if __name__ == '__main__':
    unittest.main()
