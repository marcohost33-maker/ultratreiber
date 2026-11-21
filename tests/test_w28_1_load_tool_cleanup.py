"""W28.1 (Codex review on #8): the load tool reaps every burner it started.

``tools/w27_fd_handoff_load.py`` started its ``while True: pass`` burners in a
list comprehension before the ``try/finally``. If the third start failed (process
limit, interrupt), the first two kept running after the tool exited. The burners
are now started inside the protected region.
"""
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]


class BurnerCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(REPO / 'tools'))
        try:
            import w27_fd_handoff_load
        finally:
            sys.path.pop(0)
        cls.tool = w27_fd_handoff_load

    def test_partial_start_failure_kills_and_reaps_the_started_burners(self):
        started = []

        class FakeBurner:
            def __init__(self):
                self.killed = self.waited = False

            def kill(self):
                self.killed = True

            def wait(self, timeout=None):
                self.waited = True
                return -9

        def fake_popen(args, **kwargs):
            if args[1:] == ['-c', 'while True: pass']:
                if len(started) == 2:
                    raise OSError(11, 'Resource temporarily unavailable')
                started.append(FakeBurner())
                return started[-1]
            raise AssertionError(f'unexpected Popen {args!r}')

        def fake_run(args, **kwargs):            # git rev-parse / git show only; no real process
            if args[:2] == ['git', 'rev-parse']:
                return subprocess.CompletedProcess(args, 0, stdout='0' * 40 + '\n', stderr='')
            if args[:2] == ['git', 'show']:
                return subprocess.CompletedProcess(args, 0, stdout=b'# demo\n', stderr=b'')
            raise AssertionError(f'unexpected run {args!r}')

        with mock.patch.object(self.tool.subprocess, 'Popen', fake_popen), \
                mock.patch.object(self.tool.subprocess, 'run', fake_run), \
                mock.patch.object(self.tool.time, 'sleep', lambda s: None):
            with self.assertRaises(OSError):
                self.tool.measure([5], 1, 'HEAD')
        self.assertEqual(len(started), 2)
        self.assertTrue(all(b.killed and b.waited for b in started))


if __name__ == '__main__':
    unittest.main()
