"""W28 / UDX28-01: a ``fcntl`` without memfd seal constants must not crash imports.

Measured on Linux 6.18: the GCC build of CPython 3.13.18 exposes F_ADD_SEALS,
F_GET_SEALS and F_SEAL_*; a Clang build of the same version does not. Before
W28 ``udx_ref.sealed_snapshot`` read the constants at import time, so on that
build the import raised AttributeError and five test modules (and every module
importing ``fd_handoff`` -> ... -> ``sealed_snapshot``) failed to load. Now the
constants are resolved at use and a missing one is a typed refusal.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

from udx_ref import fd_reader, sealed_snapshot

REPO = pathlib.Path(__file__).resolve().parents[1]
NAMES = ('F_ADD_SEALS', 'F_GET_SEALS', 'F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK', 'F_SEAL_SEAL')
# Linux UAPI values, used only to build stand-in modules for the pure function.
ABI = {'F_ADD_SEALS': 1033, 'F_GET_SEALS': 1034, 'F_SEAL_SEAL': 1, 'F_SEAL_SHRINK': 2,
       'F_SEAL_GROW': 4, 'F_SEAL_WRITE': 8}
LINUX_MEMFD = sys.platform == 'linux' and hasattr(os, 'memfd_create')


def stub(without=()):
    mod = types.SimpleNamespace(**{k: v for k, v in ABI.items() if k not in without})
    return mod


class SealingResolution(unittest.TestCase):
    def test_complete_module_yields_add_get_and_full_mask(self):
        self.assertEqual(sealed_snapshot._sealing(stub()), (1033, 1034, 1 | 2 | 4 | 8))

    def test_each_missing_constant_yields_none(self):
        for name in NAMES:
            with self.subTest(missing=name):
                self.assertIsNone(sealed_snapshot._sealing(stub(without=(name,))))

    def test_no_module_yields_none(self):
        self.assertIsNone(sealed_snapshot._sealing(None))

    def test_availability_matches_the_running_interpreter(self):
        try:
            import fcntl
        except ImportError:
            fcntl = None
        expected = LINUX_MEMFD and fcntl is not None and all(hasattr(fcntl, n) for n in NAMES)
        self.assertIs(sealed_snapshot.sealing_available(), expected)

    def test_module_imports_with_a_fcntl_lacking_the_constants(self):
        # Fresh execution of the module source under a constant-less fcntl:
        # before W28 this raised AttributeError at import time.
        spec = importlib.util.spec_from_file_location(
            'udx_ref._w28_sealed_snapshot_probe', REPO / 'udx_ref' / 'sealed_snapshot.py')
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'fcntl': stub(without=NAMES)}):
            spec.loader.exec_module(module)
        self.assertFalse(module.sealing_available())


@unittest.skipUnless(LINUX_MEMFD and hasattr(os, 'geteuid'), 'Linux memfd required')
class SnapshotRefusal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix='udx-w28-')
        path = pathlib.Path(self.dir.name) / 'source'
        path.write_bytes(b'stable-source')
        self.fd = os.open(path, os.O_RDONLY)

    def tearDown(self):
        os.close(self.fd)
        self.dir.cleanup()

    @staticmethod
    def _open_fds():
        return set(os.listdir('/proc/self/fd'))

    def test_missing_constant_is_refused_before_the_source_is_read(self):
        class MustNotRead:
            def __init__(self, *a, **k):
                raise AssertionError('source read although sealing is unavailable')

        for name in NAMES:
            with self.subTest(missing=name):
                before = self._open_fds()
                with mock.patch.object(sealed_snapshot, 'fcntl', stub(without=(name,))), \
                        mock.patch.object(sealed_snapshot, 'ApprovedFdReader', MustNotRead):
                    with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SEALING_UNAVAILABLE'):
                        sealed_snapshot.SealedSnapshot(self.fd, expected_uid=os.geteuid())
                self.assertEqual(self._open_fds(), before)

    def test_owner_check_still_precedes_the_sealing_check(self):
        with mock.patch.object(sealed_snapshot, 'fcntl', stub(without=NAMES)):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'OWNER_REQUIRED'):
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=-1)

    @unittest.skipUnless(sealed_snapshot.sealing_available(), 'fcntl seal constants required')
    def test_os_error_while_sealing_is_typed_and_closes_the_copy(self):
        import fcntl as real

        class SealingFails:
            def __getattr__(self, name):
                return getattr(real, name)

            def fcntl(self, fd, op, *args):
                if op == real.F_ADD_SEALS:
                    raise OSError(22, 'Invalid argument')
                return real.fcntl(fd, op, *args)

        before = self._open_fds()
        with mock.patch.object(sealed_snapshot, 'fcntl', SealingFails()):
            with self.assertRaisesRegex(fd_reader.ReadGuardError, 'SNAPSHOT_UNSEALED') as ctx:
                sealed_snapshot.SealedSnapshot(self.fd, expected_uid=os.geteuid())
        self.assertIsInstance(ctx.exception.__cause__, OSError)
        self.assertEqual(self._open_fds(), before)

    @unittest.skipUnless(sealed_snapshot.sealing_available(), 'fcntl seal constants required')
    def test_positive_control_real_snapshot(self):
        with sealed_snapshot.SealedSnapshot(self.fd, expected_uid=os.geteuid()) as snap:
            self.assertEqual(snap.read(), b'stable-source')


if __name__ == '__main__':
    unittest.main()
