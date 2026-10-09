"""W12: typed fail-closed denial of POSIX-only components on non-POSIX hosts."""
import os
import pathlib
import tempfile
import unittest

from udx_ref.durable_grants import DurableGrantStore, GrantDenied


@unittest.skipIf(os.name == 'posix' and hasattr(os, 'getuid'),
                 'non-POSIX host required (checks the Windows denial path)')
class DurableStoreNonPosixDenied(unittest.TestCase):
    def test_store_denied_with_typed_reason_and_no_file_created(self):
        with tempfile.TemporaryDirectory(prefix='udx-w12-') as d:
            db = pathlib.Path(d) / 'grants.db'
            with self.assertRaisesRegex(GrantDenied, 'UNSUPPORTED_PLATFORM'):
                DurableGrantStore(str(db))
            self.assertFalse(db.exists())

    def test_relative_path_also_denied_before_any_io(self):
        with self.assertRaisesRegex(GrantDenied, 'UNSUPPORTED_PLATFORM'):
            DurableGrantStore('relative.db')
        self.assertFalse(pathlib.Path('relative.db').exists())


if __name__ == '__main__':
    unittest.main()
