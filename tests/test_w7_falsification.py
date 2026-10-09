"""W7: red/green, stable image signal, and kernel sealed copy."""
import concurrent.futures
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from uuid import uuid4
from udx_ref.preview_gate import PreviewGate, PreviewProposal, GateError
from udx_ref.perception import TileChangeTracker


class FakeClock:
    now = 100.
    def __call__(self): return self.now


class GateW7(unittest.TestCase):
    def setUp(self):
        self.t=FakeClock();self.g=PreviewGate(clock=self.t)
        self.p=PreviewProposal(str(uuid4()), 'p','s','r',1,32,32,1,2)
    def grant(self):
        return self.g.issue(human_approved=True,principal='p',session_id='s',resource_id='r',frame_epoch=1,width=32,height=32)
    def test_bool_and_float_equality_coercions_denied(self):
        for field,bad in [('frame_epoch',True),('frame_epoch',1.),('width',32.),('width',True),
                          ('height',32.),('height',True),('principal',1),('capability',None)]:
            with self.subTest(field=field,bad=bad):
                g=self.grant()
                self.assertFalse(self.g.check_and_consume(g,replace(self.p,**{field:bad})).accepted)
                self.assertTrue(self.g.check_and_consume(g,replace(self.p,request_id=str(uuid4()))).accepted)
    def test_clock_rollback_denies_and_clears_all(self):
        grant=self.grant();self.t.now=99.
        self.assertEqual(self.g.check_and_consume(grant,self.p).code,'CLOCK_ANOMALY')
        self.assertEqual(self.g.grant_count,0)
        self.assertEqual(self.g.check_and_consume(grant,self.p).code,'NO_ACTIVE_GRANT')
    def test_nonfinite_clock_denies(self):
        key=self.grant();self.t.now=float('nan')
        self.assertEqual(self.g.check_and_consume(key,self.p).code,'CLOCK_ANOMALY')
        self.assertEqual(self.g.grant_count,0)
    def test_new_grants_only_after_clock_recovered(self):
        self.grant();self.t.now=-1.
        with self.assertRaises(GateError):self.grant()
        self.assertEqual(self.g.grant_count,0)
        self.t.now=101.
        self.assertTrue(self.grant())


class PerceptionW7(unittest.TestCase):
    def test_nonzero_change_never_counts_quiet(self):
        t=TileChangeTracker(tile_edge=8,quiet_observations=2,change_threshold=1)
        a=bytes(32*32); b=bytearray(a); b[0]=1
        t.inspect(a,width=32,height=32,channels=1)
        for changed in (bytes(b), a, bytes(b), a):
            result=t.inspect(changed,width=32,height=32,channels=1)
            self.assertEqual(result.state,'LOW_CHANGE')
            self.assertEqual(result.stable_observations,0)
    def test_reset_rotates_digest_key(self):
        t=TileChangeTracker(tile_edge=8)
        key=t._key
        t.inspect(bytes(8*8),width=8,height=8,channels=1)
        before=t._hashes
        t.reset()
        self.assertNotEqual(key,t._key)
        self.assertEqual(t.inspect(bytes(8*8),width=8,height=8,channels=1).state,'BASELINE_REQUIRED')
        self.assertNotEqual(before,t._hashes)
    def test_same_input_same_instance_consistent(self):
        t=TileChangeTracker(tile_edge=8)
        frame=bytes(range(64))
        t.inspect(frame,width=8,height=8,channels=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            r=list(pool.map(lambda _: t.inspect(frame,width=8,height=8,channels=1),range(80)))
        self.assertEqual(r[-1].state,'STABLE_HEURISTIC')
        self.assertTrue(all(x.changed_tile_fraction==0 for x in r))
    def test_digest_does_not_leak_raw_identical_cross_instance_fingerprint(self):
        frame=bytes(8*8); a=TileChangeTracker(tile_edge=8);b=TileChangeTracker(tile_edge=8)
        a.inspect(frame,width=8,height=8,channels=1)
        b.inspect(frame,width=8,height=8,channels=1)
        self.assertNotEqual(a._hashes,b._hashes)


@unittest.skipUnless(sys.platform=='linux' and hasattr(os,'memfd_create'), 'Linux memfd required')
class SealedSnapshotW7(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='udx-w7-')
        self.p=os.path.join(self.t.name,'source')
        with open(self.p,'wb') as f: f.write(b'approved-source')
    def tearDown(self): self.t.cleanup()
    def _make(self):
        from udx_ref.sealed_snapshot import SealedSnapshot
        fd=os.open(self.p,os.O_RDONLY)
        try: return SealedSnapshot(fd,expected_uid=os.geteuid())
        finally: os.close(fd)
    def test_snapshot_fixed_after_source_changes(self):
        with self._make() as snap:
            with open(self.p,'wb') as f:f.write(b'modified-source')
            self.assertEqual(snap.read(),b'approved-source')
        from udx_ref.fd_reader import ReadGuardError
        with self.assertRaises(ReadGuardError):snap.read()
    def test_kernel_seals_reject_modification(self):
        import fcntl
        with self._make() as snap:
            flags=fcntl.fcntl(snap._fd,fcntl.F_GET_SEALS)
            for name in ('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'):
                self.assertTrue(flags&getattr(fcntl,name))
            with self.assertRaises(OSError):os.write(snap._fd,b'overwrite')
            self.assertEqual(snap.read(),b'approved-source')
    def test_source_must_be_readonly(self):
        from udx_ref.fd_reader import ReadGuardError
        from udx_ref.sealed_snapshot import SealedSnapshot
        fd=os.open(self.p,os.O_RDWR)
        try:
            with self.assertRaises(ReadGuardError):SealedSnapshot(fd,expected_uid=os.geteuid())
        finally:os.close(fd)
    def test_requires_os_owner_identity(self):
        from udx_ref.fd_reader import ReadGuardError
        from udx_ref.sealed_snapshot import SealedSnapshot
        fd=os.open(self.p,os.O_RDONLY)
        try:
            with self.assertRaises(ReadGuardError):SealedSnapshot(fd,expected_uid=None)
            with self.assertRaises(ReadGuardError):SealedSnapshot(fd,expected_uid=os.geteuid()+1)
        finally:os.close(fd)
    def test_empty_regular_file(self):
        with open(self.p,'wb'):pass
        with self._make() as snap:self.assertEqual(snap.read(),b'')
    def test_parallel_snapshot_read_and_close(self):
        from udx_ref.fd_reader import ReadGuardError
        s=self._make()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:s.read(),range(50)))
        self.assertTrue(all(x==b'approved-source' for x in results))
        s.close()
        with self.assertRaises(ReadGuardError):s.read()

if __name__=='__main__':unittest.main()
