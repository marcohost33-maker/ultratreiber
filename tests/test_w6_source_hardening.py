"""W6 standalone defensive dry-run, frame lifecycle and perception tests."""
import concurrent.futures
import json
import random
import unittest
from dataclasses import replace
from uuid import uuid4
from udx_ref.preview_gate import PreviewGate, PreviewProposal, GateError, MAX_EVENTS, MAX_GRANTS
from udx_ref.perception import TileChangeTracker, MAX_FRAME_BYTES
from udx_ref.frame_lease import frame_lease, ReleasedFrame

class Clock:
    def __init__(self): self.now=100.0
    def __call__(self): return self.now

class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.g=PreviewGate(self.clock)
        self.base=PreviewProposal(str(uuid4()), 'test-app', 's1', 'display-1', 7, 1920, 1080, 500, 300)
        self.issue=lambda **kw:self.g.issue(human_approved=True,principal='test-app',session_id='s1',
            resource_id='display-1',frame_epoch=7,width=1920,height=1080,**kw)
    def test_default_denied(self):
        self.assertFalse(self.g.check_and_consume(str(uuid4()),self.base).accepted)
    def test_no_approval_no_grant(self):
        with self.assertRaises(GateError):
            self.g.issue(human_approved=False,principal='test-app',session_id='s1',resource_id='display-1',
                         frame_epoch=7,width=1920,height=1080)
    def test_one_shot_dryrun_only(self):
        key=self.issue();ok=self.g.check_and_consume(key,self.base)
        self.assertEqual(ok.code,'DRY_RUN_ONLY');self.assertTrue(ok.accepted);self.assertEqual(ok.effect,'NONE')
        self.assertFalse(self.g.check_and_consume(key,self.base).accepted)
    def test_stale_frame_epoch_denied_without_consumption(self):
        key=self.issue();self.assertEqual(self.g.check_and_consume(key,replace(self.base,frame_epoch=6)).code,'SCOPE_MISMATCH')
        self.assertTrue(self.g.check_and_consume(key,self.base).accepted)
    def test_principal_resource_session_surface_scope(self):
        for field,value in [('principal','another-app'),('session_id','s2'),('resource_id','display-2'),
                           ('width',1921),('height',1081),('capability','process.spawn')]:
            with self.subTest(field=field):
                key=self.issue();self.assertFalse(self.g.check_and_consume(key,replace(self.base,**{field:value})).accepted)
                self.g.revoke(key)
    def test_coordinates_strict_and_reject_bool_float(self):
        for field,val in [('x',True),('x',-1),('x',1920),('y',1080),('y',2.1),('y',False)]:
            with self.subTest(field=field):
                key=self.issue();res=self.g.check_and_consume(key,replace(self.base,**{field:val}))
                self.assertEqual(res.code,'INVALID_COORDINATES');self.g.revoke(key)
    def test_expiry_and_revoke(self):
        key=self.issue(ttl_seconds=0.1);self.clock.now+=0.11
        self.assertEqual(self.g.check_and_consume(key,self.base).code,'NO_ACTIVE_GRANT')
        key=self.issue();self.assertTrue(self.g.revoke(key))
        self.assertEqual(self.g.check_and_consume(key,self.base).code,'NO_ACTIVE_GRANT')
    def test_ttl_and_types_fail_closed(self):
        for ttl in [float('nan'),float('inf'),-1,0,61,True]:
            with self.subTest(ttl=ttl),self.assertRaises(GateError):self.issue(ttl_seconds=ttl)
    def test_concurrent_one_winner(self):
        key=self.issue()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            out=list(pool.map(lambda _:self.g.check_and_consume(key,replace(self.base,request_id=str(uuid4()))),range(100)))
        self.assertEqual(sum(x.accepted for x in out),1)
        self.assertTrue(all(x.effect=='NONE' for x in out))
    def test_grant_capacity_bounded(self):
        keys=[self.issue() for _ in range(MAX_GRANTS)]
        self.assertEqual(self.g.grant_count,MAX_GRANTS)
        with self.assertRaises(GateError):self.issue()
        self.assertTrue(self.g.revoke(keys[0]));self.assertTrue(self.issue())
    def test_events_no_secret_and_bounded(self):
        for _ in range(2*MAX_EVENTS):self.g.check_and_consume('malformed',self.base)
        self.assertEqual(self.g.event_count,MAX_EVENTS)
        self.assertNotIn('test-app',repr(self.g._events))
        self.assertNotIn('display-1',repr(self.g._events))

class PerceptionTests(unittest.TestCase):
    def test_first_baseline_requires_more_frames(self):
        t=TileChangeTracker(tile_edge=8,quiet_observations=2)
        first=t.inspect(bytes(16*16),width=16,height=16,channels=1)
        self.assertEqual(first.state,'BASELINE_REQUIRED')
        self.assertEqual(t.inspect(bytes(16*16),width=16,height=16,channels=1).state,'QUIET_CANDIDATE')
        self.assertEqual(t.inspect(bytes(16*16),width=16,height=16,channels=1).state,'STABLE_HEURISTIC')
    def test_changed_tile_detected_not_stubbed_zero(self):
        t=TileChangeTracker(tile_edge=8)
        base=bytes(16*16)
        t.inspect(base,width=16,height=16,channels=1)
        mod=bytearray(base);mod[0]=1
        sig=t.inspect(bytes(mod),width=16,height=16,channels=1)
        self.assertEqual(sig.changed_tile_fraction,0.25)
        self.assertEqual(sig.state,'CHANGING')
    def test_new_geometry_invalidates_baseline(self):
        t=TileChangeTracker(tile_edge=8)
        t.inspect(bytes(16*16),width=16,height=16,channels=1)
        self.assertEqual(t.inspect(bytes(8*8),width=8,height=8,channels=1).state,'BASELINE_REQUIRED')
    def test_bad_inputs_fail_before_allocation(self):
        t=TileChangeTracker()
        for frame,w,h,c in [(b'abc',1,1,4),(b'',0,1,1),(b'',8192,8192,4),(b'',1,1,2)]:
            with self.subTest(w=w,h=h,c=c),self.assertRaises(ValueError):t.inspect(frame,width=w,height=h,channels=c)
    def test_does_not_retain_full_frame(self):
        t=TileChangeTracker(tile_edge=8)
        image=bytes(range(64))*64
        t.inspect(image,width=64,height=64,channels=1)
        self.assertFalse(any(type(x) is bytes and len(x)==len(image) for x in vars(t).values()))
        self.assertTrue(all(len(x)==16 for x in t._hashes))
    def test_tile_mutations_randomized(self):
        rng=random.Random(314159)
        for _ in range(200):
            w=h=16
            original=bytes(rng.randrange(256) for i in range(w*h))
            modified=bytearray(original);tile=rng.randrange(4)
            x=(tile%2)*8+rng.randrange(8);y=(tile//2)*8+rng.randrange(8)
            modified[y*w+x]^=255
            t=TileChangeTracker(tile_edge=8)
            t.inspect(original,width=w,height=h,channels=1)
            self.assertEqual(t.inspect(bytes(modified),width=w,height=h,channels=1).changed_tile_fraction,0.25)

class LeaseTests(unittest.TestCase):
    def test_guaranteed_release(self):
        counts={'acquire':0,'release':0}
        def acquire():counts['acquire']+=1;return 'dummy-frame'
        def release():counts['release']+=1
        with frame_lease(acquire,release) as lease:self.assertEqual(lease.handle,'dummy-frame')
        self.assertEqual(counts,{'acquire':1,'release':1})
        with self.assertRaises(ReleasedFrame):_=lease.handle
    def test_release_on_exception(self):
        calls=[]
        with self.assertRaises(ZeroDivisionError):
            with frame_lease(lambda:'frame',lambda:calls.append('released')):1/0
        self.assertEqual(calls,['released'])

if __name__=='__main__':unittest.main()

# Extra POSIX pre-opened-descriptor tests; this module is NOT registered with IPC.
import os
import tempfile
from udx_ref.fd_reader import ApprovedFdReader, ReadGuardError, MAX_READ

@unittest.skipUnless(os.name=='posix' and hasattr(os,'pread'),'POSIX FD required')
class FdReadTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='udx-fd-')
        self.p=os.path.join(self.t.name,'data.bin')
        with open(self.p,'wb') as f:f.write(b'approved-test-bytes')
    def tearDown(self):self.t.cleanup()
    def test_read_only_fd_and_close(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:
            with ApprovedFdReader(fd,expected_uid=os.geteuid()) as reader:
                self.assertEqual(reader.read(),b'approved-test-bytes')
                self.assertEqual(reader.read(),b'approved-test-bytes')
            with self.assertRaises(ReadGuardError):reader.read()
        finally:os.close(fd)
    def test_reject_write_access(self):
        fd=os.open(self.p,os.O_RDWR)
        try:
            with self.assertRaises(ReadGuardError):ApprovedFdReader(fd)
        finally:os.close(fd)
    def test_reject_directory(self):
        fd=os.open(self.t.name,os.O_RDONLY)
        try:
            with self.assertRaises(ReadGuardError):ApprovedFdReader(fd)
        finally:os.close(fd)
    def test_reject_path_string(self):
        with self.assertRaises(ReadGuardError):ApprovedFdReader(self.p)
    def test_reject_owner_mismatch(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:
            with self.assertRaises(ReadGuardError):ApprovedFdReader(fd,expected_uid=os.geteuid()+1)
        finally:os.close(fd)
    def test_reject_changed_file(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:
            with ApprovedFdReader(fd) as reader:
                with open(self.p,'ab') as f:f.write(b'!')
                with self.assertRaises(ReadGuardError):reader.read()
        finally:os.close(fd)
    def test_reject_oversize(self):
        fd=os.open(self.p,os.O_RDONLY)
        try:
            with self.assertRaises(ReadGuardError):ApprovedFdReader(fd,limit=3)
        finally:os.close(fd)
    def test_reject_bool_fd(self):
        with self.assertRaises(ReadGuardError):ApprovedFdReader(True)

class MoreGateTests(unittest.TestCase):
    def test_seen_id_replay_memory_bounded(self):
        from udx_ref.preview_gate import MAX_SEEN
        g=PreviewGate()
        for i in range(MAX_SEEN+30):
            k=g.issue(human_approved=True,principal='p',session_id='s',resource_id='r',
                frame_epoch=1,width=4,height=4)
            proposal=PreviewProposal(str(uuid4()),'p','s','r',1,4,4,0,0)
            self.assertTrue(g.check_and_consume(k,proposal).accepted)
        self.assertEqual(len(g._seen),MAX_SEEN)
        self.assertEqual(len(g._seen_order),MAX_SEEN)
