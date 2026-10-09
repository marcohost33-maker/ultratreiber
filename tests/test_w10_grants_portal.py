"""W10 focused falsification: per-grant durable replay, recovery, revocation and portal correlation."""
from __future__ import annotations
import os
import pathlib
import socket
import tempfile
import threading
import unittest
import uuid
from udx_ref.durable_grants import DurableGrantStore,GrantDenied
from udx_ref.portal_request import PortalRequest,PortalFlowError
from udx_ref.authorized_handoff import perform_trusted_handoff
from udx_ref.credentialed_handoff import available, credentialed_pair, process_one

class DurableGrantTests(unittest.TestCase):
    def setUp(self):
        self.root=tempfile.TemporaryDirectory(prefix='udx-w10-')
        self.location=str(pathlib.Path(self.root.name)/'grants.db')
        self.file=pathlib.Path(self.root.name)/'approved.bin'
        self.file.write_bytes(b'NO_PATH_UNTRUSTED_HOST_ONLY')
        self.fd=os.open(self.file,os.O_RDONLY)
        self.uid=os.getuid()
        self.now=[1234567890000000000]
        self.store=DurableGrantStore(self.location,clock_ns=lambda:self.now[0])
    def tearDown(self):
        self.store.close();os.close(self.fd);self.root.cleanup()
    def issue(self,**kwargs):
        return self.store.issue(self.fd,issuer_uid=self.uid,recipient_uid=self.uid+1,**kwargs)
    def claim(self,gid,**kwargs):
        return self.store.claim(gid,self.fd,issuer_uid=self.uid,recipient_uid=self.uid+1,
                                request_id=kwargs.pop('request_id',str(uuid.uuid4())),**kwargs)
    def test_one_use(self):
        g=self.issue();request=str(uuid.uuid4());self.claim(g,request_id=request)
        self.store.finish(g,request)
        self.assertEqual(self.store.state(g),'COMPLETED')
        with self.assertRaisesRegex(GrantDenied,'NOT_ISSUED'):self.claim(g)
    def test_cross_grant_same_request_id_rejected(self):
        g1=self.issue();g2=self.issue();rid=str(uuid.uuid4())
        self.claim(g1,request_id=rid)
        with self.assertRaisesRegex(GrantDenied,'REQUEST_REPLAY'):
            self.claim(g2,request_id=rid)
        self.assertEqual(self.store.state(g2),'ISSUED')
    def test_revoke_before_claim(self):
        g=self.issue();self.store.revoke(g)
        with self.assertRaisesRegex(GrantDenied,'NOT_ISSUED'):self.claim(g)
    def test_revoke_during_transfer_fails_finish(self):
        g=self.issue();req=str(uuid.uuid4());self.claim(g,request_id=req)
        self.store.revoke(g)
        with self.assertRaisesRegex(GrantDenied,'UNCERTAIN'):self.store.finish(g,req)
        self.assertEqual(self.store.state(g),'REVOKED_INFLIGHT')
    def test_restart_does_not_reissue_inflight(self):
        g=self.issue();self.claim(g);self.store.close()
        self.store=DurableGrantStore(self.location,clock_ns=lambda:self.now[0])
        self.assertEqual(self.store.recover_inflight(),1)
        self.assertEqual(self.store.state(g),'QUARANTINED')
        with self.assertRaises(GrantDenied):self.claim(g)
    def test_issued_survives_restart(self):
        g=self.issue();self.store.close()
        self.store=DurableGrantStore(self.location,clock_ns=lambda:self.now[0]);self.claim(g)
        self.assertEqual(self.store.state(g),'INFLIGHT')
    def test_recovery_idempotent(self):
        g=self.issue();self.claim(g)
        self.assertEqual(self.store.recover_inflight(),1)
        self.assertEqual(self.store.recover_inflight(),0)
    def test_principal_scope(self):
        g=self.issue()
        with self.assertRaisesRegex(GrantDenied,'SCOPE_MISMATCH'):
            self.store.claim(g,self.fd,issuer_uid=self.uid,recipient_uid=self.uid+2,request_id=str(uuid.uuid4()))
        self.assertEqual(self.store.state(g),'ISSUED')
    def test_fd_scope(self):
        g=self.issue();other=pathlib.Path(self.root.name)/'other';other.write_bytes(b'ABCD')
        fd=os.open(other,os.O_RDONLY)
        try:
            with self.assertRaisesRegex(GrantDenied,'SCOPE_MISMATCH'):
                self.store.claim(g,fd,issuer_uid=self.uid,recipient_uid=self.uid+1,request_id=str(uuid.uuid4()))
        finally:os.close(fd)
    def test_modified_file_scope(self):
        g=self.issue();self.file.write_bytes(b'CHANGED')
        with self.assertRaisesRegex(GrantDenied,'SCOPE_MISMATCH'):self.claim(g)
    def test_expired(self):
        g=self.issue(ttl_seconds=1);self.now[0]+=10**9
        with self.assertRaisesRegex(GrantDenied,'EXPIRED'):self.claim(g)
        self.assertEqual(self.store.state(g),'EXPIRED')
    def test_backward_wall_clock_denied(self):
        g=self.issue();self.now[0]-=1
        with self.assertRaisesRegex(GrantDenied,'CLOCK_ROLLBACK'):self.claim(g)
    def test_boolean_uid_rejected(self):
        with self.assertRaisesRegex(GrantDenied,'BAD_PRINCIPAL'):
            self.store.issue(self.fd,issuer_uid=True,recipient_uid=2)
    def test_ttl_validation(self):
        for ttl in (-1,0,True,301,1.0):
            with self.subTest(ttl=ttl),self.assertRaisesRegex(GrantDenied,'BAD_TTL'):self.issue(ttl_seconds=ttl)
    def test_secure_db_permissions(self):
        self.assertEqual(os.stat(self.location).st_mode & 0o777,0o600)
        self.assertEqual(self.store.db.execute('PRAGMA synchronous').fetchone()[0],2)
    def test_symlink_store_rejected(self):
        link=pathlib.Path(self.root.name)/'link.db';link.symlink_to(self.location)
        with self.assertRaisesRegex(GrantDenied,'UNSAFE_STORE_FILE'):DurableGrantStore(str(link))
    def test_world_readable_directory_denied(self):
        os.chmod(self.root.name,0o755)
        try:
            with self.assertRaisesRegex(GrantDenied,'UNSAFE_STORE_DIRECTORY'):
                DurableGrantStore(str(pathlib.Path(self.root.name)/'second.db'))
        finally:os.chmod(self.root.name,0o700)
    def test_two_connections_race_one_claim(self):
        g=self.issue();other=DurableGrantStore(self.location,clock_ns=lambda:self.now[0]);results=[]
        def run(st):
            try:st.claim(g,self.fd,issuer_uid=self.uid,recipient_uid=self.uid+1,request_id=str(uuid.uuid4()));results.append('ok')
            except GrantDenied:results.append('deny')
        try:
            a=threading.Thread(target=run,args=(self.store,));b=threading.Thread(target=run,args=(other,));a.start();b.start();a.join();b.join()
            self.assertEqual(sorted(results),['deny','ok'])
        finally:other.close()
    def test_no_path_or_content_stored(self):
        g=self.issue()
        data=pathlib.Path(self.location).read_bytes()
        self.assertNotIn(str(self.file).encode(),data)
        self.assertNotIn(b'NO_PATH_UNTRUSTED_HOST_ONLY',data)
    @unittest.skipUnless(available(),'Linux SCM_CREDENTIALS required')
    def test_trusted_positive_transfer_consumes_grant(self):
        # Same-UID fixture for fast unit regression; W10 demo tests distinct UIDs.
        grant=self.store.issue(self.fd,issuer_uid=self.uid,recipient_uid=self.uid)
        req=str(uuid.uuid4());a,b=credentialed_pair()
        results=[]
        t=threading.Thread(target=lambda: results.append(process_one(b,expected_sender_uid=self.uid,source_owner_uid=self.uid)))
        t.start()
        try:
            reply=perform_trusted_handoff(self.store,a,self.fd,grant_id=grant,issuer_uid=self.uid,
                                           worker_uid=self.uid,request_id=req)
            self.assertEqual(reply['size'],self.file.stat().st_size)
            self.assertEqual(self.store.state(grant),'COMPLETED')
            t.join(timeout=3)
            self.assertFalse(t.is_alive())
        finally:a.close();b.close()

    @unittest.skipUnless(available(),'Linux SCM_CREDENTIALS required')
    def test_claim_before_real_ipc_transfer(self):
        # This test provides host-side grant, NOT a real portal selection.
        g=self.issue();left,right=credentialed_pair();req=str(uuid.uuid4());result=[]
        def worker():result.append(process_one(right,expected_sender_uid=self.uid,source_owner_uid=self.uid))
        worker_thread=threading.Thread(target=worker);worker_thread.start()
        # Both endpoints same UID in this local unit test; cross-UID demo is inherited from W9.
        try:
            reply=perform_trusted_handoff(self.store,left,self.fd,grant_id=g,issuer_uid=self.uid,worker_uid=self.uid+1,request_id=req)
            self.fail('expected mismatch')
        except Exception:
            self.assertEqual(self.store.state(g),'QUARANTINED')
        finally:
            worker_thread.join(timeout=3);left.close();right.close()

class PortalFlowTests(unittest.TestCase):
    def setUp(self):
        self.now=[100.0]
        self.req=PortalRequest(caller_unique=':1.45',portal_owner_unique=':1.9',clock=lambda:self.now[0])
    def good(self):return dict(sender_unique=':1.9',signal_path=self.req.handle,response_code=0,results={'uris':['file:///tmp/selected.txt']})
    def test_valid_correlated_result_not_grant(self):
        self.req.bind_handle(self.req.handle)
        self.assertEqual(self.req.receive(**self.good()),'file:///tmp/selected.txt')
        self.assertEqual(self.req.state,'RESULT_OBSERVED')
    def test_wrong_sender_rejected(self):
        self.req.bind_handle(self.req.handle);e=self.good();e['sender_unique']=':1.10'
        with self.assertRaisesRegex(PortalFlowError,'PROVENANCE_MISMATCH'):self.req.receive(**e)
    def test_wrong_handle_rejected(self):
        with self.assertRaisesRegex(PortalFlowError,'HANDLE_MISMATCH'):
            self.req.bind_handle('/org/freedesktop/portal/desktop/request/1_45/wrong')
    def test_wrong_signal_path_rejected(self):
        self.req.bind_handle(self.req.handle);e=self.good();e['signal_path']='/org/freedesktop/portal/desktop/request/1_45/other'
        with self.assertRaisesRegex(PortalFlowError,'PROVENANCE_MISMATCH'):self.req.receive(**e)
    def test_late_response_after_cancel(self):
        self.req.bind_handle(self.req.handle);self.req.cancel()
        with self.assertRaisesRegex(PortalFlowError,'NOT_EXPECTING_RESPONSE'):self.req.receive(**self.good())
    def test_timeout(self):
        self.req.bind_handle(self.req.handle);self.now[0]=500
        with self.assertRaisesRegex(PortalFlowError,'TIMEOUT'):self.req.receive(**self.good())
    def test_duplicate_response(self):
        self.req.bind_handle(self.req.handle);self.req.receive(**self.good())
        with self.assertRaisesRegex(PortalFlowError,'NOT_EXPECTING_RESPONSE'):self.req.receive(**self.good())
    def test_deny_portal_cancel(self):
        self.req.bind_handle(self.req.handle);e=self.good();e['response_code']=1
        with self.assertRaisesRegex(PortalFlowError,'DENIED_OR_MALFORMED'):self.req.receive(**e)
    def test_untrusted_json_not_admissible_proof(self):
        self.assertNotIn('approved',self.req.request_options)
        self.assertEqual(self.req.request_options['writable'],False)
        self.assertEqual(self.req.request_options['multiple'],False)
    def test_bad_bus_owner(self):
        with self.assertRaisesRegex(PortalFlowError,'BAD_PORTAL_OWNER'):
            PortalRequest(caller_unique=':1.4',portal_owner_unique='org.fake.portal')

if __name__=='__main__':unittest.main()
