"""W11 red/green regression tests for timing and shared-db serializability."""
import math
import os
import pathlib
import tempfile
import threading
import unittest
import uuid
from udx_ref.portal_request import PortalRequest,PortalFlowError
from udx_ref.durable_grants import DurableGrantStore,GrantDenied

class PortalClockFalsification(unittest.TestCase):
    def make(self,now,ttl=5):
        return PortalRequest(caller_unique=':1.22',portal_owner_unique=':1.23',clock=lambda:now[0],ttl_seconds=ttl)
    def response(self,p):
        p.bind_handle(p.handle)
        return p.receive(sender_unique=':1.23',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/selected']})
    def test_nan_at_start_denied(self):
        with self.assertRaisesRegex(PortalFlowError,'BAD_CLOCK'):self.make([float('nan')])
    def test_inf_at_start_denied(self):
        with self.assertRaisesRegex(PortalFlowError,'BAD_CLOCK'):self.make([float('inf')])
    def test_bool_clock_denied(self):
        with self.assertRaisesRegex(PortalFlowError,'BAD_CLOCK'):self.make([True])
    def test_nan_before_response_denied(self):
        n=[1.0];p=self.make(n);p.bind_handle(p.handle);n[0]=float('nan')
        with self.assertRaisesRegex(PortalFlowError,'BAD_CLOCK'):
            p.receive(sender_unique=':1.23',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/selected']})
        self.assertEqual(p.state,'REJECTED')
    def test_inf_before_response_denied(self):
        n=[1.0];p=self.make(n);p.bind_handle(p.handle);n[0]=float('inf')
        with self.assertRaisesRegex(PortalFlowError,'BAD_CLOCK'):
            p.receive(sender_unique=':1.23',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/selected']})
        self.assertEqual(p.state,'REJECTED')
    def test_backwards_clock_denied(self):
        n=[5.0];p=self.make(n);p.bind_handle(p.handle);n[0]=4.99
        with self.assertRaisesRegex(PortalFlowError,'CLOCK_ROLLBACK'):
            p.receive(sender_unique=':1.23',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/selected']})
        self.assertEqual(p.state,'REJECTED')
    def test_exact_deadline_denied(self):
        n=[0.0];p=self.make(n,ttl=5);p.bind_handle(p.handle);n[0]=5.0
        with self.assertRaisesRegex(PortalFlowError,'TIMEOUT'):
            p.receive(sender_unique=':1.23',signal_path=p.handle,response_code=0,results={'uris':['file:///tmp/selected']})
    def test_valid_clock_allows_structural_result(self):
        n=[0.0];p=self.make(n);n[0]=0.4
        self.assertEqual(self.response(p),'file:///tmp/selected')
    def test_clock_exception_denied(self):
        def bad(): raise RuntimeError('bad')
        with self.assertRaisesRegex(PortalFlowError,'CLOCK_FAILED'):
            PortalRequest(caller_unique=':1.22',portal_owner_unique=':1.23',clock=bad)

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'),
                     'POSIX uid/mode store checks required (os.getuid, fcntl)')
class ThreadSafety(unittest.TestCase):
    def test_single_connection_concurrent_grant_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            f=pathlib.Path(directory)/'data';f.write_bytes(b'UDX')
            fd=os.open(f,os.O_RDONLY)
            try:
                with DurableGrantStore(str(pathlib.Path(directory)/'grants.db')) as store:
                    uid=os.getuid();gid=store.issue(fd,issuer_uid=uid,recipient_uid=uid)
                    gate=threading.Barrier(12); outcomes=[]; lock=threading.Lock()
                    def runner():
                        gate.wait()
                        try:store.claim(gid,fd,issuer_uid=uid,recipient_uid=uid,request_id=str(uuid.uuid4()));s='OK'
                        except GrantDenied:s='DENIED'
                        with lock:outcomes.append(s)
                    threads=[threading.Thread(target=runner) for _ in range(12)]
                    for t in threads:t.start()
                    for t in threads:t.join(5)
                    self.assertFalse(any(t.is_alive() for t in threads))
                    self.assertEqual(outcomes.count('OK'),1)
                    self.assertEqual(outcomes.count('DENIED'),11)
                    self.assertEqual(store.state(gid),'INFLIGHT')
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
