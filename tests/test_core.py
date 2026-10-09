"""Standalone reference behavior, no OS side effects."""
import json
import random
import unittest
import uuid
from udx_ref.core import (Broker, FixtureAdapter, ObjectMetadata, PeerIdentity, Policy,
                          decode_request, Refusal, MAX_MESSAGE_BYTES, VERSION)

def request(cap='object.metadata.read', params=None, **changes):
    req = {'version': VERSION, 'request_id': str(uuid.uuid4()),
           'capability': cap, 'params': {'object_id': 'document-1'} if params is None else params}
    req.update(changes)
    return json.dumps(req, separators=(',', ':')).encode('utf-8')

class TestUDX(unittest.TestCase):
    def setUp(self):
        self.adapter = FixtureAdapter({
            'document-1': ObjectMetadata('document-1','alice',123,'text'),
            'document-2': ObjectMetadata('document-2','bob',456,'text')})
        self.policy = Policy({'alice': {'udx.discover', 'udx.metadata.read'},
                              'bob': {'udx.discover', 'udx.metadata.read'},
                              'viewer': {'udx.discover'}})
        self.broker = Broker(self.adapter, self.policy)
        self.alice = PeerIdentity('alice', True)
    def outcome(self, data, peer=None):
        return self.broker.handle(data, self.alice if peer is None else peer)['code']
    def test_valid_read(self):
        res = self.broker.handle(request(), self.alice)
        self.assertEqual(res['code'], 'OK')
        self.assertEqual(res['data'], {'object_id':'document-1','kind':'text','size_bytes':123})
    def test_discovery_does_not_authorize(self):
        viewer = PeerIdentity('viewer', True)
        res = self.broker.handle(request('device.capabilities.list', {}), viewer)
        self.assertEqual(res['code'], 'OK')
        self.assertEqual(len(res['data']['capabilities']), 2)
        self.assertEqual(self.outcome(request(), viewer), 'CAPABILITY_NOT_GRANTED')
    def test_cross_owner_denied(self):
        self.assertEqual(self.outcome(request(), PeerIdentity('bob',True)), 'OBJECT_ACCESS_DENIED')
    def test_missing_object_denied(self):
        self.assertEqual(self.outcome(request(params={'object_id':'nonexistent'})), 'OBJECT_ACCESS_DENIED')
    def test_ungranted_denied(self):
        self.assertEqual(self.outcome(request(), PeerIdentity('stranger',True)), 'CAPABILITY_NOT_GRANTED')
    def test_unauthenticated_denied(self):
        self.assertEqual(self.outcome(request(), PeerIdentity('alice',False)), 'UNAUTHENTICATED_PEER')
    def test_truthy_string_not_authenticated(self):
        self.assertEqual(self.outcome(request(), PeerIdentity('alice', 'yes')), 'UNAUTHENTICATED_PEER')
    def test_nonstring_principal_not_authenticated(self):
        self.assertEqual(self.outcome(request(), PeerIdentity(1, True)), 'UNAUTHENTICATED_PEER')
    def test_none_peer_denied(self):
        self.assertEqual(self.broker.handle(request(), None)['code'], 'UNAUTHENTICATED_PEER')
    def test_identity_spoofing_payload(self):
        self.assertEqual(self.outcome(request(actor='alice')), 'INVALID_ENVELOPE')
    def test_consent_spoofing_payload(self):
        self.assertEqual(self.outcome(request(consent=True)), 'INVALID_ENVELOPE')
    def test_duplicate_json_key(self):
        self.assertEqual(self.outcome(b'{"version":"udx/0.1","version":"udx/0.1"}'), 'DUPLICATE_JSON_KEY')
    def test_invalid_utf8(self):
        self.assertEqual(self.outcome(b'\xff'), 'MALFORMED_JSON')
    def test_large_frame(self):
        self.assertEqual(self.outcome(b'x'*(MAX_MESSAGE_BYTES+1)), 'FRAME_TOO_LARGE')
    def test_frame_size_boundary(self):
        with self.assertRaises(Refusal) as ctx:
            decode_request(b'x'*MAX_MESSAGE_BYTES)
        self.assertEqual(ctx.exception.code, 'MALFORMED_JSON')
    def test_bad_version(self):
        self.assertEqual(self.outcome(request(version='udx/0.2')), 'UNSUPPORTED_VERSION')
    def test_unknown_action(self):
        self.assertEqual(self.outcome(request('device.process.spawn',{})), 'UNKNOWN_CAPABILITY')
    def test_case_sensitive_capability(self):
        self.assertEqual(self.outcome(request('Object.Metadata.Read',{})), 'INVALID_CAPABILITY')
    def test_shell_token_rejected(self):
        self.assertEqual(self.outcome(request('object.metadata.read;sh',{})), 'INVALID_CAPABILITY')
    def test_path_traversal_rejected(self):
        self.assertEqual(self.outcome(request(params={'object_id':'../etc'})), 'INVALID_OBJECT_ID')
    def test_additional_parameter_rejected(self):
        self.assertEqual(self.outcome(request(params={'object_id':'document-1','path':'/'})), 'INVALID_PARAMS')
    def test_boolean_id_rejected(self):
        self.assertEqual(self.outcome(request(params={'object_id':True})), 'INVALID_OBJECT_ID')
    def test_params_string_rejected(self):
        self.assertEqual(self.outcome(request(params='x')), 'INVALID_PARAMS')
    def test_float_rejected(self):
        self.assertEqual(self.outcome(request(params={'object_id':'document-1','extra':1.2})), 'NON_INTEGER_JSON_NUMBER')
    def test_nan_rejected(self):
        self.assertEqual(self.outcome(request().replace(b'"document-1"',b'NaN')), 'NON_FINITE_JSON_NUMBER')
    def test_noncanonical_uuid(self):
        self.assertEqual(self.outcome(request(request_id='invalid')), 'INVALID_REQUEST_ID')
    def test_replay_denied(self):
        raw = request()
        self.assertEqual(self.outcome(raw), 'OK')
        self.assertEqual(self.outcome(raw), 'REPLAY_REJECTED')
        self.assertEqual(self.adapter.read_count, 1)
    def test_revoke_rechecked(self):
        self.assertEqual(self.outcome(request()), 'OK')
        self.policy.replace_grants('alice', set())
        self.assertEqual(self.outcome(request()), 'CAPABILITY_NOT_GRANTED')
    def test_discovery_extra_args(self):
        self.assertEqual(self.outcome(request('device.capabilities.list',{'any':True})), 'INVALID_PARAMS')
    def test_invalids_no_reads(self):
        for raw in (request('no.such.cap',{}), request(params={'object_id':'document-2'}),
                    request(request_id='nope')):
            self.assertNotEqual(self.outcome(raw), 'OK')
        self.assertEqual(self.adapter.read_count, 0)
    def test_audit_contains_no_payload_or_actor(self):
        self.outcome(request())
        self.assertEqual(set(self.broker.audit[0]), {'request_id','code'})
    def test_random_input_negative_controls(self):
        rng = random.Random(20261009)
        for _ in range(250):
            blob = bytes(rng.randrange(256) for _ in range(rng.randrange(100)))
            self.assertNotEqual(self.outcome(blob), 'OK')
        self.assertEqual(self.adapter.read_count, 0)
    def test_replay_not_persistent(self):
        raw = request()
        self.assertEqual(self.outcome(raw), 'OK')
        self.assertEqual(Broker(self.adapter,self.policy).handle(raw,self.alice)['code'], 'OK')
        # Explicitly documents a limitation, not a desired production feature.

if __name__ == '__main__':
    unittest.main()
