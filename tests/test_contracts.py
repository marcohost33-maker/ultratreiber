"""Contract parity: normative JSON Schema plus parser/dispatcher golden cases.

Requires jsonschema only for the schema conformance lane, not runtime.
"""
import json
import unittest
from pathlib import Path
from udx_ref.core import Broker, FixtureAdapter, ObjectMetadata, PeerIdentity, Policy, Refusal, decode_request

BASE = Path(__file__).resolve().parents[1]


class ContractVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            raise unittest.SkipTest('jsonschema conformance dependency missing; NOT green')
        cls.request_validator = Draft202012Validator(json.loads((BASE/'contracts/request.schema.json').read_text()))
        cls.response_validator = Draft202012Validator(json.loads((BASE/'contracts/response.schema.json').read_text()))
        Draft202012Validator.check_schema(cls.request_validator.schema)
        Draft202012Validator.check_schema(cls.response_validator.schema)

    def test_vectors(self):
        broker = Broker(FixtureAdapter({'sample-1': ObjectMetadata('sample-1','uid:1000',42,'fixture')}),
                        Policy({'uid:1000':{'udx.metadata.read', 'udx.discover'}}))
        peer = PeerIdentity('uid:1000', True)
        for line in (BASE/'fixtures/golden.jsonl').read_text().splitlines():
            vector = json.loads(line)
            with self.subTest(vector=vector['id']):
                raw = vector['raw'].encode('utf-8')
                if vector['parse'] == 'OK':
                    req = decode_request(raw)
                    if vector.get('schema_valid', True):
                        self.request_validator.validate(req)
                    else:
                        self.assertFalse(self.request_validator.is_valid(req))
                else:
                    with self.assertRaises(Refusal) as err:
                        decode_request(raw)
                    self.assertEqual(err.exception.code, vector['parse'])
                    # Note: some wire-only errors (duplicate keys) cannot be expressed in JSON Schema.
                out = broker.handle(raw, peer)
                self.assertEqual(out['code'], vector['result'])
                self.response_validator.validate(out)

    def test_schema_known_action_guards(self):
        from jsonschema import ValidationError
        schema = self.request_validator
        source = {'version':'udx/0.1','request_id':'00000000-0000-4000-8000-000000000001',
                  'capability':'object.metadata.read','params':{'object_id':'sample-1'}}
        schema.validate(source)
        for change in [ {'params':{'object_id':'../'}}, {'params':{'object_id':'sample-1','path':'../'}},
                        {'capability':'device.capabilities.list', 'params':{'object_id':'sample-1'}},
                        {'version':'udx/0.2'}, {'identity':'uid:0'}]:
            bad = dict(source, **change)
            with self.subTest(change=change), self.assertRaises(ValidationError):
                schema.validate(bad)

    def test_no_schema_is_security_boundary(self):
        # The parser rejects duplicate JSON keys which JSON Schema cannot express.
        raw = b'{"version":"udx/0.1","version":"udx/0.1"}'
        with self.assertRaises(Refusal) as err:
            decode_request(raw)
        self.assertEqual(err.exception.code, 'DUPLICATE_JSON_KEY')
