"""Independent-runtime parser agreement; REQUIRED for W4 local conformance.

The CLI runs a separate Node.js process, not the Python parser embedded in JS.
"""
import json
import base64
import random
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from udx_ref.core import decode_request, Refusal
BASE = Path(__file__).resolve().parents[1]


def code(raw):
    try: decode_request(raw)
    except Refusal as exc: return exc.code
    return 'OK'


class NodeInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('node'):
            raise unittest.SkipTest('NODE_NOT_AVAILABLE: cross-language gate remains OPEN')

    def run_node(self, vectors):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'cases.json'
            p.write_text(json.dumps(vectors), encoding='utf-8')
            out = subprocess.check_output(['node', str(BASE/'interop/golden-runner.mjs'), str(p)], timeout=8)
        return json.loads(out)

    def test_19_golden_parser_vectors(self):
        vectors = [json.loads(line) for line in (BASE/'fixtures/golden.jsonl').read_text().splitlines()]
        actual = self.run_node(vectors)
        self.assertEqual([v['id'] for v in vectors], [v['id'] for v in actual])
        for expected, got in zip(vectors, actual):
            with self.subTest(id=expected['id']):
                self.assertEqual(got['parse'], expected['parse'])
                self.assertEqual(code(expected['raw'].encode()), got['parse'])

    def test_200_deterministic_contract_mutations(self):
        rng = random.Random(0xA4A4)
        baseline = '{"version":"udx/0.1","request_id":"00000000-0000-4000-8000-000000000001","capability":"object.metadata.read","params":{"object_id":"sample-1"}}'
        values = ['true','null','[]','{}','0','-0','1.5','9007199254740992','"\\ud800"','"\\udc00"','"x"']
        keys = ['version','request_id','capability','params','random','actor']
        vectors = []
        for i in range(200):
            item = json.loads(baseline)
            item[rng.choice(keys)] = json.loads(rng.choice(values))
            raw = json.dumps(item, ensure_ascii=True, separators=(',',':'))
            vectors.append({'id': f'seeded_{i:03d}', 'raw':raw})
        actual = self.run_node(vectors)
        for vector, got in zip(vectors,actual):
            with self.subTest(id=vector['id']):
                self.assertEqual(code(vector['raw'].encode()),got['parse'])


class CrossRuntimeByteFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('node'):
            raise unittest.SkipTest('NODE_NOT_AVAILABLE: cross-language gate remains OPEN')

    def test_1200_mutated_utf8_and_frame_bytes(self):
        """Deterministic differential test of *bytes*, not just JS strings."""
        rng = random.Random(20261009)
        baseline = b'{"version":"udx/0.1","request_id":"00000000-0000-4000-8000-000000000001","capability":"object.metadata.read","params":{"object_id":"sample-1"}}'
        vectors=[]
        for i in range(1200):
            raw=bytearray(baseline)
            for _ in range(rng.randint(1,5)):
                if len(raw) and rng.random()<0.32:
                    del raw[rng.randrange(len(raw))]
                elif rng.random()<0.45:
                    raw.insert(rng.randrange(len(raw)+1),rng.randrange(256))
                else:
                    raw[rng.randrange(len(raw))]=rng.randrange(256)
            vectors.append({'id':f'bytes_{i:04d}',
                            'raw_b64':base64.b64encode(raw).decode('ascii')})
        results=NodeInterop.run_node(self,vectors)
        self.assertEqual(len(results),len(vectors))
        for vector,result in zip(vectors,results):
            with self.subTest(vector=vector['id']):
                self.assertEqual(code(base64.b64decode(vector['raw_b64'])),result['parse'])
