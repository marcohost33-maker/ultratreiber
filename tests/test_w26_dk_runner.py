"""W26: the discriminating-mutation runner (tools/dk_runner.py) is itself tested.

A mutation runner that reports false kills or hides survivors would turn every
"n/n killed" claim of this repository into noise. These tests run the real
runner on a synthetic work tree and pin each verdict, the byte-exact restore
(CRLF included, the Windows text-mode trap), the timeout rule (a hang is never a
kill) and that the W26 specs are anchored in the current tree.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
try:
    import dk_runner as dk
finally:
    sys.path.pop(0)

MOD = b'def f():\r\n    return 1\r\n\r\ndef slow():\n    return 0\n'
TESTS = '''import unittest
import mod


class T(unittest.TestCase):
    def test_strong(self):
        self.assertEqual(mod.f(), 1)

    def test_weak(self):
        self.assertTrue(callable(mod.f))

    @unittest.skip('platform')
    def test_skipped(self):
        self.assertEqual(mod.f(), 1)

    def test_red(self):
        self.assertEqual(mod.f(), 2)

    def test_hang(self):
        self.assertEqual(mod.slow(), 0)
'''


def case(name, alt, neu, test, datei='mod.py'):
    return {'name': name, 'datei': datei, 'alt': alt, 'neu': neu, 'test': 'tests/test_syn.py::T::' + test}


class RunnerVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        work = pathlib.Path(cls.tmp.name) / 'work'
        work.mkdir()
        (work.parent / 'outside.py').write_bytes(b'x = 1\n')    # must stay untouched
        (work / 'tests').mkdir()
        (work / 'mod.py').write_bytes(MOD)
        (work / 'tests' / 'test_syn.py').write_text(TESTS, encoding='utf-8')
        spec = {'timeout_s': 3, 'faelle': [
            case('kill', '    return 1\r\n', '    return 7\r\n', 'test_strong'),
            case('survive', '    return 1\r\n', '    return 7\r\n', 'test_weak'),
            case('stale', 'return 99', 'return 7', 'test_strong'),
            case('twice', 'return', 'return 7 or', 'test_strong'),
            case('skip', '    return 1\r\n', '    return 7\r\n', 'test_skipped'),
            case('red', '    return 1\r\n', '    return 7\r\n', 'test_red'),
            case('hang', '    return 0\n', '    import time; time.sleep(30); return 1\n', 'test_hang'),
            {'name': 'bad id', 'datei': 'mod.py', 'alt': 'return 1', 'neu': 'return 7', 'test': 'mod.py::f'},
            case('escape', 'x', 'y', 'test_strong', datei='../outside.py'),
            case('absolute', 'x', 'y', 'test_strong', datei='/etc/hostname'),
        ]}
        path = work / 'spec.json'
        path.write_text(json.dumps(spec), encoding='utf-8')
        cls.result = dk.run_spec(path, work)
        cls.verdicts = {c['name']: c['verdict'] for c in cls.result['cases']}
        cls.after = (work / 'mod.py').read_bytes()
        cls.outside = (work.parent / 'outside.py').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_each_verdict(self):
        self.assertEqual(self.verdicts, {
            'kill': 'KILLED', 'survive': 'SURVIVED', 'stale': 'STALE_ANCHOR', 'twice': 'STALE_ANCHOR',
            'skip': 'SKIPPED_ON_PLATFORM', 'red': 'BASELINE_RED', 'hang': 'TIMEOUT', 'bad id': 'RUNNER_ERROR',
            'escape': 'RUNNER_ERROR', 'absolute': 'RUNNER_ERROR'})

    def test_restore_is_byte_exact_including_crlf(self):
        self.assertEqual(self.after, MOD)

    def test_spec_cannot_write_outside_the_work_copy(self):
        self.assertEqual(self.outside, b'x = 1\n')

    def test_spec_is_not_ok_unless_every_applicable_case_is_killed(self):
        self.assertFalse(self.result['ok'])
        self.assertEqual(self.result['killed'], '1/9')          # 10 cases, 1 skipped
        self.assertEqual(len(self.result['spec_sha256']), 64)


class RunnerPureLogic(unittest.TestCase):
    def test_decide(self):
        self.assertEqual(dk.decide(1, 'PASS', 'FAIL'), 'KILLED')
        self.assertEqual(dk.decide(1, 'PASS', 'PASS'), 'SURVIVED')
        self.assertEqual(dk.decide(1, 'PASS', 'SKIP'), 'SURVIVED')     # a mutant that skips is not a kill
        self.assertEqual(dk.decide(1, 'PASS', 'TIMEOUT'), 'TIMEOUT')
        self.assertEqual(dk.decide(1, 'PASS', None), 'TIMEOUT')
        self.assertEqual(dk.decide(0, 'PASS', 'FAIL'), 'STALE_ANCHOR')
        self.assertEqual(dk.decide(2, 'PASS', 'FAIL'), 'STALE_ANCHOR')
        self.assertEqual(dk.decide(1, 'SKIP', None), 'SKIPPED_ON_PLATFORM')
        self.assertEqual(dk.decide(1, 'FAIL', None), 'BASELINE_RED')
        self.assertEqual(dk.decide(1, 'TIMEOUT', None), 'TIMEOUT')

    def test_classify_requires_exactly_one_test(self):
        self.assertEqual(dk.classify(0, 'Ran 1 test in 0.001s\n\nOK\n'), 'PASS')
        self.assertEqual(dk.classify(0, 'Ran 1 test in 0.001s\n\nOK (skipped=1)\n'), 'SKIP')
        self.assertEqual(dk.classify(0, 'Ran 0 tests in 0.000s\n\nOK\n'), 'FAIL')     # nothing ran
        self.assertEqual(dk.classify(0, 'Ran 2 tests in 0.001s\n\nOK\n'), 'FAIL')
        self.assertEqual(dk.classify(1, 'Ran 1 test in 0.001s\n\nFAILED (failures=1)\n'), 'FAIL')
        self.assertEqual(dk.classify(None, ''), 'TIMEOUT')

    def test_test_id(self):
        self.assertEqual(dk.test_id('tests/test_a.py::C::test_b'), 'tests.test_a.C.test_b')
        for bad in (None, 'tests/test_a.py::C', 'tests/test_a::C::t', 'tests/a b.py::C::t',
                    'tests/test_a.py::C::t;rm', '../x.py::C::t'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dk.test_id(bad)

    def test_runner_never_writes_the_working_tree(self):
        src = (ROOT / 'tools' / 'dk_runner.py').read_text(encoding='utf-8')
        body = src[src.index('def run_spec('):src.index('def main(')]
        self.assertNotIn('REPO /', body)                       # mutations only under ``work``
        self.assertIn('write_bytes', body)
        self.assertNotIn('write_text', body)
        self.assertIn("'-B'", src)
        self.assertIn("PYTHONDONTWRITEBYTECODE='1'", src)


class W26SpecsAnchored(unittest.TestCase):
    SPECS = ('w26_dk_spec.json', 'w26_carryover_dk_spec.json', 'w26_carryover_native_dk_spec.json')

    def test_every_w26_anchor_exists_exactly_once_and_names_a_real_test(self):
        for spec in self.SPECS:
            data = json.loads((ROOT / 'evidence' / spec).read_text(encoding='utf-8'))
            self.assertTrue(data['faelle'], spec)
            for f in data['faelle']:
                src = (ROOT / f['datei']).read_bytes()
                self.assertEqual(src.count(f['alt'].encode('utf-8')), 1, f['name'])
                self.assertNotEqual(f['alt'], f['neu'], f['name'])
                path, cls, meth = f['test'].split('::')
                text = (ROOT / path).read_text(encoding='utf-8')
                self.assertIn('class %s(' % cls, text, f['name'])
                self.assertIn('def %s(' % meth, text, f['name'])


if __name__ == '__main__':
    unittest.main()
