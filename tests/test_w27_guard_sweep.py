"""W27: the two-sided guard sweep (tools/guard_sweep.py) is itself tested.

The sweep decides which refusals count as tested in both directions. A sweep
that misses guards, mutates the wrong bytes or lets a new survivor pass would
make its baseline meaningless. These tests pin the inventory, the byte-exact
mutation, every verdict, the ratchet and one real end-to-end run on a synthetic
tree in which exactly one guard has no positive control.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
try:
    import guard_sweep as gs
finally:
    sys.path.pop(0)

SRC = b'''class E(Exception):
    pass


def check(x, limit):
    if type(x) is not int:
        raise E('TYPE')
    elif x < 0:
        raise E('NEGATIVE')
    if (x > limit or
            x == 13):
        raise E('LIMIT')
    if x == 7:
        return 'seven'
    if x == 99:
        x = 98
        raise ValueError
    return x


class K:
    def m(self, y):
        if y:
            raise E('TYPE')
        if y:
            raise E('TYPE')
        try:
            pass
        except E:
            if y is None:
                raise
'''


class Inventory(unittest.TestCase):
    def setUp(self):
        self.guards = gs.inventory('udx_ref/m.py', SRC)

    def test_finds_every_if_and_elif_whose_body_ends_in_raise_and_nothing_else(self):
        got = [(g['scope'], g['code'], g['condition']) for g in self.guards]
        self.assertEqual(got, [
            ('check', 'E:TYPE', 'type(x) is not int'),
            ('check', 'E:NEGATIVE', 'x < 0'),
            ('check', 'E:LIMIT', 'x > limit or x == 13'),
            ('check', 'ValueError', 'x == 99'),
            ('K.m', 'E:TYPE', 'y'),
            ('K.m', 'E:TYPE', 'y'),
            ('K.m', 'reraise', 'y is None'),
        ])

    def test_keys_are_unique_and_do_not_depend_on_line_numbers(self):
        keys = [g['key'] for g in self.guards]
        self.assertEqual(len(set(keys)), len(keys))
        self.assertTrue(keys[5].endswith('#2') and not keys[4].endswith('#2'))
        moved = gs.inventory('udx_ref/m.py', b'\n\n# moved\n' + SRC)
        self.assertEqual([g['key'] for g in moved], keys)
        self.assertNotEqual([g['line'] for g in moved], [g['line'] for g in self.guards])

    def test_key_changes_when_the_condition_or_the_code_changes(self):
        other = gs.inventory('udx_ref/m.py', SRC.replace(b'x < 0', b'x <= 0'))
        self.assertNotEqual(other[1]['key'], self.guards[1]['key'])
        other = gs.inventory('udx_ref/m.py', SRC.replace(b"E('NEGATIVE')", b"E('NEG')"))
        self.assertNotEqual(other[1]['key'], self.guards[1]['key'])


class Mutation(unittest.TestCase):
    def test_only_the_condition_bytes_change_also_across_lines_and_with_crlf(self):
        for source in (SRC, SRC.replace(b'\n', b'\r\n')):
            guards = gs.inventory('udx_ref/m.py', source)
            limit = guards[2]
            # W28.1: the condition is kept and only its result forced.
            for kind, (head, tail) in (('ADMIT', (b'((', b') and False)')), ('REFUSE', (b'((', b') or True)'))):
                with self.subTest(kind=kind, crlf=b'\r\n' in source):
                    out = gs.mutate(source, limit, kind)
                    cond = source[limit['begin']:limit['end']]
                    self.assertEqual(out, source[:limit['begin']] + head + cond + tail + source[limit['end']:])
                    compile(out, 'm.py', 'exec')
                    self.assertIn(head + cond + tail + b'):', out)

    def test_non_ascii_before_the_condition_does_not_shift_the_range(self):
        source = 'def f(x):\n    s = "\u00e4\u00f6\u00fc\u20ac"; \n    if s and x:\n        raise ValueError(s)\n'.encode('utf-8')
        source = source.replace(b'; \n    if', b';\n    if')
        guard, = gs.inventory('udx_ref/m.py', source)
        self.assertEqual(source[guard['begin']:guard['end']], b's and x')
        one_line = 'def f(x):\n    s = "\u20ac"\n    if x: raise ValueError("\u20ac")\n'.encode('utf-8')
        guard, = gs.inventory('udx_ref/m.py', one_line)
        self.assertEqual(one_line[guard['begin']:guard['end']], b'x')


class Verdicts(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(gs.classify(0, 'Ran 3 tests in 0.1s\n\nOK\n'), 'PASS')
        self.assertEqual(gs.classify(1, 'Ran 3 tests\n\nFAILED (failures=1)\n'), 'FAIL_ASSERTION')
        self.assertEqual(gs.classify(1, 'Ran 3 tests\n\nFAILED (failures=1, errors=2)\n'), 'FAIL_ASSERTION')
        # W28: an error counts only when a test method raised; see test_w28_guard_sweep_v2.
        err = 'ERROR: test_a (tests.test_m.T.test_a)\n----\nRan 3 tests\n\nFAILED (errors=2)\n'
        self.assertEqual(gs.classify(1, err), 'FAIL_ERROR_IN_TEST')
        self.assertEqual(gs.classify(1, 'Ran 3 tests\n\nFAILED (errors=2)\n'), 'FAIL_STRUCTURAL')
        self.assertEqual(gs.classify(1, 'Traceback ...'), 'FAIL_STRUCTURAL')
        self.assertEqual(gs.classify(None, ''), 'TIMEOUT')

    def test_a_timeout_is_never_a_kill_and_a_red_baseline_is_not_a_result(self):
        self.assertEqual(gs.decide('PASS', 'FAIL_ASSERTION'), 'KILLED')
        self.assertEqual(gs.decide('PASS', 'FAIL_ERROR_IN_TEST'), 'KILLED')
        self.assertEqual(gs.decide('PASS', 'FAIL_STRUCTURAL'), 'STRUCTURAL')
        self.assertEqual(gs.decide('PASS', 'PASS'), 'SURVIVED')
        self.assertEqual(gs.decide('PASS', 'TIMEOUT'), 'TIMEOUT')
        self.assertEqual(gs.decide('TIMEOUT', 'FAIL_ASSERTION'), 'TIMEOUT')
        self.assertEqual(gs.decide('FAIL_ASSERTION', 'FAIL_ASSERTION'), 'BASELINE_RED')
        self.assertEqual(gs.decide('NO_TESTS', None), 'BASELINE_RED')
        self.assertEqual(gs.decide('PASS', None), 'BASELINE_RED')


class Ratchet(unittest.TestCase):
    def test_new_survivor_and_stale_pin_are_both_reported(self):
        self.assertEqual(gs.compare({'ADMIT a', 'REFUSE b'}, {'ADMIT a': {}, 'REFUSE c': {}}),
                         {'new_survivors': ['REFUSE b'], 'stale_baseline': ['REFUSE c']})
        self.assertEqual(gs.compare({'ADMIT a'}, {'ADMIT a': {}}), {'new_survivors': [], 'stale_baseline': []})

    def test_baseline_entries_need_a_known_class_and_a_reason_and_must_be_unique(self):
        good = {'kind': 'ADMIT', 'key': 'k', 'class': 'DEFENSE_IN_DEPTH', 'reason': 'second check'}
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'b.json'
            path.write_text(json.dumps({'accepted_survivors': [good]}), encoding='utf-8')
            self.assertEqual(list(gs.load_baseline(path)), ['ADMIT k'])
            for bad in (dict(good, **{'class': 'FINE'}), dict(good, reason='  '), None):
                entries = [good, good] if bad is None else [bad]
                path.write_text(json.dumps({'accepted_survivors': entries}), encoding='utf-8')
                with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'BASELINE_ENTRY_INVALID'):
                    gs.load_baseline(path)


MOD = '''class E(Exception):
    pass


def admit(x):
    if x < 0:
        raise E('NEGATIVE')
    if x > 100:
        raise E('LARGE')
    if x == 50:
        raise E('FIFTY')
    return x
'''
TESTS = '''import unittest
from udx_ref.m import admit, E


class T(unittest.TestCase):
    def test_negative_refused(self):
        with self.assertRaises(E):
            admit(-1)

    def test_zero_admitted(self):
        self.assertEqual(admit(0), 0)

    def test_large_refused(self):
        with self.assertRaises(E):
            admit(101)
'''


class EndToEnd(unittest.TestCase):
    def test_real_sweep_on_a_synthetic_tree_reports_exactly_the_untested_direction(self):
        with tempfile.TemporaryDirectory(prefix='udx_gs_test_') as tmp:
            repo = pathlib.Path(tmp) / 'repo'
            (repo / 'udx_ref').mkdir(parents=True)
            (repo / 'tests').mkdir()
            (repo / 'tools').mkdir()
            (repo / 'udx_ref' / '__init__.py').write_bytes(b'')
            (repo / 'udx_ref' / 'm.py').write_bytes(MOD.encode())
            (repo / 'tests' / '__init__.py').write_bytes(b'')
            (repo / 'tests' / 'test_m.py').write_bytes(TESTS.encode())
            before = (repo / 'udx_ref' / 'm.py').read_bytes()
            result = gs.sweep(['udx_ref/m.py'], 2, 60.0, repo=repo,
                              copy_tree=lambda dest: shutil.copytree(repo, dest, dirs_exist_ok=True))
            self.assertEqual((repo / 'udx_ref' / 'm.py').read_bytes(), before)
        self.assertEqual(result['modules']['udx_ref/m.py']['tests'], ['tests.test_m'])
        self.assertEqual(result['modules']['udx_ref/m.py']['baseline'], 'PASS')
        verdicts = {(c['kind'], c['condition']): c['verdict'] for c in result['cases']}
        self.assertEqual(verdicts, {
            ('ADMIT', 'x < 0'): 'KILLED', ('REFUSE', 'x < 0'): 'KILLED',
            ('ADMIT', 'x > 100'): 'KILLED', ('REFUSE', 'x > 100'): 'KILLED',
            # FIFTY has no negative test (ADMIT survives); zero_admitted is its positive control.
            ('ADMIT', 'x == 50'): 'SURVIVED', ('REFUSE', 'x == 50'): 'KILLED',
        })


if __name__ == '__main__':
    unittest.main()
