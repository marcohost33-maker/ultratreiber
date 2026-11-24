"""W28: guard sweep v2 - more refusal forms, attributable kills, witnessed pins.

Answers A7-R6 U6-4 (the W27 sweep saw only ``if ...: raise``) and A7-R17
PR-R17-06 (a kill caused by a runtime error is not automatically evidence).
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


def check(x):
    if x == 1:
        return 'REFUSED_ONE'
    if x == 2:
        return False
    if x == 3:
        return decision('why', False)
    if x == 4:
        return 'fine'
    if x == 5:
        return
    try:
        int(x)
    except (TypeError,
            ValueError) as exc:
        raise E('NOT_INT') from exc
    try:
        pass
    except KeyError:
        return False
    except OSError:
        raise
    except LookupError:
        return
    except:
        raise E('BARE')
    return x
'''


class InventoryForms(unittest.TestCase):
    def setUp(self):
        self.guards = gs.inventory('udx_ref/m.py', SRC)

    def test_return_and_handler_refusals_are_found_ordinary_ones_are_not(self):
        got = [(g['form'], g['code'], g['condition']) for g in self.guards]
        self.assertEqual(got, [
            ('return', 'return:REFUSED_ONE', 'x == 1'),
            ('return', 'return:False', 'x == 2'),
            ('return', 'return:decision', 'x == 3'),
            ('handler', 'except:E:NOT_INT', '(TypeError, ValueError)'),
            ('handler', 'except:return:False', 'KeyError'),
        ])

    def test_kinds_per_form(self):
        self.assertEqual(gs.kinds_for({'form': 'raise'}), ('ADMIT', 'REFUSE'))
        self.assertEqual(gs.kinds_for({'form': 'return'}), ('ADMIT', 'REFUSE'))
        self.assertEqual(gs.kinds_for({'form': 'handler'}), ('UNTYPED',))
        self.assertEqual(gs.kinds_for({}), ('ADMIT', 'REFUSE'))       # a W27 record

    def test_untyped_mutant_catches_nothing_and_compiles(self):
        handler = self.guards[3]
        out = gs.mutate(SRC, handler, 'UNTYPED')
        self.assertIn(b'except () as exc:', out)
        self.assertEqual(out[:handler['begin']], SRC[:handler['begin']])
        self.assertEqual(out[handler['begin'] + 2:], SRC[handler['end']:])
        namespace = {}
        exec(compile(out, 'm.py', 'exec'), namespace)
        with self.assertRaises(ValueError):            # escapes untyped
            namespace['check']('nan-text')
        namespace = {}
        exec(compile(SRC, 'm.py', 'exec'), namespace)
        with self.assertRaises(namespace['E']):
            namespace['check']('nan-text')

    def test_a_kind_that_does_not_fit_the_form_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'KIND_NOT_APPLICABLE'):
            gs.mutate(SRC, self.guards[3], 'ADMIT')
        with self.assertRaisesRegex(ValueError, 'KIND_NOT_APPLICABLE'):
            gs.mutate(SRC, self.guards[0], 'UNTYPED')

    def test_w27_raise_keys_are_unchanged(self):
        src = b"def f(x):\n    if x:\n        raise ValueError('X')\n"
        guard, = gs.inventory('udx_ref/m.py', src)
        self.assertEqual(guard['form'], 'raise')
        self.assertEqual(guard['key'], 'udx_ref/m.py|f|ValueError:X|' + __import__('hashlib').sha256(b'x').hexdigest()[:12])

    def test_runtime_package_inventory_covers_the_new_forms(self):
        forms = {}
        for rel in gs.DEFAULT_MODULES:
            for g in gs.inventory(rel, (ROOT / rel).read_bytes()):
                forms[g['form']] = forms.get(g['form'], 0) + 1
        self.assertGreaterEqual(forms.get('return', 0), 11)
        self.assertGreaterEqual(forms.get('handler', 0), 18)


IMPORT_FAIL = '''======================================================================
ERROR: test_m (unittest.loader._FailedTest.test_m)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_m
----------------------------------------------------------------------
Ran 1 test in 0.000s

FAILED (errors=1)
'''
SETUP_FAIL = '''ERROR: setUpClass (tests.test_m.T)
----------------------------------------------------------------------
Ran 0 tests in 0.001s

FAILED (errors=1)
'''
IN_TEST = '''ERROR: test_a (tests.test_m.T.test_a)
----------------------------------------------------------------------
TypeError: boom
ERROR: setUpClass (tests.test_m.U)
----------------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (errors=2)
'''


class SideEffectsArePreserved(unittest.TestCase):
    """W28.1 (Codex review on #8): forcing a condition must not drop its side effects."""

    SRC = b"""class E(Exception):
    pass


def reply(raw, sock):
    if len(raw) > 4 or sock.send(raw) != len(raw):
        raise E('REPLY_FAILED')
    return 'SENT'
"""

    def test_mutants_still_evaluate_the_condition(self):
        guard, = gs.inventory('udx_ref/m.py', self.SRC)

        class Sock:
            sent = []

            def send(self, data):
                self.sent.append(data)
                return len(data)

        for kind, expect in (('ADMIT', 'SENT'), ('REFUSE', 'E')):
            ns = {}
            exec(compile(gs.mutate(self.SRC, guard, kind), 'm.py', 'exec'), ns)
            sock = Sock()
            Sock.sent = []
            try:
                got = ns['reply'](b'ok', sock)
            except ns['E']:
                got = 'E'
            with self.subTest(kind=kind):
                self.assertEqual(got, expect)
                self.assertEqual(Sock.sent, [b'ok'])        # the send happened in both mutants


class KillAttribution(unittest.TestCase):
    def test_structural_errors_are_not_kills(self):
        for name, output in (('import', IMPORT_FAIL), ('setUpClass', SETUP_FAIL)):
            with self.subTest(name):
                self.assertEqual(gs.classify(1, output), 'FAIL_STRUCTURAL')
                self.assertEqual(gs.decide('PASS', gs.classify(1, output)), 'STRUCTURAL')

    def test_an_error_inside_a_test_method_is_a_kill(self):
        self.assertEqual(gs.classify(1, IN_TEST), 'FAIL_ERROR_IN_TEST')
        self.assertEqual(gs.failing_tests(IN_TEST), [('ERROR', 'tests.test_m.T.test_a', False),
                                                     ('ERROR', 'tests.test_m.U', True)])

    def test_subtest_parameters_are_not_part_of_the_test_id(self):
        out = "FAIL: test_v (tests.test_m.T.test_v) (vector='b (1)')\n----\nFAILED (failures=1)\n"
        self.assertEqual(gs.failing_tests(out), [('FAIL', 'tests.test_m.T.test_v', False)])

    def test_a_failure_is_an_assertion_kill_whatever_else_happened(self):
        self.assertEqual(gs.classify(1, IMPORT_FAIL.replace('errors=1', 'failures=1, errors=1')),
                         'FAIL_ASSERTION')


class RatchetInput(unittest.TestCase):
    def test_survived_structural_and_unreliable_all_need_a_pin(self):
        cases = [{'kind': 'ADMIT', 'key': k, 'verdict': v} for k, v in
                 (('a', 'SURVIVED'), ('b', 'STRUCTURAL'), ('c', 'UNRELIABLE'), ('d', 'KILLED'),
                  ('e', 'TIMEOUT'), ('f', 'BASELINE_RED'))]
        self.assertEqual(gs.not_killed(cases), {'ADMIT a', 'ADMIT b', 'ADMIT c'})


class WitnessedBaseline(unittest.TestCase):
    def test_equivalent_needs_a_witness_and_kinds_are_known(self):
        good = {'kind': 'UNTYPED', 'key': 'k', 'class': 'DEFENSE_IN_DEPTH', 'reason': 'r'}
        eq = {'kind': 'ADMIT', 'key': 'q', 'class': 'EQUIVALENT', 'reason': 'r', 'witness': 'tests.t.C.test_x'}
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'b.json'
            path.write_text(json.dumps({'accepted_survivors': [good, eq]}), encoding='utf-8')
            self.assertEqual(sorted(gs.load_baseline(path)), ['ADMIT q', 'UNTYPED k'])
            for bad in (dict(eq, witness=' '), {k: v for k, v in eq.items() if k != 'witness'},
                        dict(good, kind='DELETE')):
                path.write_text(json.dumps({'accepted_survivors': [bad]}), encoding='utf-8')
                with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'BASELINE_ENTRY_INVALID'):
                    gs.load_baseline(path)

    def test_missing_witness_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            (repo / 'tests').mkdir()
            (repo / 'tests' / 't.py').write_text('class C:\n    def test_x(self):\n        pass\n')
            base = {'ADMIT a': {'witness': 'tests.t.C.test_x'}, 'ADMIT b': {'witness': 'tests.t.C.test_y'},
                    'ADMIT c': {'witness': 'tests.nope.C.test_x'}, 'ADMIT d': {'witness': 'x'},
                    'ADMIT e': {}}
            self.assertEqual(gs.missing_witnesses(base, repo),
                             ['ADMIT b -> tests.t.C.test_y', 'ADMIT c -> tests.nope.C.test_x', 'ADMIT d -> x'])

    def test_repository_baseline_is_valid_and_fully_witnessed(self):
        path = ROOT / 'evidence' / 'w31_guard_sweep_baseline.json'   # W31: current baseline (W28 kept as record)
        baseline = gs.load_baseline(path)
        self.assertEqual(gs.missing_witnesses(baseline, ROOT), [])
        data = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(data['modules'], list(gs.DEFAULT_MODULES))
        self.assertEqual([e for e in baseline.values() if e['class'] == 'OPEN_NO_TEST'], [])


MOD = '''class E(Exception):
    pass


STRICT = False
if STRICT:
    raise E('IMPORT_TIME')


def parse(text):
    try:
        return int(text)
    except ValueError as exc:
        raise E('NOT_INT') from exc


def parse_loose(text):
    try:
        return int(text)
    except ValueError as exc:
        raise E('LOOSE') from exc


def small(x):
    if x > 9:
        return 'TOO_LARGE'
    return 'OK'
'''
TESTS = '''import unittest
from udx_ref.m import parse, parse_loose, small, E


class T(unittest.TestCase):
    def test_typed(self):
        with self.assertRaises(E):
            parse('x')
        self.assertEqual(parse('4'), 4)

    def test_loose_only_checks_that_something_failed(self):
        with self.assertRaises(Exception):
            parse_loose('x')
        self.assertEqual(parse_loose('4'), 4)

    def test_small(self):
        self.assertEqual(small(10), 'TOO_LARGE')
        self.assertEqual(small(1), 'OK')
'''


SIDE_MOD = """class E(Exception):
    pass


class Sock:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data)
        return len(data)


def reply(raw, sock):
    if len(raw) > 4 or sock.send(raw) != len(raw):
        raise E('REPLY_FAILED')
    return 'SENT'
"""
SIDE_TESTS = """import unittest
from udx_ref.m import reply, Sock, E


class T(unittest.TestCase):
    def test_positive_path_sends(self):
        s = Sock()
        self.assertEqual(reply(b'ok', s), 'SENT')
        self.assertEqual(s.sent, [b'ok'])
"""
FLAKY_MOD = """class E(Exception):
    pass


def parse(text):
    try:
        return int(text)
    except ValueError as exc:
        raise E('NOT_INT') from exc
"""
FLAKY_TESTS = """import pathlib, unittest
from udx_ref.m import parse

COUNTER = pathlib.Path(COUNTER_PATH)


class T(unittest.TestCase):
    def test_flaky_second_run(self):
        n = int(COUNTER.read_text()) + 1 if COUNTER.exists() else 1
        COUNTER.write_text(str(n))
        self.assertEqual(parse('4'), 4)
        self.assertNotEqual(n, 2)            # fails on the second run only
"""


def _tree(tmp, mod, tests):
    repo = pathlib.Path(tmp) / 'repo'
    for d in ('udx_ref', 'tests', 'tools'):
        (repo / d).mkdir(parents=True)
    (repo / 'udx_ref' / '__init__.py').write_bytes(b'')
    (repo / 'udx_ref' / 'm.py').write_bytes(mod.encode())
    (repo / 'tests' / '__init__.py').write_bytes(b'')
    (repo / 'tests' / 'test_m.py').write_bytes(tests.encode())
    return repo


class W281EndToEnd(unittest.TestCase):
    def test_side_effecting_guard_without_negative_test_survives(self):
        # W27/W28 counted this ADMIT mutant as killed: the positive test failed
        # because the mutant also dropped the send.
        with tempfile.TemporaryDirectory(prefix='udx_gs3_') as tmp:
            repo = _tree(tmp, SIDE_MOD, SIDE_TESTS)
            result = gs.sweep(['udx_ref/m.py'], 1, 60.0, repo=repo,
                              copy_tree=lambda dest: shutil.copytree(repo, dest, dirs_exist_ok=True))
        got = {c['kind']: c['verdict'] for c in result['cases']}
        self.assertEqual(got, {'ADMIT': 'SURVIVED', 'REFUSE': 'KILLED'})

    def test_a_kill_that_does_not_reproduce_is_unreliable(self):
        with tempfile.TemporaryDirectory(prefix='udx_gs4_') as tmp:
            counter = pathlib.Path(tmp) / 'runs.txt'
            repo = _tree(tmp, FLAKY_MOD, FLAKY_TESTS.replace('COUNTER_PATH', repr(str(counter))))
            result = gs.sweep(['udx_ref/m.py'], 1, 60.0, repo=repo,
                              copy_tree=lambda dest: shutil.copytree(repo, dest, dirs_exist_ok=True))
            runs = int(counter.read_text())
        case, = result['cases']
        # run 1 baseline (pass), run 2 mutant (fails by flakiness), run 3 confirmation (pass)
        self.assertEqual(runs, 3)
        self.assertEqual((case['kind'], case['verdict'], case['confirmed']), ('UNTYPED', 'UNRELIABLE', False))
        self.assertEqual(case['failing'], ['tests.test_m.T.test_flaky_second_run'])


class EndToEnd(unittest.TestCase):
    def test_v2_sweep_on_a_synthetic_tree(self):
        with tempfile.TemporaryDirectory(prefix='udx_gs2_test_') as tmp:
            repo = pathlib.Path(tmp) / 'repo'
            for d in ('udx_ref', 'tests', 'tools'):
                (repo / d).mkdir(parents=True)
            (repo / 'udx_ref' / '__init__.py').write_bytes(b'')
            (repo / 'udx_ref' / 'm.py').write_bytes(MOD.encode())
            (repo / 'tests' / '__init__.py').write_bytes(b'')
            (repo / 'tests' / 'test_m.py').write_bytes(TESTS.encode())
            result = gs.sweep(['udx_ref/m.py'], 2, 60.0, repo=repo,
                              copy_tree=lambda dest: shutil.copytree(repo, dest, dirs_exist_ok=True))
        by_key = {(c['kind'], c['key'].split('|')[1]): c for c in result['cases']}
        self.assertEqual(by_key[('ADMIT', '<module>')]['verdict'], 'SURVIVED')
        self.assertEqual(by_key[('REFUSE', '<module>')]['verdict'], 'STRUCTURAL')
        self.assertEqual(by_key[('UNTYPED', 'parse')]['verdict'], 'KILLED')
        self.assertEqual(by_key[('UNTYPED', 'parse')]['kill_mode'], 'ERROR_IN_TEST')
        self.assertEqual(by_key[('UNTYPED', 'parse')]['failing'], ['tests.test_m.T.test_typed'])
        # assertRaises(Exception) also accepts the untyped ValueError: survivor.
        self.assertEqual(by_key[('UNTYPED', 'parse_loose')]['verdict'], 'SURVIVED')
        self.assertEqual(by_key[('ADMIT', 'small')]['kill_mode'], 'ASSERTION')
        self.assertEqual(by_key[('REFUSE', 'small')]['kill_mode'], 'ASSERTION')
        self.assertEqual(result['mutants_by_form'], {'handler': 2, 'raise': 2, 'return': 2})
        self.assertEqual(result['kill_modes'], {'ADMIT ASSERTION': 1, 'REFUSE ASSERTION': 1,
                                                'UNTYPED ERROR_IN_TEST': 1})


if __name__ == '__main__':
    unittest.main()
