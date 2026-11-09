"""W25: the principal-matrix verdict is decided from the report alone and fails closed.

The Windows lane runs in CI (job ``windows-principal-matrix``): real Low-IL,
AppContainer and restricted-token processes of the C++ client against the
Python and the C++ server. These portable tests pin the decision function, the
layer-2 control SD and the C++ client's stderr contract: a complete report
passes, and every single missing or contradicting fact blocks it.
"""
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
try:
    import w25_principal_matrix as tool
finally:
    sys.path.pop(0)

USER = 'S-1-5-21-1-2-3-500'
AC = 'S-1-15-2-1-2-3-4-5-6-7'
HIGH = 0x3000


def facts(principal: str) -> dict:
    return {
        'same_token': {'user_sid': USER, 'integrity_rid': HIGH, 'appcontainer': False,
                       'appcontainer_sid': None, 'restricted': False},
        'low_il': {'user_sid': USER, 'integrity_rid': 0x1000, 'appcontainer': False,
                   'appcontainer_sid': None, 'restricted': False},
        'appcontainer': {'user_sid': USER, 'integrity_rid': 0x1000, 'appcontainer': True,
                         'appcontainer_sid': AC, 'restricted': False},
        'restricted': {'user_sid': USER, 'integrity_rid': HIGH, 'appcontainer': False,
                       'appcontainer_sid': None, 'restricted': True},
    }[principal]


def good_report() -> dict:
    prod = tool.production_sddl(USER)
    cases = {}
    for name, (server, sd, principal, cexit, oerr, sexp) in tool.EXPECTED.items():
        child = {'exit': cexit, 'open_error': oerr, 'elapsed_s': 0.4, 'facts': facts(principal),
                 'stderr': '' if oerr is None else f'UDX_CLIENT_OPEN_ERROR {oerr}\n'}
        if server == 'python':
            verdict, reason, identified = sexp
            srv = {'verdict': verdict, 'reason': reason, 'client_sid': USER if identified else None,
                   'sent': verdict == 'PEER_OK', 'winerror': None}
        else:
            srv = {'exit': sexp}
        cases[name] = {'server': server, 'sd': sd, 'principal': principal, 'child': child,
                       'server_result': srv}
    return {
        'release_authorized': False,
        'parent': {'user_sid': USER, 'integrity_rid': HIGH, 'appcontainer': False,
                   'appcontainer_sid': None, 'restricted': False},
        'sddl': {'production': prod, 'control': tool.control_sddl(prod)},
        'appcontainer': {'name': 'udx.w25.probe.0123456789ab', 'sid': AC, 'created': True},
        'cases': cases,
        'cleanup': {'appcontainer_profile': 'deleted'},
    }


class EvaluatePrincipalMatrix(unittest.TestCase):
    def test_complete_report_passes(self):
        self.assertEqual(tool.evaluate(good_report()), ('PRINCIPAL_MATRIX_OK', []))

    def _blocked_with(self, mutate, issue):
        r = good_report()
        mutate(r)
        verdict, issues = tool.evaluate(r)
        self.assertEqual(verdict, 'BLOCKED')
        self.assertIn(issue, issues)

    def test_not_an_object(self):
        self.assertEqual(tool.evaluate([]), ('BLOCKED', ['REPORT_NOT_OBJECT']))

    def test_release_claim_blocks(self):
        self._blocked_with(lambda r: r.update(release_authorized=True), 'RELEASE_CLAIM')
        self._blocked_with(lambda r: r.pop('release_authorized'), 'RELEASE_CLAIM')

    def test_orchestration_error_blocks(self):
        self._blocked_with(lambda r: r.update(error='BUILD_FAILED'), 'ORCHESTRATION_ERROR')

    def test_case_set_must_be_exact(self):
        self._blocked_with(lambda r: r['cases'].pop('cpp_restricted'), 'CASE_SET_DRIFT')
        self._blocked_with(lambda r: r['cases'].update(extra={}), 'CASE_SET_DRIFT')

    def test_case_error_blocks(self):
        self._blocked_with(lambda r: r['cases'].update(py_low_il={'error': 'OSError: 1314'}),
                           'CASE_ERROR:py_low_il')

    def test_launcher_that_did_not_lower_integrity_blocks(self):
        # The false green this lane exists to exclude: a "low_il" child that ran
        # at the parent's level and was refused for some other reason.
        self._blocked_with(lambda r: r['cases']['py_low_il']['child']['facts'].update(integrity_rid=HIGH),
                           'CHILD_INTEGRITY_WRONG:py_low_il')

    def test_appcontainer_child_must_be_in_this_appcontainer(self):
        self._blocked_with(lambda r: r['cases']['cpp_appcontainer']['child']['facts'].update(appcontainer=False),
                           'CHILD_APPCONTAINER_WRONG:cpp_appcontainer')
        self._blocked_with(lambda r: r['cases']['ctl_appcontainer']['child']['facts'].update(
            appcontainer_sid='S-1-15-2-9'), 'CHILD_APPCONTAINER_SID_WRONG:ctl_appcontainer')
        self._blocked_with(lambda r: r['appcontainer'].update(sid='S-1-5-21-1'), 'APPCONTAINER_SID_INVALID')

    def test_restricted_child_must_be_restricted(self):
        self._blocked_with(lambda r: r['cases']['py_restricted']['child']['facts'].update(restricted=False),
                           'CHILD_RESTRICTED_WRONG:py_restricted')
        self._blocked_with(lambda r: r['cases']['py_same_token']['child']['facts'].update(restricted=True),
                           'CHILD_RESTRICTED_WRONG:py_same_token')

    def test_child_must_run_as_the_same_user(self):
        self._blocked_with(lambda r: r['cases']['cpp_low_il']['child']['facts'].update(user_sid='S-1-5-21-9'),
                           'CHILD_USER_DRIFT:cpp_low_il')

    def test_child_facts_missing_blocks(self):
        self._blocked_with(lambda r: r['cases']['py_appcontainer']['child'].pop('facts'),
                           'CHILD_FACTS_MISSING:py_appcontainer')

    def test_refusal_must_be_access_denied_at_open(self):
        # Exit 1 alone also means "pipe absent until the deadline".
        self._blocked_with(lambda r: r['cases']['py_low_il']['child'].update(open_error=2),
                           'CLIENT_OPEN_ERROR_WRONG:py_low_il')
        self._blocked_with(lambda r: r['cases']['cpp_appcontainer']['child'].update(open_error=None),
                           'CLIENT_OPEN_ERROR_WRONG:cpp_appcontainer')
        self._blocked_with(lambda r: r['cases']['py_appcontainer']['child'].update(open_error=True),
                           'CLIENT_OPEN_ERROR_WRONG:py_appcontainer')

    def test_client_exit_code(self):
        self._blocked_with(lambda r: r['cases']['ctl_low_il']['child'].update(exit=0),
                           'CLIENT_EXIT_WRONG:ctl_low_il')
        self._blocked_with(lambda r: r['cases']['py_same_token']['child'].update(exit=None),
                           'CLIENT_EXIT_WRONG:py_same_token')
        self._blocked_with(lambda r: r['cases']['py_same_token']['child'].update(exit=False),
                           'CLIENT_EXIT_WRONG:py_same_token')

    def test_client_must_end_on_its_own_in_time(self):
        for bad in (None, -1.0, float('nan'), float('inf'), tool.CHILD_LIMIT_S + 0.1, '0.4'):
            self._blocked_with(lambda r, bad=bad: r['cases']['cpp_low_il']['child'].update(elapsed_s=bad),
                               'CLIENT_NOT_BOUNDED:cpp_low_il')

    def test_python_server_decision(self):
        self._blocked_with(lambda r: r['cases']['ctl_low_il']['server_result'].update(reason='SID_MISMATCH'),
                           'SERVER_DECISION_WRONG:ctl_low_il')
        self._blocked_with(lambda r: r['cases']['py_restricted']['server_result'].update(verdict='PEER_OK'),
                           'SERVER_DECISION_WRONG:py_restricted')
        self._blocked_with(lambda r: r['cases'].__setitem__('py_low_il', dict(
            r['cases']['py_low_il'], server_result=None)), 'SERVER_DECISION_WRONG:py_low_il')

    def test_server_must_have_identified_the_real_user(self):
        self._blocked_with(lambda r: r['cases']['ctl_appcontainer']['server_result'].update(client_sid=None),
                           'SERVER_DID_NOT_IDENTIFY_USER:ctl_appcontainer')
        self._blocked_with(lambda r: r['cases']['py_low_il']['server_result'].update(client_sid=USER),
                           'SERVER_SAW_A_CLIENT:py_low_il')

    def test_denied_server_must_not_have_sent(self):
        self._blocked_with(lambda r: r['cases']['py_restricted']['server_result'].update(sent=True),
                           'SERVER_SENT_WRONG:py_restricted')
        self._blocked_with(lambda r: r['cases']['py_same_token']['server_result'].update(sent=False),
                           'SERVER_SENT_WRONG:py_same_token')

    def test_cpp_server_exit(self):
        self._blocked_with(lambda r: r['cases']['cpp_restricted']['server_result'].update(exit=0),
                           'CPP_SERVER_EXIT_WRONG:cpp_restricted')
        self._blocked_with(lambda r: r['cases']['cpp_low_il']['server_result'].update(exit=None),
                           'CPP_SERVER_EXIT_WRONG:cpp_low_il')

    def test_case_shape(self):
        self._blocked_with(lambda r: r['cases']['ctl_low_il'].update(sd='production'),
                           'CASE_SHAPE_DRIFT:ctl_low_il')

    def test_parent_facts(self):
        self._blocked_with(lambda r: r['parent'].update(user_sid='S-1-5-18'), 'PARENT_SID_INVALID')
        self._blocked_with(lambda r: r['parent'].update(integrity_rid=0x1000), 'PARENT_INTEGRITY_BELOW_MEDIUM')
        self._blocked_with(lambda r: r['parent'].update(restricted=True), 'PARENT_NOT_PLAIN')

    def test_sddl_drift(self):
        self._blocked_with(lambda r: r['sddl'].update(production=r['sddl']['control']), 'PRODUCTION_SDDL_DRIFT')
        self._blocked_with(lambda r: r['sddl'].update(control=r['sddl']['production']), 'CONTROL_SDDL_DRIFT')

    def test_cleanup(self):
        self._blocked_with(lambda r: r['cleanup'].update(appcontainer_profile='hr=0x80070005'),
                           'CLEANUP_INCOMPLETE')

    def test_every_case_is_discriminating(self):
        # Each expected case contributes at least one issue when its child exit flips.
        for name in tool.EXPECTED:
            r = good_report()
            r['cases'][name]['child']['exit'] = 77
            self.assertIn('CLIENT_EXIT_WRONG:' + name, tool.evaluate(r)[1], name)

    def test_cli_evaluate_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / 'r.json'
            path.write_text(json.dumps(good_report()), encoding='utf-8')
            ok = subprocess.run([sys.executable, str(ROOT / 'tools' / 'w25_principal_matrix.py'), '--evaluate',
                                 '--output', str(path)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            bad = good_report()
            bad['cases']['py_low_il']['child']['open_error'] = None
            path.write_text(json.dumps(bad), encoding='utf-8')
            no = subprocess.run([sys.executable, str(ROOT / 'tools' / 'w25_principal_matrix.py'), '--evaluate',
                                 '--output', str(path)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(no.returncode, 1)
            self.assertIn('BLOCKED', no.stdout)


class ControlSddl(unittest.TestCase):
    def test_production_literal_matches_the_module(self):
        from udx_ref import windows_pipe as wp
        self.assertEqual(tool.production_sddl(USER), wp.build_sddl(USER))

    def test_control_adds_exactly_ac_ace_and_low_label(self):
        prod = tool.production_sddl(USER)
        ctl = tool.control_sddl(prod)
        self.assertTrue(ctl.endswith(')(A;;0x12008b;;;AC)S:(ML;;NWNR;;;LW)'))
        self.assertEqual(ctl.replace('(A;;0x12008b;;;AC)', '').replace(';LW)', ';ME)'), prod)

    def test_control_refuses_non_production_input(self):
        for bad in ('', None, tool.control_sddl(tool.production_sddl(USER)), 'O:S-1-5-18D:P'):
            with self.assertRaises(ValueError):
                tool.control_sddl(bad)

    def test_evaluate_does_not_trust_a_weakened_production_sd(self):
        r = good_report()
        r['sddl']['production'] = r['sddl']['production'].replace('NWNR;;;ME', 'NW;;;ME')
        self.assertIn('PRODUCTION_SDDL_DRIFT', tool.evaluate(r)[1])


class OpenErrorLine(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(tool.parse_open_error('UDX_CLIENT_OPEN_ERROR 5\n'), 5)
        self.assertEqual(tool.parse_open_error('noise\r\nUDX_CLIENT_OPEN_ERROR 2\r\n'), 2)
        for bad in (None, '', 'UDX_CLIENT_OPEN_ERROR', 'UDX_CLIENT_OPEN_ERROR -5', 'UDX_CLIENT_OPEN_ERROR 5 x',
                    'UDX_CLIENT_OPEN_ERROR 5\nUDX_CLIENT_OPEN_ERROR 5', 'UDX_CLIENT_OPEN_ERROR 99999999999',
                    b'UDX_CLIENT_OPEN_ERROR 5'):
            self.assertIsNone(tool.parse_open_error(bad), bad)

    def test_cpp_client_prints_the_error_before_exit_1(self):
        src = (ROOT / 'windows' / 'udx_sid_client.cpp').read_text(encoding='utf-8')
        line = 'fwprintf(stderr, L"UDX_CLIENT_OPEN_ERROR %lu\\n", err);'
        self.assertIn(line, src)
        self.assertLess(src.index('const DWORD err = GetLastError();'), src.index(line))
        self.assertLess(src.index(line), src.index('return 1;', src.index(line)))
        # stdout stays free; exit codes unchanged
        self.assertNotIn('wprintf(L"UDX_CLIENT_OPEN_ERROR', src)


class CiWiring(unittest.TestCase):
    def test_ci_job_runs_the_matrix(self):
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        self.assertIn('windows-principal-matrix:', ci)
        job = ci[ci.index('windows-principal-matrix:'):]
        self.assertIn('python tools/w25_principal_matrix.py --output', job)
        self.assertIn('exit $code', job)
        self.assertNotIn('continue-on-error', job.split('\n  windows-', 1)[0])


if __name__ == '__main__':
    unittest.main()
