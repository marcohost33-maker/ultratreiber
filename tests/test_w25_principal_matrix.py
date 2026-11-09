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


BIN = {'client': 'a' * 64, 'probe': 'b' * 64}
DENIAL = {'level': 1, 'rid': HIGH, 'appc': 0, 'restricted': 1, 'session_ok': 1, 'sid_ok': 1}


def squat_case(name: str, mode: str) -> dict:
    lowf = dict(facts('low_il'))
    if name == 'squat_low_il_medium_label':
        rep = {'created': False, 'create_error': 1314}
        cpp = {'exit': 1, 'open_error': 2, 'inherit': 'handle_list:1'}
        py = {'reason': 'OPEN_FAILED', 'sent': False, 'open_error': 2}
    elif mode == 'standard_account':
        rep = {'created': True, 'owner': USER, 'label_rid': 0x1000, 'received': 0}
        cpp = {'exit': 7, 'open_error': None, 'inherit': 'handle_list:1'}
        py = {'reason': 'PIPE_LABEL_TOO_LOW', 'sent': False, 'open_error': None, 'pipe_label': 0x1000}
    else:
        rep = {'created': True, 'owner': 'S-1-5-32-544', 'label_rid': 0x1000, 'received': 0}
        cpp = {'exit': 5, 'open_error': None, 'inherit': 'handle_list:1'}
        py = {'reason': 'PIPE_OWNER_MISMATCH', 'sent': False, 'open_error': None}
    return {'kind': 'default', 'squatter': {'facts': lowf, 'inherit': 'handle_list:1', 'report': rep},
            'cpp_client': cpp, 'py_client': py}


def good_report(mode: str = 'elevated_admin') -> dict:
    rid = HIGH if mode == 'elevated_admin' else 0x2000
    prod = tool.production_sddl(USER)
    sddl = {kind: tool.sd_variant(prod, kind) for kind in tool.SD_KINDS}
    cases = {}
    for name, (server, sd, principal, cexit, oerr, sexp) in tool.EXPECTED.items():
        f = dict(facts(principal))
        if f['integrity_rid'] == HIGH:
            f['integrity_rid'] = rid
        child = {'exit': cexit, 'open_error': oerr, 'elapsed_s': 0.4, 'facts': f, 'inherit': 'handle_list:1',
                 'stderr': '' if oerr is None else f'UDX_CLIENT_OPEN_ERROR {oerr}\n'}
        case = {'server': server, 'sd': sd, 'principal': principal, 'child': child}
        if server == 'python':
            verdict, reason, identified = sexp
            case['server_sddl'] = sddl[sd]
            case['server_result'] = {'verdict': verdict, 'reason': reason,
                                     'client_sid': USER if identified else None,
                                     'sent': verdict == 'PEER_OK', 'winerror': None}
        else:
            code, denial = sexp
            case['server_result'] = {'exit': code, 'denial': None if denial is None else dict(DENIAL, rid=rid)}
        cases[name] = case
    report = {
        'release_authorized': False,
        'mode': mode,
        'parent': {'user_sid': USER, 'integrity_rid': rid, 'appcontainer': False, 'appcontainer_sid': None,
                   'restricted': False, 'administrators_member': mode == 'elevated_admin'},
        'sddl': sddl,
        'binaries': {k: {'built': v, 'used': v} for k, v in BIN.items()},
        'appcontainer': {'name': 'udx.w25.probe.0123456789ab', 'sid': AC, 'created': True},
        'cases': cases,
        'cleanup': {'appcontainer_profile': 'deleted', 'workdir': 'deleted'},
    }
    report['squat'] = {name: squat_case(name, mode) for name in tool.SQUAT_CASES}
    if mode == 'standard_account':
        report['account'] = {'name': 'udxw25s', 'sid': USER}
        report['cleanup'].update(account='deleted', batch_logon_right='removed', workroot='deleted')
    return report


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
        self._blocked_with(lambda r: r['sddl'].update(control=r['sddl']['production']),
                           'SD_VARIANT_DRIFT:control')
        self._blocked_with(lambda r: r['sddl'].update(label_only=r['sddl']['control']),
                           'SD_VARIANT_DRIFT:label_only')
        self._blocked_with(lambda r: r['sddl'].update(extra='O:'), 'SD_SET_DRIFT')

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


class HardeningW251(unittest.TestCase):
    """W25.1: handle allow-list, attribution SDs, C++ denial facts, binaries,
    standard-account parent."""

    def _issues(self, mutate, mode='elevated_admin'):
        r = good_report(mode)
        mutate(r)
        return tool.evaluate(r)[1]

    def test_standard_account_report_passes(self):
        self.assertEqual(tool.evaluate(good_report('standard_account')), ('PRINCIPAL_MATRIX_OK', []))

    def test_child_must_inherit_only_its_pipe(self):
        self.assertIn('CHILD_INHERITANCE_NOT_LIMITED:py_appcontainer', self._issues(
            lambda r: r['cases']['py_appcontainer']['child'].update(inherit='all')))
        self.assertIn('CHILD_INHERITANCE_NOT_LIMITED:cpp_low_il', self._issues(
            lambda r: r['cases']['cpp_low_il']['child'].pop('inherit')))

    def test_server_must_have_used_the_declared_sd(self):
        # A label_only case served with the fully weakened control SD would make
        # the attribution meaningless.
        self.assertIn('SERVER_SD_NOT_THE_DECLARED_ONE:lbl_appcontainer', self._issues(
            lambda r: r['cases']['lbl_appcontainer'].update(server_sddl=r['sddl']['control'])))
        self.assertIn('SERVER_SD_NOT_THE_DECLARED_ONE:py_low_il', self._issues(
            lambda r: r['cases']['py_low_il'].pop('server_sddl')))

    def test_attribution_cases_exist(self):
        # W25.2: the token's NO_WRITE_UP policy refuses a Low-IL writer on any
        # Medium-labelled pipe, whatever the label mask (measured twice).
        self.assertEqual(tool.EXPECTED['lbl_low_il'][1:5], ('label_only', 'low_il', 1, 5))
        self.assertEqual(tool.EXPECTED['ctl_low_il'][3:6], (1, 5, ('DENIED', 'CONNECT_TIMEOUT', False)))
        self.assertEqual(tool.EXPECTED['lbl_appcontainer'][1:5], ('label_only', 'appcontainer', 1, 5))
        # Falsified hypothesis (CI run 42593419596): the Medium label does NOT stop
        # a lowbox token once the DACL grants AC; the server check has to.
        self.assertEqual(tool.EXPECTED['ace_appcontainer'][1:6],
                         ('acace_only', 'appcontainer', 3, None, ('DENIED', 'INTEGRITY_TOO_LOW', True)))
        self.assertEqual(tool.EXPECTED['ace_same_token'][3], 0)

    def test_sd_variants_differ_by_exactly_one_mechanism(self):
        prod = tool.production_sddl(USER)
        v = {k: tool.sd_variant(prod, k) for k in tool.SD_KINDS}
        self.assertEqual(v['label_only'], prod.replace('(ML;;NWNR;;;ME)', '(ML;;NX;;;ME)'))
        self.assertEqual(v['acace_only'], prod.replace(')S:', ')(A;;0x12008b;;;AC)S:'))
        self.assertEqual(v['control'], v['acace_only'].replace('(ML;;NWNR;;;ME)', '(ML;;NX;;;ME)'))
        # W25.2: every variant keeps an explicit Medium label (the clients require it)
        for k in tool.SD_KINDS:
            self.assertTrue(v[k].endswith(';;;ME)'), k)
        with self.assertRaises(ValueError):
            tool.sd_variant(prod, 'everyone')

    def test_cpp_restricted_denial_must_name_only_the_restricted_flag(self):
        for k, bad in (('restricted', 0), ('sid_ok', 0), ('session_ok', 0), ('appc', 1), ('rid', 0x1000),
                       ('level', 0)):
            self.assertIn('CPP_DENIAL_NOT_ATTRIBUTED:cpp_restricted', self._issues(
                lambda r, k=k, bad=bad: r['cases']['cpp_restricted']['server_result']['denial'].update({k: bad})),
                k)
        self.assertIn('CPP_DENIAL_NOT_ATTRIBUTED:cpp_restricted', self._issues(
            lambda r: r['cases']['cpp_restricted']['server_result'].update(denial={'facts': 'unavailable'})))
        self.assertIn('CPP_UNEXPECTED_DENIAL:cpp_same_token', self._issues(
            lambda r: r['cases']['cpp_same_token']['server_result'].update(denial=dict(DENIAL))))

    def test_binaries_must_be_the_built_ones(self):
        self.assertIn('BINARY_NOT_THE_BUILT_ONE:client', self._issues(
            lambda r: r['binaries']['client'].update(used='c' * 64)))
        self.assertIn('BINARY_NOT_THE_BUILT_ONE:probe', self._issues(lambda r: r['binaries'].pop('probe')))

    def test_mode_must_match_the_parent_facts(self):
        self.assertIn('MODE_INVALID', self._issues(lambda r: r.update(mode='admin')))
        self.assertIn('PARENT_NOT_ELEVATED_ADMIN', self._issues(
            lambda r: r['parent'].update(administrators_member=False)))
        # the W18 lesson: a UAC-filtered admin (Medium, deny-only) is not a standard account
        self.assertIn('PARENT_NOT_STANDARD_ACCOUNT', self._issues(
            lambda r: r['parent'].update(administrators_member=True), 'standard_account'))
        self.assertIn('PARENT_NOT_STANDARD_ACCOUNT', self._issues(
            lambda r: r['parent'].update(integrity_rid=HIGH), 'standard_account'))
        self.assertIn('PARENT_NOT_THE_THROWAWAY_ACCOUNT', self._issues(
            lambda r: r['account'].update(sid='S-1-5-21-9-9-9-1001'), 'standard_account'))

    def test_standard_mode_cleanup(self):
        for key in ('account', 'batch_logon_right', 'workroot', 'workdir'):
            self.assertIn('CLEANUP_INCOMPLETE', self._issues(
                lambda r, key=key: r['cleanup'].pop(key), 'standard_account'), key)

    def test_parse_probe_denial(self):
        line = 'UDX_PROBE_DENIED level=1 rid=12288 appc=0 restricted=1 session_ok=1 sid_ok=1\r\n'
        self.assertEqual(tool.parse_probe_denial(line), dict(DENIAL, rid=12288))
        self.assertEqual(tool.parse_probe_denial('UDX_PROBE_DENIED facts=unavailable\n'), {'facts': 'unavailable'})
        for bad in (None, '', line + line, line.replace('rid=12288 ', ''), line.replace('=1 rid', '=-1 rid'),
                    line.replace('sid_ok=1', 'sid_ok=1 extra=2'), line.replace('appc=0', 'appc=0 appc=0'),
                    line.replace('level=1', 'level1')):
            self.assertIsNone(tool.parse_probe_denial(bad), bad)

    def test_cpp_probe_prints_the_denial_facts(self):
        src = (ROOT / 'windows' / 'udx_sid_probe.cpp').read_text(encoding='utf-8')
        start = src.index('if (!authorized) {')
        block = src[start:src.index('return 20;', start)]
        self.assertIn('UDX_PROBE_DENIED level=%lu rid=%lu appc=%lu restricted=%lu session_ok=%d sid_ok=%d', block)
        self.assertIn('UDX_PROBE_DENIED facts=unavailable', block)
        # the decision itself is unchanged: sid_ok is the same EqualSid result
        self.assertIn('sid_ok = EqualSid(client_sid, server_sid) != 0;', src)
        self.assertIn('&& appc == 0 && restricted == 0 && session == server_session\n                    && sid_ok;', src)

    def test_launcher_uses_a_handle_list_for_every_principal(self):
        src = (ROOT / 'tools' / 'w25_principal_matrix.py').read_text(encoding='utf-8')
        launch = src[src.index('    def launch('):src.index('def _read_all(')]
        self.assertIn('PROC_THREAD_ATTRIBUTE_HANDLE_LIST', launch)
        self.assertEqual(launch.count('EXTENDED_STARTUPINFO_PRESENT'), 1)   # set once, used by both create calls
        self.assertIn('flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT', launch)
        self.assertEqual(launch.count('c.byref(siex), c.byref(pi)'), 2)


class DiscriminationSpec(unittest.TestCase):
    def test_every_mutation_anchor_exists_exactly_once(self):
        # A stale anchor silently drops a mutation (found in W25.1: DK8 after the
        # cleanup rewrite). Each 'alt' must occur once and name an existing test.
        spec = json.loads((ROOT / 'evidence' / 'w25_dk_spec.json').read_text(encoding='utf-8'))
        self.assertGreaterEqual(len(spec['faelle']), 14)
        for f in spec['faelle']:
            src = (ROOT / f['datei']).read_text(encoding='utf-8')
            self.assertEqual(src.count(f['alt']), 1, f['name'])
            path, cls, meth = f['test'].split('::')
            self.assertIn('def %s(' % meth, (ROOT / path).read_text(encoding='utf-8'), f['name'])
            self.assertIn('class %s(' % cls, (ROOT / path).read_text(encoding='utf-8'), f['name'])


class SquatterW252(unittest.TestCase):
    """W25.2: a Low-IL squatter of the same user must never receive a byte."""

    def _issues(self, mutate, mode='standard_account', name='squat_low_il_default'):
        r = good_report(mode)
        mutate(r['squat'][name])
        return tool.evaluate(r)[1]

    def test_both_modes_pass(self):
        for mode in ('standard_account', 'elevated_admin'):
            self.assertEqual(tool.evaluate(good_report(mode)), ('PRINCIPAL_MATRIX_OK', []), mode)

    def test_squat_set_must_be_exact(self):
        r = good_report()
        r['squat'].pop('squat_low_il_medium_label')
        self.assertIn('SQUAT_SET_DRIFT', tool.evaluate(r)[1])

    def test_client_that_accepts_the_squatter_blocks(self):
        # The pre-W25.2 behaviour for a standard account: owner check passes, the client writes.
        self.assertIn('CPP_CLIENT_ACCEPTED_SQUATTER:squat_low_il_default',
                      self._issues(lambda c: c['cpp_client'].update(exit=0)))
        self.assertIn('PY_CLIENT_ACCEPTED_SQUATTER:squat_low_il_default',
                      self._issues(lambda c: c['py_client'].update(reason='OK', sent=True)))
        self.assertIn('SQUATTER_RECEIVED_DATA:squat_low_il_default',
                      self._issues(lambda c: c['squatter']['report'].update(received=1)))
        self.assertIn('CPP_CLIENT_ACCEPTED_SQUATTER:squat_low_il_default',
                      self._issues(lambda c: c['cpp_client'].update(exit=0), 'elevated_admin'))

    def test_standard_mode_needs_the_label_check_not_the_owner_check(self):
        # exit 5 would mean the owner check fired: then the decisive case was not shown
        self.assertIn('CPP_CLIENT_ACCEPTED_SQUATTER:squat_low_il_default',
                      self._issues(lambda c: c['cpp_client'].update(exit=5)))
        self.assertIn('SQUATTER_OWNER_NOT_THE_USER:squat_low_il_default',
                      self._issues(lambda c: c['squatter']['report'].update(owner='S-1-5-32-544')))

    def test_kernel_low_label_and_privilege_refusal_are_pinned(self):
        self.assertIn('SQUATTER_LABEL_NOT_LOW:squat_low_il_default',
                      self._issues(lambda c: c['squatter']['report'].update(label_rid=None)))
        self.assertIn('SQUATTER_RAISED_ITS_LABEL:squat_low_il_medium_label',
                      self._issues(lambda c: c['squatter']['report'].update(created=True),
                                   name='squat_low_il_medium_label'))
        self.assertIn('SQUATTER_RAISED_ITS_LABEL:squat_low_il_medium_label',
                      self._issues(lambda c: c['squatter']['report'].update(create_error=5),
                                   name='squat_low_il_medium_label'))

    def test_squatter_must_really_be_low_il(self):
        self.assertIn('CHILD_INTEGRITY_WRONG:squat_low_il_default',
                      self._issues(lambda c: c['squatter']['facts'].update(integrity_rid=HIGH)))

    def test_squatter_that_could_not_create_blocks_the_default_case(self):
        self.assertIn('SQUATTER_COULD_NOT_CREATE:squat_low_il_default',
                      self._issues(lambda c: c['squatter']['report'].update(created=False)))

    def test_cpp_client_checks_the_label_before_writing(self):
        src = (ROOT / 'windows' / 'udx_sid_client.cpp').read_text(encoding='utf-8')
        label = src.index('LABEL_SECURITY_INFORMATION')
        self.assertLess(src.index('if (!owner_ok)'), label)
        self.assertLess(label, src.index('WriteFile('))
        self.assertIn('if (labels != 1 || label_rid < SECURITY_MANDATORY_MEDIUM_RID) {', src)
        self.assertIn('SYSTEM_MANDATORY_LABEL_ACE_TYPE', src)

    def test_python_client_checks_the_label_before_writing(self):
        src = (ROOT / 'udx_ref' / 'windows_pipe.py').read_text(encoding='utf-8')
        body = src[src.index('def client_ping('):src.index('def main(')]
        self.assertLess(body.index('_verify_pipe_owner(api, h, expected_bin)'),
                        body.index('_verify_pipe_label(api, h)'))
        self.assertLess(body.index('_verify_pipe_label(api, h)'), body.index('api.WriteFile('))
        self.assertIn("if rid is None or rid < SECURITY_MANDATORY_MEDIUM_RID:", src)


class Summary(unittest.TestCase):
    def test_one_line_per_case_without_failing_on_junk(self):
        lines = tool.summary_lines(good_report())
        self.assertEqual(len(lines), len(tool.EXPECTED) + len(tool.SQUAT_CASES))
        self.assertEqual(sum(1 for x in lines if x.startswith('SQUAT ')), len(tool.SQUAT_CASES))
        self.assertTrue(any('CASE py_low_il: rid=0x1000' in x and 'open_error=5' in x for x in lines))
        self.assertEqual(tool.summary_lines(None), [])
        self.assertEqual(len(tool.summary_lines({'cases': {'x': {'error': 'E'}, 'y': 3}})), 1)


class ControlSddl(unittest.TestCase):
    def test_production_literal_matches_the_module(self):
        from udx_ref import windows_pipe as wp
        self.assertEqual(tool.production_sddl(USER), wp.build_sddl(USER))

    def test_control_adds_exactly_ac_ace_and_low_label(self):
        prod = tool.production_sddl(USER)
        ctl = tool.control_sddl(prod)
        self.assertTrue(ctl.endswith(')(A;;0x12008b;;;AC)S:(ML;;NX;;;ME)'))
        self.assertEqual(ctl.replace('(A;;0x12008b;;;AC)', '').replace('(ML;;NX;;;ME)', '(ML;;NWNR;;;ME)'), prod)

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
        self.assertIn('python tools/w25_principal_matrix.py --mode elevated_admin --output', job)
        self.assertIn('python tools/w25_principal_matrix.py --mode standard_account --output', job)
        self.assertIn('exit $code', job)
        self.assertNotIn('continue-on-error', job.split('\n  windows-', 1)[0])


if __name__ == '__main__':
    unittest.main()
