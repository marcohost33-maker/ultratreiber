"""W20: the account-matrix verdict is decided from the report alone and fails closed.

The Windows lane itself runs in CI (job ``windows-account-matrix``) as an elevated
administrator on the throwaway hosted runner, because it creates and deletes
local accounts. These portable tests pin the decision function: a complete
report passes, and every single missing or contradicting fact blocks it.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
try:
    import w20_account_matrix as tool
finally:
    sys.path.pop(0)

A, B, ADMIN = 'S-1-5-21-1-2-3-1001', 'S-1-5-21-1-2-3-1002', 'S-1-5-21-1-2-3-500'


def good_report() -> dict:
    std = {'administrators_member': False, 'administrators_deny_only': None, 'elevation_type': 1,
           'integrity_rid': 0x2000, 'session_id': 0}
    return {
        'release_authorized': False,
        'facts': {'A': dict(std, user_sid=A), 'B': dict(std, user_sid=B),
                  'admin': {'user_sid': ADMIN, 'administrators_member': True, 'elevation_type': 2,
                            'integrity_rid': 0x3000}},
        'cases': {'admin_open': {'opened': False, 'winerror': 5},
                  'second_account': {'reason': 'OPEN_FAILED', 'open_error': 5, 'sent': False},
                  'same_account': {'reason': 'OK', 'open_error': None, 'sent': True},
                  'server': {'verdict': 'PEER_OK', 'reason': 'OK', 'client_sid': A}},
        'collector': {'collect_exit': 0, 'verify_exit': 0, 'verify_verdict': 'UNTRUSTED_REPORT_SCHEMA_VALID',
                      'cases': 47, 'passed': 47, 'run_as': 'A'},
    }


class EvaluateAccountMatrix(unittest.TestCase):
    def test_complete_report_passes(self):
        self.assertEqual(tool.evaluate(good_report()), ('STANDARD_ACCOUNT_LANE_OK', []))

    def _blocked_with(self, mutate, issue):
        r = good_report()
        mutate(r)
        verdict, issues = tool.evaluate(r)
        self.assertEqual(verdict, 'BLOCKED')
        self.assertIn(issue, issues)

    def test_filtered_admin_is_not_a_standard_account(self):
        # The W18 local run: Administrators present as deny-only, Medium IL.
        def m(r):
            r['facts']['A'].update(administrators_member=True, administrators_deny_only=True, elevation_type=3)
        self._blocked_with(m, 'NOT_STANDARD_ACCOUNT:A')

    def test_elevation_and_integrity_must_be_observed(self):
        self._blocked_with(lambda r: r['facts']['B'].update(elevation_type=None), 'ELEVATION_TYPE_NOT_DEFAULT:B')
        self._blocked_with(lambda r: r['facts']['A'].update(integrity_rid=0x1000), 'INTEGRITY_NOT_MEDIUM:A')
        self._blocked_with(lambda r: r['facts'].pop('B'), 'FACTS_MISSING:B')

    def test_principals_must_be_distinct(self):
        self._blocked_with(lambda r: r['facts']['B'].update(user_sid=A), 'PRINCIPALS_NOT_DISTINCT')
        self._blocked_with(lambda r: r['facts']['admin'].update(user_sid=A), 'PRINCIPALS_NOT_DISTINCT')

    def test_second_account_must_be_denied_at_open(self):
        self._blocked_with(lambda r: r['cases']['second_account'].update(reason='PIPE_OWNER_MISMATCH', open_error=None),
                           'SECOND_ACCOUNT_NOT_DENIED')
        self._blocked_with(lambda r: r['cases']['second_account'].update(sent=True), 'SECOND_ACCOUNT_NOT_DENIED')

    def test_admin_open_and_controls(self):
        self._blocked_with(lambda r: r['cases']['admin_open'].update(opened=True, winerror=0), 'ADMIN_OPEN_NOT_DENIED')
        self._blocked_with(lambda r: r['cases']['same_account'].update(reason='OPEN_FAILED'),
                           'SAME_ACCOUNT_CONTROL_FAILED')
        self._blocked_with(lambda r: r['cases']['server'].update(client_sid=B), 'SERVER_DID_NOT_IDENTIFY_A')
        self._blocked_with(lambda r: r['cases'].pop('server'), 'CASE_SET_DRIFT')

    def test_collector_must_be_47_of_47_as_a(self):
        self._blocked_with(lambda r: r['collector'].update(passed=46), 'COLLECTOR_NOT_47_OF_47')
        self._blocked_with(lambda r: r['collector'].update(verify_exit=2), 'COLLECTOR_EXIT_NONZERO')
        self._blocked_with(lambda r: r['collector'].update(run_as='admin'), 'COLLECTOR_NOT_RUN_AS_A')
        self._blocked_with(lambda r: r.pop('collector'), 'COLLECTOR_MISSING')

    def test_error_and_release_claim_block(self):
        self._blocked_with(lambda r: r.update(error='RuntimeError: X'), 'ORCHESTRATION_ERROR')
        self._blocked_with(lambda r: r.update(release_authorized=True), 'RELEASE_CLAIM')
        self.assertEqual(tool.evaluate([]), ('BLOCKED', ['REPORT_NOT_OBJECT']))

    def test_good_report_is_not_mutated(self):
        r = good_report()
        before = copy.deepcopy(r)
        tool.evaluate(r)
        self.assertEqual(r, before)


class PortableEntryPoint(unittest.TestCase):
    def test_non_windows_refuses_without_claim(self):
        if sys.platform == 'win32':
            self.skipTest('non-Windows path only')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = tool.main([])
        report = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report['verdict'], 'NATIVE_WINDOWS_REQUIRED')
        self.assertFalse(report['release_authorized'])


if __name__ == '__main__':
    unittest.main()
