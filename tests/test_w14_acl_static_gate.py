"""Portable research-contract negatives. These do not stand in for Win32 tests."""
import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('w14_gate', ROOT/'tools'/'w14_acl_static_gate.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class W14PortableGateTests(unittest.TestCase):
    def test_current_structural_contract_never_approves_release(self):
        info = GATE.audit(ROOT)
        self.assertTrue(info['diagnostic_ok'], info['findings'])
        self.assertFalse(info['merge_release_authorized'])
        self.assertEqual(info['verdict'], 'BLOCKED_NO_WINDOWS_EVIDENCE')

    def test_aliased_instance_right_is_exposed(self):
        info = GATE.audit(ROOT)
        self.assertTrue(info['rights_observation']['file_create_pipe_instance_allowed'])
        self.assertFalse(info['rights_observation']['explicit_write_dac_allowed'])
        self.assertFalse(info['rights_observation']['explicit_write_owner_allowed'])

    def test_system_ga_regression_is_rejected(self):
        from udx_ref import windows_pipe as wp
        with mock.patch.object(wp, 'build_sddl', return_value='D:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-18)'):
            result = GATE.audit(ROOT)
        self.assertFalse(result['diagnostic_ok'])
        self.assertIn('SDDL_CHANGED', {x['code'] for x in result['findings']})

    def test_pipe_flag_regressions_are_rejected(self):
        src = (ROOT/'udx_ref'/'windows_pipe.py').read_text(encoding='utf-8')
        import ast
        tree = ast.parse(src)
        constants = GATE._constants(tree)
        flags, _ = GATE._find_server_flags(tree, constants)
        self.assertTrue(flags[0] & constants['FILE_FLAG_FIRST_PIPE_INSTANCE'])
        self.assertTrue(flags[1] & constants['PIPE_REJECT_REMOTE_CLIENTS'])
        removed = src.replace('PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,',
                              'PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,')
        changed, _ = GATE._find_server_flags(ast.parse(removed), constants)
        self.assertFalse(changed[0] & constants['FILE_FLAG_FIRST_PIPE_INSTANCE'])

    def test_grgw_is_not_equivalent_to_explicit_client_least_privilege(self):
        self.assertEqual(GATE.GRGW_MASK & GATE.FILE_CREATE_PIPE_INSTANCE, 4)
        self.assertEqual(GATE.GRGW_MASK & (GATE.WRITE_DAC | GATE.WRITE_OWNER | GATE.DELETE), 0)

    def test_auditor_blocks_when_baseline_head_is_wrong(self):
        with mock.patch.object(GATE, 'EXPECTED_HEAD', '0'*40):
            result = GATE.audit(ROOT)
        self.assertIn('HEAD_UNVERIFIED', {x['code'] for x in result['findings']})
        self.assertFalse(result['merge_release_authorized'])


if __name__ == '__main__':
    unittest.main()
