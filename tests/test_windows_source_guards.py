"""Static source checks are NOT Windows runtime security tests."""
from pathlib import Path
import unittest

DIR=Path(__file__).resolve().parents[1]/'windows'
class WindowsCandidateSourceAudit(unittest.TestCase):
    def test_no_default_dacl_or_remote_flag_omission(self):
        s=(DIR/'udx_sid_probe.cpp').read_text()
        for expected in ['ConvertStringSecurityDescriptorToSecurityDescriptorW',
                         'FILE_FLAG_FIRST_PIPE_INSTANCE', 'PIPE_REJECT_REMOTE_CLIENTS',
                         'ImpersonateNamedPipeClient', 'OpenThreadToken', 'EqualSid',
                         'RevertToSelf', 'ReadFile']:
            self.assertIn(expected,s)
        self.assertIn('D:P(A;;GA;;;SY)',s)
    def test_explicit_client_impersonation_level(self):
        s=(DIR/'udx_sid_client.cpp').read_text()
        self.assertIn('SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION',s)
