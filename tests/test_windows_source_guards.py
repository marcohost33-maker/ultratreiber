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
        self.assertIn('D:P(A;;0x12008b;;;SY)',s)     # W18 (was GRGW until W17)
    def test_explicit_client_impersonation_level(self):
        # W13 protocol inversion (Aegis P1-a): Identification + EFFECTIVE_ONLY,
        # static tracking; the client must never grant Impersonation.
        s=(DIR/'udx_sid_client.cpp').read_text()
        self.assertIn('SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY',s)
        self.assertNotIn('SECURITY_IMPERSONATION',s)
        self.assertNotIn('SECURITY_CONTEXT_TRACKING',s)
    def test_client_checks_pipe_owner_before_write(self):
        s=(DIR/'udx_sid_client.cpp').read_text()
        self.assertIn('OWNER_SECURITY_INFORMATION',s)
        self.assertLess(s.index('OWNER_SECURITY_INFORMATION'), s.index('WriteFile('))
        self.assertNotIn('GetNamedPipeServerProcessId',s)
    def test_client_opens_with_individual_rights(self):
        # W18: GENERIC_WRITE maps to FILE_GENERIC_WRITE, which contains
        # FILE_APPEND_DATA == FILE_CREATE_PIPE_INSTANCE; the DACL no longer grants it.
        s=(DIR/'udx_sid_client.cpp').read_text()
        self.assertIn('constexpr DWORD access = FILE_GENERIC_READ | FILE_WRITE_DATA;',s)
        self.assertIn('CreateFileW(name, access,',s)
        self.assertNotIn('GENERIC_READ | GENERIC_WRITE',s)
