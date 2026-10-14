"""Portable, negative-first validation of W15 witness/claim boundary."""
import copy
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('w15_windows_evidence', ROOT / 'tools' / 'w15_windows_evidence.py')
W15 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W15)


def sample():
    return {
        'schema': 'UDX_W15_NATIVE_EVIDENCE_V1',
        'collector_platform': 'win32',
        'git_head': W15.BASELINE_HEAD,
        'subprocess_exitcode': 0,
        'source_sha256': {x: '0'*64 for x in W15.SOURCE_FILES},
        'native_suite': {
            'tests_run': 47, 'success': True, 'all_native_cases_pass': True,
            'cases': ([{'id': f'test_w12_windows_pipe.WindowsPipeRuntime.test_{i}', 'status': 'PASS'} for i in range(23)] +
                      [{'id': f'test_w12_windows_pipe.WindowsPipeFaultInjection.test_{i}', 'status': 'PASS'} for i in range(24)]),
        },
        'manual_gates': {x: 'NOT_EXECUTED' for x in W15.MANUAL_GATES},
        'release_authorized': False,
    }


class W15EvidenceTests(unittest.TestCase):
    def test_synthetic_report_never_can_authorize_release(self):
        record = W15._check_report(sample())
        self.assertTrue(record['schema_ok'], record['issues'])
        self.assertFalse(record['release_authorized'])
        self.assertEqual(record['verdict'], 'UNTRUSTED_REPORT_SCHEMA_VALID')

    def test_incomplete_class_coverage_rejected(self):
        data = sample()
        data['native_suite']['cases'] = data['native_suite']['cases'][:23] + data['native_suite']['cases'][:24]
        self.assertIn('DUPLICATE_CASE_IDS', W15._check_report(data)['issues'])
        data = sample()
        data['native_suite']['cases'][-1]['id'] = 'test_w12_windows_pipe.WindowsPipeRuntime.test_extra'
        self.assertIn('NATIVE_CLASS_COVERAGE_DRIFT', W15._check_report(data)['issues'])

    def test_skipped_native_case_rejected(self):
        data = sample()
        data['native_suite']['cases'][1]['status'] = 'SKIP'
        self.assertIn('NATIVE_CASE_NOT_PASSED', W15._check_report(data)['issues'])

    def test_wrong_head_rejected(self):
        data = sample(); data['git_head'] = '0' * 40
        self.assertIn('HEAD_MISMATCH', W15._check_report(data)['issues'])

    def test_linux_claim_rejected(self):
        data = sample(); data['collector_platform'] = 'linux'
        self.assertIn('NO_WINDOWS_RUN', W15._check_report(data)['issues'])

    def test_release_forgery_rejected(self):
        data = sample(); data['release_authorized'] = True
        self.assertIn('UNSAFE_RELEASE_CLAIM', W15._check_report(data)['issues'])

    def test_self_claim_second_account_not_accepted(self):
        data = sample(); data['manual_gates']['SECOND_ORDINARY_ACCOUNT_DENIAL'] = 'PASS'
        self.assertIn('MANUAL_GATE_CLAIM_CONFLICT', W15._check_report(data)['issues'])

    def test_invalid_hash_encoding_rejected(self):
        data = sample(); data['source_sha256'][W15.SOURCE_FILES[0]] = 'not-a-hash'
        self.assertIn('INVALID_HASH_ENCODING', W15._check_report(data)['issues'])

    def test_failed_subprocess_rejected(self):
        data = sample(); data['subprocess_exitcode'] = 124
        self.assertIn('COLLECTOR_EXIT_NONZERO', W15._check_report(data)['issues'])

    def test_missing_case_and_duplicate_case_rejected(self):
        data = sample(); data['native_suite']['tests_run'] = 0
        self.assertIn('INVALID_CASE_COUNT', W15._check_report(data)['issues'])
        data = sample(); data['native_suite']['cases'][1]['id'] = data['native_suite']['cases'][0]['id']
        self.assertIn('DUPLICATE_CASE_IDS', W15._check_report(data)['issues'])

    def test_wrong_hash_and_traversal_never_deref_unlisted(self):
        data = sample()
        with tempfile.TemporaryDirectory() as tmp:
            for file in W15.SOURCE_FILES:
                path = pathlib.Path(tmp, file); path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('source', encoding='utf-8')
            self.assertTrue(any(x.startswith('SOURCE_CHANGED:') for x in W15._check_report(data, repo=pathlib.Path(tmp))['issues']))
        data = sample(); data['source_sha256']['../../secret'] = '0'*64
        self.assertIn('MISSING_SOURCE_HASHES', W15._check_report(data)['issues'])

    def test_no_windows_collect_or_worker(self):
        with mock.patch.object(W15, 'is_windows', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_WINDOWS_REQUIRED'):
                W15.collect(ROOT)
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_WINDOWS_REQUIRED'):
                W15.run_worker(ROOT)

    def test_invalid_schema_rejected(self):
        data = sample(); data['schema'] = 'something else'
        self.assertIn('SCHEMA_MISMATCH', W15._check_report(data)['issues'])
        self.assertFalse(W15._check_report(None)['schema_ok'])


if __name__ == '__main__':
    unittest.main()
