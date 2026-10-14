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
        'source_sha256': {x: (W15.PINNED_NATIVE_TEST_SHA256 if x == 'tests/test_w12_windows_pipe.py' else '0'*64)
                          for x in W15.SOURCE_FILES},
        'native_suite': {
            'tests_run': 47, 'success': True, 'all_native_cases_pass': True,
            'cases': [{'id': test_id, 'status': 'PASS', 'elapsed_seconds': 0.01}
                      for test_id in sorted(W15.EXPECTED_NATIVE_TEST_IDS)],
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
        self.assertIn('NATIVE_TEST_ID_SET_DRIFT', W15._check_report(data)['issues'])

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


class W16AdversarialTests(unittest.TestCase):
    def test_type_confusion_malformed_cases_never_raise(self):
        for bad in ([], {}, 17, False, None, ['arbitrary'], float('nan')):
            with self.subTest(bad=repr(bad)):
                d = sample()
                d['native_suite']['cases'][0]['id'] = bad
                verdict = W15._check_report(d)
                self.assertFalse(verdict['schema_ok'])
                self.assertIn('INVALID_CASE_ID_TYPE', verdict['issues'])

    def test_exact_test_ids_not_just_count_and_class_names(self):
        d = sample()
        d['native_suite']['cases'][0]['id'] = (
            'test_w12_windows_pipe.WindowsPipeFaultInjection.test_fake_but_pass')
        d['native_suite']['cases'][1]['id'] = (
            'test_w12_windows_pipe.WindowsPipeRuntime.test_another_fake_but_pass')
        verdict = W15._check_report(d)
        self.assertIn('NATIVE_TEST_ID_SET_DRIFT', verdict['issues'])

    def test_invalid_signed_like_source_claims_fail(self):
        d = sample()
        d['source_sha256']['tests/test_w12_windows_pipe.py'] = '1' * 64
        self.assertIn('NATIVE_TEST_SOURCE_NOT_PINNED', W15._check_report(d)['issues'])
        d = sample()
        d['source_sha256'][5] = '0' * 64
        self.assertIn('MISSING_SOURCE_HASHES', W15._check_report(d)['issues'])
        d = sample()
        d['manual_gates'][3] = 'NOT_EXECUTED'
        self.assertIn('MANUAL_GATE_CLAIM_CONFLICT', W15._check_report(d)['issues'])

    def test_missing_or_bad_durations_fail(self):
        for bad in (None, True, -1, float('nan'), 10**350, 5000, '0.2'):
            with self.subTest(bad=repr(bad)):
                d = sample()
                if bad is None:
                    del d['native_suite']['cases'][0]['elapsed_seconds']
                else:
                    d['native_suite']['cases'][0]['elapsed_seconds'] = bad
                self.assertIn('NATIVE_CASE_NOT_PASSED', W15._check_report(d)['issues'])

    def test_bad_run_count_bool_not_accepted(self):
        d = sample(); d['native_suite']['tests_run'] = True
        self.assertIn('INVALID_CASE_COUNT', W15._check_report(d)['issues'])

    def test_untrusted_report_schema_never_release(self):
        d = sample()
        self.assertEqual(W15._check_report(d)['verdict'], 'UNTRUSTED_REPORT_SCHEMA_VALID')
        self.assertFalse(W15._check_report(d)['release_authorized'])

    def test_cli_input_limit_and_nonfinite_denied(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / 'report.json'
            p.write_bytes(b'a' * (W15.MAX_REPORT_BYTES + 1))
            self.assertEqual(W15.main(['--verify', str(p)]), 2)
            p.write_text('NaN', encoding='utf-8')
            self.assertEqual(W15.main(['--verify', str(p)]), 2)

    def test_worker_output_privacy(self):
        import inspect
        source = inspect.getsource(W15.run_worker)
        self.assertIn('output_redacted', source)
        for forbidden in ("'captured_test_stdout_tail':", "'captured_test_stderr_tail':", "'runner_text':"):
            self.assertNotIn(forbidden, source)

    def test_collector_does_not_embed_unredacted_stderr(self):
        import inspect
        source = inspect.getsource(W15.collect)
        self.assertNotIn("'diagnostic_tail': diagnostic", source)
        self.assertIn("'diagnostic_code':", source)

    def test_source_hash_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / 'repo';repo.mkdir()
            secret = pathlib.Path(tmp) / 'secret';secret.write_text('do not read', encoding='utf-8')
            for item in W15.SOURCE_FILES:
                q = repo / item;q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text('fixture', encoding='utf-8')
            (repo/W15.SOURCE_FILES[0]).unlink()
            (repo/W15.SOURCE_FILES[0]).symlink_to(secret)
            with self.assertRaisesRegex(RuntimeError, 'UNSAFE_SOURCE_PATH'):
                W15.source_hashes(repo)

    def test_linux_collect_remains_denied(self):
        with mock.patch.object(W15, 'is_windows', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_WINDOWS_REQUIRED'):
                W15.collect(ROOT)


if __name__ == '__main__':
    unittest.main()
