"""Portable, negative-first validation of W15 witness/claim boundary."""
import copy
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('w15_windows_evidence', ROOT / 'tools' / 'w15_windows_evidence.py')
W15 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W15)


def _git(repo, *args):
    # Isolated from the developer's global/system git config (signing, hooks).
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    return subprocess.check_output(
        ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
         '-c', 'commit.gpgsign=false', *args], text=True, env=env, stderr=subprocess.DEVNULL).strip()


def make_lineage(tmp):
    """Temp repo: A -> B (B descends from A) plus an orphan C. Returns (repo, A, B, C)."""
    if shutil.which('git') is None:
        raise unittest.SkipTest('GIT_NOT_AVAILABLE')
    repo = pathlib.Path(tmp) / 'lineage'
    repo.mkdir()
    _git(repo, 'init', '-q')
    _git(repo, 'commit', '-q', '--allow-empty', '-m', 'a')
    a = _git(repo, 'rev-parse', 'HEAD')
    _git(repo, 'commit', '-q', '--allow-empty', '-m', 'b')
    b = _git(repo, 'rev-parse', 'HEAD')
    c = _git(repo, 'commit-tree', a + '^{tree}', '-m', 'orphan')
    return repo, a, b, c


def sample():
    return {
        'schema': 'UDX_W15_NATIVE_EVIDENCE_V1',
        'collector_platform': 'win32',
        'git_head': W15.BASELINE_HEAD,
        'subprocess_exitcode': 0,
        'source_sha256': {x: W15.PINNED_SOURCE_SHA256.get(x, '0'*64) for x in W15.SOURCE_FILES},
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
        # The guard is exercised on every platform: ``is_symlink`` is simulated for
        # one regular in-tree file, so no symlink privilege is needed (a standard
        # Windows user gets WinError 1314 for a real link). Only the is_symlink
        # half can trigger here; the resolve-escape half is the real-link test below.
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / 'repo';repo.mkdir()
            for item in W15.SOURCE_FILES:
                q = repo / item;q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text('fixture', encoding='utf-8')
            self.assertEqual(set(W15.source_hashes(repo)), set(W15.SOURCE_FILES))  # positive control
            flagged = repo / W15.SOURCE_FILES[0]
            real_is_symlink = pathlib.Path.is_symlink
            with mock.patch.object(pathlib.Path, 'is_symlink', autospec=True,
                                   side_effect=lambda p: p == flagged or real_is_symlink(p)):
                with self.assertRaisesRegex(RuntimeError, 'UNSAFE_SOURCE_PATH'):
                    W15.source_hashes(repo)

    def test_source_hash_real_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / 'repo';repo.mkdir()
            secret = pathlib.Path(tmp) / 'secret';secret.write_text('do not read', encoding='utf-8')
            for item in W15.SOURCE_FILES:
                q = repo / item;q.parent.mkdir(parents=True, exist_ok=True)
                q.write_text('fixture', encoding='utf-8')
            (repo/W15.SOURCE_FILES[0]).unlink()
            try:
                (repo/W15.SOURCE_FILES[0]).symlink_to(secret)
            except OSError as exc:
                self.skipTest('SYMLINK_PRIVILEGE_UNAVAILABLE: %s (guard covered by the simulated test)'
                              % type(exc).__name__)
            with self.assertRaisesRegex(RuntimeError, 'UNSAFE_SOURCE_PATH'):
                W15.source_hashes(repo)

    def test_worker_discovery_yields_exact_pinned_ids(self):
        # W16b: the worker's own discovery path must resolve the 47 pinned IDs on
        # any platform (it raised ImportError before and never ran natively).
        try:
            cases = W15.discover_native_cases(ROOT)
        except RuntimeError as exc:          # typed fail-closed error = this guard's red
            self.fail('worker discovery path broken: %s' % exc)
        ids = [case.id() for case in cases]
        self.assertEqual(len(ids), W15.EXPECTED_NATIVE_COUNT)
        self.assertEqual(set(ids), W15.EXPECTED_NATIVE_TEST_IDS)

    def test_worker_discovery_checks_pin_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            (repo / 'tests').mkdir()
            marker = repo / 'imported.marker'
            (repo / 'tests' / 'test_w12_windows_pipe.py').write_text(
                'import pathlib\npathlib.Path(%r).write_text("x")\n' % str(marker), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_TEST_SOURCE_NOT_PINNED'):
                W15.discover_native_cases(repo)
            self.assertFalse(marker.exists())

    def test_linux_collect_remains_denied(self):
        with mock.patch.object(W15, 'is_windows', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'NATIVE_WINDOWS_REQUIRED'):
                W15.collect(ROOT)


class PublicPrepAncestryAndPinTests(unittest.TestCase):
    """Hard ``HEAD == 26309e9`` pin replaced by ancestry + exact pinned source bytes."""

    def test_baseline_must_be_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, b, c = make_lineage(tmp)
            with mock.patch.object(W15, 'BASELINE_HEAD', a):
                self.assertTrue(W15.descends_from_baseline(repo, b))
                self.assertTrue(W15.descends_from_baseline(repo, a))
                self.assertFalse(W15.descends_from_baseline(repo, c))
            with mock.patch.object(W15, 'BASELINE_HEAD', b):
                self.assertFalse(W15.descends_from_baseline(repo, a))
            # The real W14 baseline object is absent here (like a shallow clone).
            self.assertFalse(W15.descends_from_baseline(repo, b))

    def test_malformed_heads_and_missing_git_fail_closed(self):
        for bad in (None, '', 'HEAD', '--help', 'A' * 40, '0' * 39, 17, ['x']):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(W15.descends_from_baseline(ROOT, bad))
        with mock.patch.object(W15.subprocess, 'run', side_effect=OSError('no git')):
            self.assertFalse(W15.descends_from_baseline(ROOT, W15.BASELINE_HEAD))

    def test_replace_graft_cannot_fake_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, _b, c = make_lineage(tmp)
            _git(repo, 'replace', '--graft', c, a)
            self.assertEqual(_git(repo, 'merge-base', a, c), a)  # the graft is active for plain git
            with mock.patch.object(W15, 'BASELINE_HEAD', a):
                self.assertFalse(W15.descends_from_baseline(repo, c))

    def test_collect_rejects_foreign_lineage(self):
        # A checkout whose history does not contain 26309e9 stays rejected, before any test runs.
        with tempfile.TemporaryDirectory() as tmp:
            repo, _a, _b, _c = make_lineage(tmp)
            with mock.patch.object(W15, 'is_windows', return_value=True), \
                    mock.patch.object(W15.subprocess, 'run', wraps=W15.subprocess.run) as run:
                with self.assertRaisesRegex(RuntimeError, 'W14_BASELINE_NOT_ANCESTOR'):
                    W15.collect(repo)
            self.assertFalse(any('--worker' in call.args[0] for call in run.call_args_list))

    def test_collect_rejects_pinned_source_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            for name in W15.SOURCE_FILES:
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, repo / name)
            target = repo / 'udx_ref' / 'windows_pipe.py'
            target.write_bytes(target.read_bytes() + b'\n')
            with mock.patch.object(W15, 'is_windows', return_value=True), \
                    mock.patch.object(W15, 'current_head', return_value='a' * 40), \
                    mock.patch.object(W15, 'descends_from_baseline', return_value=True), \
                    mock.patch.object(W15.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'PINNED_SOURCE_DRIFT'):
                    W15.collect(repo)
            run.assert_not_called()

    def test_report_with_repo_checks_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, b, c = make_lineage(tmp)
            with mock.patch.object(W15, 'BASELINE_HEAD', a):
                d = sample(); d['git_head'] = c
                self.assertIn('HEAD_MISMATCH', W15._check_report(d, repo=repo)['issues'])
                d = sample(); d['git_head'] = b
                self.assertNotIn('HEAD_MISMATCH', W15._check_report(d, repo=repo)['issues'])
        d = sample(); d['git_head'] = 'b' * 40   # no repo: only the baseline itself is confirmable
        self.assertIn('HEAD_MISMATCH', W15._check_report(d)['issues'])

    def test_report_pinned_source_drift_rejected(self):
        d = sample(); d['source_sha256']['udx_ref/windows_pipe.py'] = '1' * 64
        verdict = W15._check_report(d)
        self.assertIn('PINNED_SOURCE_DRIFT:udx_ref/windows_pipe.py', verdict['issues'])
        self.assertEqual(verdict['verdict'], 'BLOCKED')

    def test_pinned_sources_match_current_tree(self):
        self.assertEqual(W15.pinned_source_drift(W15.source_hashes(ROOT)), [])

    def test_pins_agree_with_w14_gate(self):
        spec = importlib.util.spec_from_file_location('w14_gate_pins', ROOT / 'tools' / 'w14_acl_static_gate.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        self.assertEqual(gate.EXPECTED_HEAD, W15.BASELINE_HEAD)
        for name, digest in gate.PINNED_SOURCE_SHA256.items():
            self.assertEqual(W15.PINNED_SOURCE_SHA256[name], digest, name)


if __name__ == '__main__':
    unittest.main()
