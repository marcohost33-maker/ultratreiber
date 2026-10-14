"""Portable research-contract negatives. These do not stand in for Win32 tests."""
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('w14_gate', ROOT/'tools'/'w14_acl_static_gate.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def _git(repo, *args):
    # Isolated from the developer's global/system git config (signing, hooks).
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    return subprocess.check_output(
        ['git', '-C', str(repo), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
         '-c', 'commit.gpgsign=false', *args], text=True, env=env,
        stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL).strip()


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


class W14PortableGateTests(unittest.TestCase):
    def test_current_structural_contract_never_approves_release(self):
        # Structural contract only: decoupled from the git state of the checkout
        # (ancestry is covered by W14AncestryAndPinTests with a real temp repo).
        with mock.patch.object(GATE, 'baseline_is_ancestor', return_value=True):
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


class W14AncestryAndPinTests(unittest.TestCase):
    def test_baseline_must_be_ancestor_of_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, b, c = make_lineage(tmp)
            with mock.patch.object(GATE, 'EXPECTED_HEAD', a):
                self.assertTrue(GATE.baseline_is_ancestor(repo, b))   # descendant
                self.assertTrue(GATE.baseline_is_ancestor(repo, a))   # baseline itself
                self.assertFalse(GATE.baseline_is_ancestor(repo, c))  # foreign lineage
            with mock.patch.object(GATE, 'EXPECTED_HEAD', b):
                self.assertFalse(GATE.baseline_is_ancestor(repo, a))  # older than baseline
            with mock.patch.object(GATE, 'EXPECTED_HEAD', '1' * 40):
                self.assertFalse(GATE.baseline_is_ancestor(repo, b))  # baseline absent (shallow)

    def test_foreign_head_without_real_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _a, b, c = make_lineage(tmp)
            self.assertFalse(GATE.baseline_is_ancestor(repo, b))
            self.assertFalse(GATE.baseline_is_ancestor(repo, c))

    def test_malformed_heads_and_missing_git_fail_closed(self):
        for bad in (None, '', 'HEAD', '--help', 'A' * 40, '0' * 39, 17, ['x']):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(GATE.baseline_is_ancestor(ROOT, bad))
        with mock.patch.object(GATE.subprocess, 'run', side_effect=OSError('no git')):
            self.assertFalse(GATE.baseline_is_ancestor(ROOT, GATE.EXPECTED_HEAD))

    def test_symbolic_and_abbreviated_refs_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, b, _c = make_lineage(tmp)
            with mock.patch.object(GATE, 'EXPECTED_HEAD', a):
                self.assertTrue(GATE.baseline_is_ancestor(repo, b))  # positive control
                for ref in ('HEAD', 'HEAD~0', b[:12]):
                    with self.subTest(ref=ref):
                        self.assertFalse(GATE.baseline_is_ancestor(repo, ref))

    def test_replace_graft_cannot_fake_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, a, _b, c = make_lineage(tmp)
            _git(repo, 'replace', '--graft', c, a)   # local lie: C "descends" from A
            self.assertEqual(_git(repo, 'merge-base', a, c), a)  # plain git now believes it
            with mock.patch.object(GATE, 'EXPECTED_HEAD', a):
                self.assertFalse(GATE.baseline_is_ancestor(repo, c))

    def test_audit_blocks_foreign_lineage(self):
        with mock.patch.object(GATE, 'baseline_is_ancestor', return_value=False):
            result = GATE.audit(ROOT)
        self.assertFalse(result['diagnostic_ok'])
        self.assertIn('HEAD_UNVERIFIED', {x['code'] for x in result['findings']})

    def test_pinned_sources_match_current_tree(self):
        self.assertEqual(GATE.source_hash_drift(ROOT), [])

    def test_source_hash_drift_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            for name in GATE.PINNED_SOURCE_SHA256:
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, repo / name)
            self.assertEqual(GATE.source_hash_drift(repo), [])
            target = repo / 'udx_ref' / 'windows_pipe.py'
            target.write_bytes(target.read_bytes() + b'\n')
            self.assertEqual(GATE.source_hash_drift(repo), ['udx_ref/windows_pipe.py'])
            target.unlink()
            self.assertEqual(GATE.source_hash_drift(repo), ['udx_ref/windows_pipe.py'])
        drifted = dict(GATE.PINNED_SOURCE_SHA256, **{'windows/udx_sid_probe.cpp': '0' * 64})
        with mock.patch.object(GATE, 'PINNED_SOURCE_SHA256', drifted), \
                mock.patch.object(GATE, 'baseline_is_ancestor', return_value=True):
            result = GATE.audit(ROOT)
        self.assertIn('SOURCE_HASH_DRIFT', {x['code'] for x in result['findings']})
        self.assertFalse(result['diagnostic_ok'])


if __name__ == '__main__':
    unittest.main()
