"""UDX W15 local Win32 evidence collector, with a permanently blocked release claim.

No privileges, account creation, network or repository mutations.  All claims
are bounded to the individual machine and SHA values observed by this process.
External JSON is untrusted; neither verify nor collect grants a release.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import math
import contextlib
import re
import json
import os
import pathlib
import platform
import subprocess
import sys
import time
import unittest

BASELINE_HEAD = '26309e997fea1ac90edba8a51e457fd494cac978'
SOURCE_FILES = (
    'udx_ref/windows_pipe.py',
    'windows/udx_sid_probe.cpp',
    'windows/udx_sid_client.cpp',
    'tools/w14_acl_static_gate.py',
    'tests/test_w12_windows_pipe.py',
    'tools/w15_windows_evidence.py',
    'tests/test_w15_windows_evidence.py',
)
EXPECTED_NATIVE_CLASSES = ('WindowsPipeRuntime', 'WindowsPipeFaultInjection')
EXPECTED_NATIVE_COUNT = 47  # 23 runtime + 24 fault-injection tests pinned to W14
# W16: bytes pinned to reviewed original W14 test source. Use autocrlf=false in Windows checkout.
PINNED_NATIVE_TEST_SHA256 = '30cfbd31ba7b856df7dd3ff525cb2ab0908e1b2a2ca74d89709c4d9ce1a88aff'
EXPECTED_NATIVE_TEST_IDS = frozenset((
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_anonymous_level_value_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_appcontainer_token_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_async_exception_after_impersonation_still_reverts',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_client_pid_failure_injected',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_close_before_write_gives_no_peer_ok',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_close_during_serve_defers_release_to_serving_thread',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_close_releases_handle_even_if_disconnect_raises',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_dropped_server_releases_pipe_name',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_exception_during_pending_io_cancels_before_release',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_failed_cancel_does_not_extend_deadline_unbounded',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_foreign_expected_sid_requires_flag',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_impersonate_failure_injected',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_late_complete_write_counts_as_sent',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_low_integrity_token_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_no_allocation_leak_when_server_sid_text_invalid',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_open_thread_token_failure_after_impersonation_still_reverts',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_other_session_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_read_happens_before_impersonation',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_real_restricted_token_client_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_restricted_flag_denied',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_revert_failure_terminates_process',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_sid_text_failure_is_typed_denial',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_single_use_and_invalid_override',
    'test_w12_windows_pipe.WindowsPipeFaultInjection.test_token_query_failure_injected',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_anonymous_level_denied',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_cli_server_exit_codes_match_cpp',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_client_cannot_request_impersonation',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_client_never_reads_response_is_bounded',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_client_owner_query_failure_is_typed',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_client_refuses_foreign_owner_without_writing',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_client_refuses_injected_foreign_owner',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_dacl_exactly_system_and_current_user',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_identification_level_peer_ok',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_legacy_impersonation_level_client_still_accepted_by_server',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_low_integrity_client_cannot_open_pipe',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_low_integrity_read_only_open_denied',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_no_client_connect_deadline',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_reject_remote_flag_reaches_create_named_pipe',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_same_user_cross_process_peer_ok',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_second_own_instance_refused',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_server_pid_is_logged_not_decisive',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_server_thread_already_impersonating_refuses',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_sid_mismatch_denied',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_silent_client_hits_deadline_without_hang',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_smb_loopback_client_rejected',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_squatted_name_refused_by_first_pipe_instance',
    'test_w12_windows_pipe.WindowsPipeRuntime.test_squatter_sees_only_identification',
))
MAX_REPORT_BYTES = 2 * 1024 * 1024
MANUAL_GATES = (
    'SECOND_ORDINARY_ACCOUNT_DENIAL',
    'REAL_APP_CONTAINER_AND_LOW_IL',
    'ELEVATED_OWNER_AND_EFFECTIVE_ACL',
    'SERVICE_ACCOUNT_SESSION',
    'REMOTE_SECOND_HOST',
    'CPP_NATIVE_BINARY_AND_TIMEOUT_PARITY',
    'INDEPENDENT_SECURITY_REVIEW',
)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def current_head(repo: pathlib.Path) -> str | None:
    try:
        return subprocess.check_output(
            ['git', '-C', str(repo), 'rev-parse', 'HEAD'],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def is_windows() -> bool:
    return sys.platform == 'win32' and os.name == 'nt'


def source_hashes(repo: pathlib.Path) -> dict[str, str]:
    base = repo.resolve(strict=True)
    recorded = {}
    for name in SOURCE_FILES:
        path = repo / name
        # A source symlink could silently hash an unrelated file outside the checkout.
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(base):
            raise RuntimeError('UNSAFE_SOURCE_PATH:' + name)
        recorded[name] = sha256_file(path)
    return recorded


class CaseRecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.case_records = []
        self._started = {}

    def startTest(self, test):
        self._started[test.id()] = time.monotonic()
        super().startTest(test)

    def _record(self, test, status):
        begin = self._started.pop(test.id(), time.monotonic())
        self.case_records.append({
            'id': test.id(), 'status': status,
            'elapsed_seconds': round(time.monotonic() - begin, 6),
        })

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, 'PASS')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, 'FAIL')

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, 'ERROR')

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, 'SKIP')

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._record(test, 'EXPECTED_FAILURE')

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, 'UNEXPECTED_SUCCESS')


def _walk(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _walk(item)
        else:
            yield item


def discover_native_cases(repo: pathlib.Path) -> list:
    """Load exactly the pinned native test module, platform-independent.

    W16b (Codie, Windows lane 2026-10-14): ``tests/`` is not a package (no
    ``__init__.py``), so ``discover(start_dir=tests, top_level_dir=repo)`` raised
    ``ImportError: Start directory is not importable`` on every Python version
    and the worker never ran a single case.  The pinned IDs
    (``test_w12_windows_pipe.<Class>.<method>``) presuppose ``tests/`` as the
    top-level directory.  The source pin is checked BEFORE the import, so module
    code that does not match the pinned bytes is never executed.
    """
    if sha256_file(repo / 'tests/test_w12_windows_pipe.py') != PINNED_NATIVE_TEST_SHA256:
        raise RuntimeError('NATIVE_TEST_SOURCE_NOT_PINNED')
    loader = unittest.TestLoader()
    try:
        discovered = loader.discover(str(repo / 'tests'), pattern='test_w12_windows_pipe.py',
                                     top_level_dir=str(repo / 'tests'))
    except ImportError:
        raise RuntimeError('NATIVE_TEST_IMPORT_FAILED') from None
    if loader.errors:
        raise RuntimeError('NATIVE_TEST_IMPORT_FAILED')
    return [x for x in _walk(discovered) if x.__class__.__name__ in EXPECTED_NATIVE_CLASSES]


def run_worker(repo: pathlib.Path) -> dict:
    if not is_windows():
        raise RuntimeError('NATIVE_WINDOWS_REQUIRED')
    cases = discover_native_cases(repo)
    case_ids = [x.id() for x in cases]
    if len(case_ids) != len(EXPECTED_NATIVE_TEST_IDS) or set(case_ids) != EXPECTED_NATIVE_TEST_IDS:
        raise RuntimeError('NATIVE_TEST_ID_SET_DRIFT')
    counts = {name: sum(x.__class__.__name__ == name for x in cases) for name in EXPECTED_NATIVE_CLASSES}
    if counts != {'WindowsPipeRuntime': 23, 'WindowsPipeFaultInjection': 24}:
        raise RuntimeError('NATIVE_TEST_DISCOVERY_DRIFT: ' + repr(counts))
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, resultclass=CaseRecordingResult, verbosity=1)
    captured_stdout, captured_stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        result = runner.run(unittest.TestSuite(cases))
    return {
        'tests_run': result.testsRun,
        'cases': result.case_records,
        'success': result.wasSuccessful(),
        'all_native_cases_pass': bool(result.wasSuccessful() and result.testsRun == len(cases)
                                      and all(c['status'] == 'PASS' for c in result.case_records)),
        # No raw test logs: they may contain local paths, SIDs, account names or tokens.
        'output_redacted': True,
        'raw_test_output_present': bool(stream.getvalue() or captured_stdout.getvalue() or captured_stderr.getvalue()),
    }


def _check_report(data: object, *, repo: pathlib.Path | None = None) -> dict:
    """Schema and local-file consistency only, NOT attestation verification."""
    issues = []
    if type(data) is not dict:
        return {'schema_ok': False, 'issues': ['INVALID_DOCUMENT'],
                'release_authorized': False, 'verdict': 'BLOCKED'}
    if data.get('schema') != 'UDX_W15_NATIVE_EVIDENCE_V1':
        issues.append('SCHEMA_MISMATCH')
    if data.get('git_head') != BASELINE_HEAD:
        issues.append('HEAD_MISMATCH')
    if data.get('collector_platform') != 'win32':
        issues.append('NO_WINDOWS_RUN')
    result = data.get('native_suite')
    if type(result) is not dict:
        issues.append('MISSING_NATIVE_SUITE')
    else:
        cases = result.get('cases')
        if type(cases) is not list or len(cases) != EXPECTED_NATIVE_COUNT or type(result.get('tests_run')) is not int or result['tests_run'] != EXPECTED_NATIVE_COUNT:
            issues.append('INVALID_CASE_COUNT')
        else:
            ids = [c.get('id') if type(c) is dict else None for c in cases]
            if any(type(test_id) is not str for test_id in ids):
                issues.append('INVALID_CASE_ID_TYPE')
            else:
                if len(set(ids)) != len(ids):
                    issues.append('DUPLICATE_CASE_IDS')
                if set(ids) != EXPECTED_NATIVE_TEST_IDS:
                    issues.append('NATIVE_TEST_ID_SET_DRIFT')
                actual_classes = {name: sum('.' + name + '.' in test_id for test_id in ids) for name in EXPECTED_NATIVE_CLASSES}
                if actual_classes != {'WindowsPipeRuntime': 23, 'WindowsPipeFaultInjection': 24}:
                    issues.append('NATIVE_CLASS_COVERAGE_DRIFT')
            if any(type(c) is not dict or c.get('status') != 'PASS' or
                   type(c.get('elapsed_seconds')) not in (int, float) or
                   (type(c.get('elapsed_seconds')) is float and
                    not math.isfinite(c.get('elapsed_seconds'))) or
                   not (0 <= c.get('elapsed_seconds', -1) <= 3600) for c in cases):
                issues.append('NATIVE_CASE_NOT_PASSED')
        if result.get('all_native_cases_pass') is not True or result.get('success') is not True:
            issues.append('NATIVE_SUITE_FAILED_OR_SKIPPED')
    if data.get('subprocess_exitcode') != 0:
        issues.append('COLLECTOR_EXIT_NONZERO')
    hashes = data.get('source_sha256')
    if type(hashes) is not dict or set(hashes) != set(SOURCE_FILES):
        issues.append('MISSING_SOURCE_HASHES')
    elif any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None for value in hashes.values()):
        issues.append('INVALID_HASH_ENCODING')
    else:
        if hashes['tests/test_w12_windows_pipe.py'] != PINNED_NATIVE_TEST_SHA256:
            issues.append('NATIVE_TEST_SOURCE_NOT_PINNED')
    if type(hashes) is dict and set(hashes) == set(SOURCE_FILES) and repo is not None:
        for name in SOURCE_FILES:
            file = repo / name
            if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(repo.resolve()) or sha256_file(file) != hashes[name]:
                issues.append('SOURCE_CHANGED:' + name)
    gates = data.get('manual_gates')
    if type(gates) is not dict or set(gates) != set(MANUAL_GATES) or any(
        value != 'NOT_EXECUTED' for value in gates.values()
    ):
        issues.append('MANUAL_GATE_CLAIM_CONFLICT')
    if data.get('release_authorized') is not False:
        issues.append('UNSAFE_RELEASE_CLAIM')
    return {
        'schema_ok': not issues,
        'issues': issues,
        'release_authorized': False,
        'verdict': 'UNTRUSTED_REPORT_SCHEMA_VALID' if not issues else 'BLOCKED',
        'note': 'This checks syntax and local hashes, not provenance or independent reviewer identity.',
    }


def collect(repo: pathlib.Path, *, timeout: int = 300) -> dict:
    if not is_windows():
        raise RuntimeError('NATIVE_WINDOWS_REQUIRED')
    if current_head(repo) != BASELINE_HEAD:
        raise RuntimeError('W14_ORIGINAL_HEAD_REQUIRED')
    if not all((repo / x).is_file() for x in SOURCE_FILES):
        raise RuntimeError('SOURCE_FILES_MISSING')
    hashes_before = source_hashes(repo)
    if hashes_before['tests/test_w12_windows_pipe.py'] != PINNED_NATIVE_TEST_SHA256:
        raise RuntimeError('NATIVE_TEST_SOURCE_NOT_PINNED')
    args = [sys.executable, str(pathlib.Path(__file__).resolve()), '--worker', '--repo', str(repo)]
    now = time.time()
    try:
        proc = subprocess.run(args, cwd=repo, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False,
                              env={**os.environ, 'PYTHONPATH': str(repo)})
        rc = proc.returncode
        diagnostic = (proc.stderr or '')[-10000:]
        if rc == 0:
            try:
                worker = json.loads(proc.stdout)
            except (json.JSONDecodeError, UnicodeError):
                worker, rc = None, 3
                diagnostic += '\nWORKER_OUTPUT_NOT_JSON'
        else:
            worker = None
    except subprocess.TimeoutExpired:
        worker, rc, diagnostic = None, 124, 'WIN32_SUITE_TIMEOUT'
    if source_hashes(repo) != hashes_before or current_head(repo) != BASELINE_HEAD:
        raise RuntimeError('SOURCE_CHANGED_DURING_TEST')
    report = {
        'schema': 'UDX_W15_NATIVE_EVIDENCE_V1',
        'collector_platform': sys.platform,
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'python': platform.python_version(),
        'python_executable_sha256': sha256_file(pathlib.Path(sys.executable)),
        'git_head': current_head(repo),
        'source_sha256': hashes_before,
        'collected_unix_utc': round(now, 3),
        'elapsed_wall_seconds': round(time.time() - now, 3),
        'command_template': 'python tools/w15_windows_evidence.py --worker --repo <audited_repo>',
        'subprocess_exitcode': rc,
        'native_suite': worker,
        'diagnostic_code': ('WIN32_SUITE_TIMEOUT' if rc == 124 else
                            'WORKER_OUTPUT_NOT_JSON' if rc == 3 else
                            'WORKER_EXIT_NONZERO' if rc != 0 else 'OK'),
        'manual_gates': {g: 'NOT_EXECUTED' for g in MANUAL_GATES},
        'release_authorized': False,
    }
    report['self_check'] = _check_report(report, repo=repo)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--collect', action='store_true')
    group.add_argument('--verify', type=pathlib.Path)
    group.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    group.add_argument('--schema', action='store_true')
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    if args.schema:
        payload = {'schema': 'UDX_W15_NATIVE_EVIDENCE_V1', 'baseline_head': BASELINE_HEAD,
                   'manual_gates': MANUAL_GATES, 'release_authorized': False}
        code = 0
    elif args.verify:
        try:
            if args.verify.stat().st_size > MAX_REPORT_BYTES:
                raise ValueError('REPORT_SIZE_LIMIT_EXCEEDED')
            payload = _check_report(json.loads(args.verify.read_text(encoding='utf-8'),
                                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NON_FINITE_JSON'))), repo=repo)
            code = 0 if payload['schema_ok'] else 2
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            payload = {'schema_ok': False, 'issues': [type(exc).__name__],
                       'release_authorized': False, 'verdict': 'BLOCKED'}
            code = 2
    elif args.worker:
        payload = run_worker(repo)
        code = 0 if payload['all_native_cases_pass'] else 2
    else:
        try:
            payload = collect(repo, timeout=args.timeout)
            code = 0 if payload['self_check']['schema_ok'] else 2
        except (RuntimeError, OSError) as exc:
            payload = {'schema': 'UDX_W15_NATIVE_EVIDENCE_V1',
                       'error': str(exc) if isinstance(exc, RuntimeError) and str(exc) in (
                           'NATIVE_WINDOWS_REQUIRED', 'W14_ORIGINAL_HEAD_REQUIRED',
                           'SOURCE_FILES_MISSING', 'NATIVE_TEST_SOURCE_NOT_PINNED',
                           'SOURCE_CHANGED_DURING_TEST') else 'COLLECTOR_RUNTIME_ERROR',
                       'release_authorized': False, 'verdict': 'BLOCKED'}
            code = 2
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
