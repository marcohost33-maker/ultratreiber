"""UDX W15 local Win32 evidence collector, with a permanently blocked release claim.

No privileges, account creation, network or repository mutations.  All claims
are bounded to the individual machine and SHA values observed by this process.
External JSON is untrusted; neither verify nor collect grants a release.
"""
from __future__ import annotations

import argparse
import hashlib
import io
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
    return {path: sha256_file(repo / path) for path in SOURCE_FILES}


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


def run_worker(repo: pathlib.Path) -> dict:
    if not is_windows():
        raise RuntimeError('NATIVE_WINDOWS_REQUIRED')
    loader = unittest.TestLoader()
    discovered = loader.discover(str(repo / 'tests'), pattern='test_w12_windows_pipe.py', top_level_dir=str(repo))
    cases = [x for x in _walk(discovered) if x.__class__.__name__ in EXPECTED_NATIVE_CLASSES]
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
        'runner_text': stream.getvalue()[-20000:],
        'captured_test_stdout_tail': captured_stdout.getvalue()[-5000:],
        'captured_test_stderr_tail': captured_stderr.getvalue()[-5000:],
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
        if type(cases) is not list or len(cases) != EXPECTED_NATIVE_COUNT or result.get('tests_run') != len(cases):
            issues.append('INVALID_CASE_COUNT')
        elif len({x.get('id') for x in cases if type(x) is dict}) != len(cases):
            issues.append('DUPLICATE_CASE_IDS')
        elif any(type(c) is not dict or c.get('status') != 'PASS' or
                 not any('.' + name + '.' in c.get('id', '') for name in EXPECTED_NATIVE_CLASSES) for c in cases):
            issues.append('NATIVE_CASE_NOT_PASSED')
        if type(cases) is list and len(cases) == EXPECTED_NATIVE_COUNT:
            actual_classes = {name: sum('.' + name + '.' in c.get('id', '') for c in cases if type(c) is dict) for name in EXPECTED_NATIVE_CLASSES}
            if actual_classes != {'WindowsPipeRuntime': 23, 'WindowsPipeFaultInjection': 24}:
                issues.append('NATIVE_CLASS_COVERAGE_DRIFT')
        if result.get('all_native_cases_pass') is not True or result.get('success') is not True:
            issues.append('NATIVE_SUITE_FAILED_OR_SKIPPED')
    if data.get('subprocess_exitcode') != 0:
        issues.append('COLLECTOR_EXIT_NONZERO')
    hashes = data.get('source_sha256')
    if type(hashes) is not dict or sorted(hashes) != sorted(SOURCE_FILES):
        issues.append('MISSING_SOURCE_HASHES')
    elif any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None for value in hashes.values()):
        issues.append('INVALID_HASH_ENCODING')
    elif repo is not None:
        for name in SOURCE_FILES:
            file = repo / name
            if not file.is_file() or sha256_file(file) != hashes[name]:
                issues.append('SOURCE_CHANGED:' + name)
    gates = data.get('manual_gates')
    if type(gates) is not dict or sorted(gates) != sorted(MANUAL_GATES) or any(
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
    if source_hashes(repo) != hashes_before:
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
        'diagnostic_tail': diagnostic,
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
            payload = _check_report(json.loads(args.verify.read_text(encoding='utf-8')), repo=repo)
            code = 0 if payload['schema_ok'] else 2
        except (OSError, ValueError, UnicodeError) as exc:
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
        except RuntimeError as exc:
            payload = {'schema': 'UDX_W15_NATIVE_EVIDENCE_V1', 'error': str(exc),
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
