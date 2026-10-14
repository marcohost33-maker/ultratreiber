#!/usr/bin/env python3
"""UDX W14 portable, advisory ACL/transport contract check (NOT an OS access test).

No external dependencies. Never produces release approval, even when all checks pass.
Usage: PYTHONPATH=. python tools/w14_acl_static_gate.py [--repo PATH] [--json PATH]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import re
import subprocess
import sys

# Audited W14 baseline. Public prep: it must be an ANCESTOR of HEAD (a hard
# ``HEAD ==`` pin can never hold for any later commit), and the audited sources
# must be byte-identical to the reviewed bytes below. Keep in sync with
# tools/w15_windows_evidence.py PINNED_SOURCE_SHA256 (a test compares both).
EXPECTED_HEAD = '26309e997fea1ac90edba8a51e457fd494cac978'
PINNED_SOURCE_SHA256 = {
    'udx_ref/windows_pipe.py': '3952c0b1f5722bd6cc07ac8b4e582665dd14181abd4fa6f07eebcd6a5dbd28ea',
    'windows/udx_sid_probe.cpp': '4ea51f360f85f9f4d8016736ddc995751fe3c0a7932bc48627c32e25aa082772',
    'windows/udx_sid_client.cpp': 'bf62f1deadffa79aad0afaca5abfd67e556fd79c0dbf03b15431c1b1913eb49a',
}
_COMMIT_RE = re.compile('[0-9a-f]{40}')
EXPECTED_SID = 'S-1-5-21-1234-5678-9012-1001'
# Windows FILE_GENERIC_READ | FILE_GENERIC_WRITE; do not confuse with least privilege.
GRGW_MASK = 0x0012019F
FILE_CREATE_PIPE_INSTANCE = 0x0004
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
DELETE = 0x00010000


def _value(node, constants: dict[str, int]):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _value(node.left, constants) | _value(node.right, constants)
    raise ValueError(f'unknown expression: {ast.dump(node)}')


def _constants(root: ast.Module) -> dict[str, int]:
    out = {}
    for stmt in root.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            try:
                out[stmt.targets[0].id] = _value(stmt.value, out)
            except ValueError:
                pass
    return out


def _find_server_flags(tree, constants):
    server = next((node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'OneShotPipeServer'), None)
    if server is None:
        return None, None
    init = next((node for node in server.body if isinstance(node, ast.FunctionDef) and node.name == '__init__'), None)
    if init is None:
        return None, None
    pipe_mode = None
    calls = []
    for node in ast.walk(init):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'pipe_mode'):
            pipe_mode = _value(node.value, constants)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'CreateNamedPipeW' and len(node.args) == 8):
            bits = _value(node.args[1], constants)
            if isinstance(node.args[2], ast.Name) and node.args[2].id == 'pipe_mode':
                mode = pipe_mode
            else:
                mode = _value(node.args[2], constants)
            max_instances = _value(node.args[3], constants)
            calls.append(((bits, mode, max_instances), node.lineno))
    if len(calls) != 1:
        return None, None
    return calls[0]


def baseline_is_ancestor(repo: pathlib.Path, head: object) -> bool:
    """git-confirmed ``EXPECTED_HEAD`` ancestor-of ``head``; every error is False (fail-closed)."""
    if type(head) is not str or _COMMIT_RE.fullmatch(head) is None:
        return False
    try:
        proc = subprocess.run(
            ['git', '--no-replace-objects', '-C', str(repo), 'merge-base', '--is-ancestor',
             EXPECTED_HEAD, head],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def source_hash_drift(repo: pathlib.Path) -> list[str]:
    """Pinned sources that are missing, symlinked or not byte-identical to the reviewed bytes."""
    drift = []
    for name, digest in PINNED_SOURCE_SHA256.items():
        path = repo / name
        try:
            ok = (path.is_file() and not path.is_symlink()
                  and hashlib.sha256(path.read_bytes()).hexdigest() == digest)
        except OSError:
            ok = False
        if not ok:
            drift.append(name)
    return drift


def audit(repo: pathlib.Path) -> dict:
    findings = []
    def check(code, ok, explanation):
        if not ok:
            findings.append({'code': code, 'evidence': explanation})
    code_path = repo / 'udx_ref' / 'windows_pipe.py'
    src = code_path.read_text(encoding='utf-8')
    tree = ast.parse(src, filename=str(code_path))
    constants = _constants(tree)
    # Only the specifically evaluated import from this fixed, locally inspected bundle.
    sys.path.insert(0, str(repo))
    from udx_ref import windows_pipe as wp
    sys.path.pop(0)
    expected = 'D:P(A;;GRGW;;;SY)(A;;GRGW;;;' + EXPECTED_SID + ')S:(ML;;NWNR;;;ME)'
    check('SDDL_CHANGED', wp.build_sddl(EXPECTED_SID) == expected,
          'W14 protected SY+user GRGW DACL and Medium NWNR SACL are required')
    flags, line = _find_server_flags(tree, constants)
    check('CREATE_NOT_FOUND', flags is not None, 'Call to CreateNamedPipeW not statically resolved')
    if flags:
        desired, mode, instances = flags
        check('FIRST_INSTANCE_MISSING', bool(desired & constants['FILE_FLAG_FIRST_PIPE_INSTANCE']),
              f'CreateNamedPipeW at {line}: FIRST_PIPE_INSTANCE absent')
        check('OVERLAPPED_MISSING', bool(desired & constants['FILE_FLAG_OVERLAPPED']),
              f'CreateNamedPipeW at {line}: FILE_FLAG_OVERLAPPED absent')
        check('REMOTE_REJECT_MISSING', bool(mode & constants['PIPE_REJECT_REMOTE_CLIENTS']),
              f'CreateNamedPipeW at {line}: REMOTE_REJECT absent')
        check('INSTANCE_COUNT_CHANGED', instances == 1, f'CreateNamedPipeW at {line}: instances={instances}')
    cpp = (repo / 'windows' / 'udx_sid_probe.cpp').read_text(encoding='utf-8')
    check('CPP_SDDL_DRIFT', 'L"D:P(A;;GRGW;;;SY)(A;;GRGW;;;"' in cpp and 'L")S:(ML;;NWNR;;;ME)"' in cpp,
          'Uncompiled C++ prototype SDDL differs from W14 research contract')
    check('CPP_PIPE_FLAGS_DRIFT', 'PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE' in cpp and
          'PIPE_REJECT_REMOTE_CLIENTS' in cpp, 'C++ pipe flags missing; source check only')
    # Explicitly surface the privilege alias even in structurally successful builds.
    check('MASK_UNEXPECTED',
          (GRGW_MASK & FILE_CREATE_PIPE_INSTANCE) == FILE_CREATE_PIPE_INSTANCE and
          (GRGW_MASK & (WRITE_DAC | WRITE_OWNER | DELETE)) == 0,
          'Expected GRGW mask rights have changed')
    try:
        head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        head = None
    check('HEAD_UNVERIFIED', baseline_is_ancestor(repo, head),
          'HEAD does not descend from the audited W14 baseline (or ancestry is unverifiable)')
    drift = source_hash_drift(repo)
    check('SOURCE_HASH_DRIFT', not drift,
          'Audited sources differ from the reviewed bytes: ' + ', '.join(drift))
    try:
        dirty = bool(subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        dirty = True
    return {
        'schema_version': 1, 'gate': 'W14_PORTABLE_DIAGNOSTIC_ONLY',
        'head': head, 'working_tree_dirty': dirty,
        'diagnostic_ok': not findings, 'findings': findings,
        'rights_observation': {'grgw_access_mask': hex(GRGW_MASK),
                               'file_create_pipe_instance_allowed': True,
                               'explicit_write_dac_allowed': False,
                               'explicit_write_owner_allowed': False},
        'owner_implicit_rights': 'UNVERIFIED_WINDOWS_RUNTIME',
        'windows_second_account_access_check': 'NOT_EXECUTED',
        'windows_appcontainer_uac_and_service_matrix': 'NOT_EXECUTED',
        'cxx_binary_and_timing_parity': 'NOT_EXECUTED',
        'merge_release_authorized': False,
        'verdict': 'BLOCKED_NO_WINDOWS_EVIDENCE',
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--json', type=pathlib.Path)
    args = parser.parse_args(argv)
    result = audit(args.repo.resolve())
    payload = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.json:
        args.json.write_text(payload, encoding='utf-8')
    else:
        print(payload, end='')
    return 0 if result['diagnostic_ok'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
