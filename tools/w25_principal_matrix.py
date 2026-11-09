"""W25: real Low-IL, AppContainer and restricted-token principals as separate processes.

RESEARCH ONLY. Until W24 the server-side token checks for a Low-IL client
(``INTEGRITY_TOO_LOW``), an AppContainer client (``APPCONTAINER_CLIENT``) and a
restricted token (``RESTRICTED_TOKEN``) were evidenced only with INJECTED token
facts (``tests/test_w12_windows_pipe.py``, fault-injection half of the 47
pinned cases). W20 covered second accounts, not sandboxed principals of the same
user. This tool starts the compiled C++ client (``windows/udx_sid_client.cpp``)
as a real, separate process under a real kernel token of each kind:

  same_token    CreateProcessAsUserW with an unmodified duplicate of this
                process' token (positive control for the launcher path)
  low_il        the same duplicate with the integrity label set to Low (S-1-16-4096)
  appcontainer  CreateProcessW with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
                for a throwaway AppContainer profile (no capabilities)
  restricted    CreateRestrictedToken whose restricting SIDs are the user and
                every enabled group: the smallest change the kernel still flags as
                restricted (IsTokenRestricted). It tests the server's
                RESTRICTED_TOKEN check, it is not a sandbox.

Every child is created SUSPENDED; its token facts (user SID, integrity RID,
AppContainer flag and SID, restricted flag) are read from the child process
before it runs, so a launcher that silently failed to apply the restriction
cannot produce a green case.

Two layers, each against the production security descriptor first:

  layer 1  production SD (``build_sddl``; C++ probe: the same SDDL). Low IL and
           AppContainer must be refused AT OPEN with ERROR_ACCESS_DENIED
           (mandatory label NW|NR at Medium; the DACL has no AppContainer ACE),
           the server must see no connection at all. The restricted token passes
           the DACL (its restricting set contains the user) and must be refused by
           the server's token check after it identified the user.
  layer 2  CONTROL SD, deliberately weakened for this harness only: Low label
           instead of Medium and an extra ACE for ALL APPLICATION PACKAGES (AC).
           Now the open succeeds and the SERVER must refuse the real token.
           A same-token positive control shows the control SD itself still serves.

Measured design fact recorded in the report: an AppContainer token is always
Low integrity, so the server's integrity check (first in order) refuses it with
INTEGRITY_TOO_LOW; the APPCONTAINER_CLIENT check is defense in depth that a
standard AppContainer token does not reach.

``evaluate`` decides from the report alone and fails closed on any missing,
extra or contradicting fact. Elevated hosted runner (Windows Server): the
parent token is the built-in Administrator, so ``same_token`` is High IL. Not a
Windows 11 result, not a second interactive session, not a release approval.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
LOW_RID, MEDIUM_RID, HIGH_RID = 0x1000, 0x2000, 0x3000
ERROR_ACCESS_DENIED = 5
EXIT_OK, EXIT_OPEN_FAILED, EXIT_BAD_RESPONSE = 0, 1, 3
EXIT_DENIED, EXIT_TIMEOUT = 20, 22
CLIENT_BUDGET_MS = 5000
REFUSED_SERVER_S = 4.0          # Python server deadline when no connection is expected
SERVE_S = 10.0
CPP_REFUSED_BUDGET_MS = 4000
CHILD_LIMIT_S = 15.0            # a client child must end on its own within this
AC_NAME_PREFIX = 'udx.w25.probe.'
PRODUCTION_LABEL = 'S:(ML;;NWNR;;;ME)'
AC_ACE = '(A;;0x12008b;;;AC)'   # ALL APPLICATION PACKAGES, same mask as every production ACE
# W25.2: since the clients require an explicit label >= Medium, the harness can no
# longer open the door for Low clients by LOWERING the label (the client refuses
# a Low-labelled pipe before writing, measured in CI run 42605717757). It keeps
# the Medium label and drops its policy instead: a label ACE's mask IS the policy
# for lower-integrity subjects (SYSTEM_MANDATORY_LABEL_ACE), so mask 0 restricts
# nothing. W25.1 used S:(ML;;NWNR;;;LW) here.
OPEN_LABEL = 'S:(ML;;0x0;;;ME)'
CONTROL_DELTA = (AC_ACE, OPEN_LABEL)
PRINCIPALS = ('same_token', 'low_il', 'appcontainer', 'restricted')
MODES = ('elevated_admin', 'standard_account')
INHERIT = 'handle_list:1'       # W25.1: the child inherits exactly its stdout/stderr pipe
# W25.1 harness-only security descriptors. 'production' is build_sddl unchanged;
# the other three exist to ATTRIBUTE a refusal to one mechanism (factorial):
#   control     +AC ACE, label policy none -> the server's own token check is reached
#   label_only  label policy none, no AC   -> only the DACL can refuse an AppContainer
#   acace_only  +AC ACE, Medium label kept -> does the label alone stop an AppContainer?
#               Measured (CI run 42593419596): NO. For a lowbox token the kernel
#               treats the integrity check as passed when the object label is
#               <= Medium and relies on the AppContainer DACL check (Forshaw,
#               Windows Security Internals, lowbox access check). The W25.1
#               hypothesis "each mechanism alone suffices" was falsified.
SD_KINDS = ('production', 'control', 'label_only', 'acace_only')

# name: (server, sd, principal, client_exit, open_error, server expectation)
# server expectation: python -> (verdict, reason, identified_user: bool)
#                     cpp    -> (exit code, required denial facts or None)
EXPECTED = {
    'py_same_token':   ('python', 'production', 'same_token', EXIT_OK, None, ('PEER_OK', 'OK', True)),
    'py_low_il':       ('python', 'production', 'low_il', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                        ('DENIED', 'CONNECT_TIMEOUT', False)),
    'py_appcontainer': ('python', 'production', 'appcontainer', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                        ('DENIED', 'CONNECT_TIMEOUT', False)),
    'py_restricted':   ('python', 'production', 'restricted', EXIT_BAD_RESPONSE, None,
                        ('DENIED', 'RESTRICTED_TOKEN', True)),
    'ctl_same_token':  ('python', 'control', 'same_token', EXIT_OK, None, ('PEER_OK', 'OK', True)),
    'ctl_low_il':      ('python', 'control', 'low_il', EXIT_BAD_RESPONSE, None,
                        ('DENIED', 'INTEGRITY_TOO_LOW', True)),
    'ctl_appcontainer': ('python', 'control', 'appcontainer', EXIT_BAD_RESPONSE, None,
                         ('DENIED', 'INTEGRITY_TOO_LOW', True)),
    # W25.1 attribution: the Low label alone admits Low IL (so the label was the
    # only reason for the production refusal), but an AppContainer is still
    # refused by the DACL. With the AC ACE and the Medium label kept, the
    # AppContainer OPENS the pipe: the label is no barrier for a lowbox token, the
    # missing AC/package ACE is the only one. The server's integrity check then
    # refuses it (the last line of defense for that case).
    'lbl_low_il':      ('python', 'label_only', 'low_il', EXIT_BAD_RESPONSE, None,
                        ('DENIED', 'INTEGRITY_TOO_LOW', True)),
    'lbl_appcontainer': ('python', 'label_only', 'appcontainer', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                         ('DENIED', 'CONNECT_TIMEOUT', False)),
    'ace_same_token':  ('python', 'acace_only', 'same_token', EXIT_OK, None, ('PEER_OK', 'OK', True)),
    'ace_appcontainer': ('python', 'acace_only', 'appcontainer', EXIT_BAD_RESPONSE, None,
                         ('DENIED', 'INTEGRITY_TOO_LOW', True)),
    'cpp_same_token':  ('cpp', 'production', 'same_token', EXIT_OK, None, (EXIT_OK, None)),
    'cpp_low_il':      ('cpp', 'production', 'low_il', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                        (EXIT_TIMEOUT, None)),
    'cpp_appcontainer': ('cpp', 'production', 'appcontainer', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                         (EXIT_TIMEOUT, None)),
    # W25.1: exit 20 alone is unspecific; the probe's denial line must show that
    # the restricted flag was the ONLY failing fact (identity, level, IL, session ok).
    'cpp_restricted':  ('cpp', 'production', 'restricted', EXIT_BAD_RESPONSE, None,
                        (EXIT_DENIED, {'restricted': 1, 'appc': 0, 'session_ok': 1, 'sid_ok': 1})),
}


# W25.2: a lower-integrity process of the SAME user squats the pipe name before
# the server starts (ADR-UDX-006: only same SID AND same IL is one trust domain).
# Two variants: default security, and an attempt to put an explicit Medium label
# on the pipe. The squatter is a real Low-IL Python process; both clients (C++
# and Python lane) then connect. Invariant: the squatter receives no byte.
SQUAT_CASES = ('squat_low_il_default', 'squat_low_il_medium_label')
# Measured in CI run 42605717757 and pinned:
#  * default: a Low-IL process CAN create the global production name; the kernel
#    labels the pipe Low (0x1000) by itself. Its owner is the creator token's
#    default owner: the user for a standard account (only the W25.2 label check
#    stops the client), BUILTIN\Administrators for an elevated admin's filtered
#    token (the owner check already stops it).
#  * medium_label: CreateNamedPipeW with an explicit Medium label fails with
#    ERROR_PRIVILEGE_NOT_HELD (1314): no label above the creator's own level.
ERROR_PRIVILEGE_NOT_HELD = 1314
ADMINISTRATORS_SID_TEXT = 'S-1-5-32-544'
EXIT_OWNER_MISMATCH = 5
SQUAT_LIFETIME_S = 12.0
EXIT_PIPE_LABEL = 7
ERROR_FILE_NOT_FOUND = 2


# --- pure decision logic (portable, tested on Linux) ---------------------------
def production_sddl(sid: str) -> str:
    """Same string as udx_ref.windows_pipe.build_sddl (kept literal on purpose:
    evaluate() must not trust the module that is under test)."""
    a = '0x12008b'
    return f'O:{sid}D:P(A;;{a};;;SY)(A;;{a};;;{sid})(A;;{a};;;OW){PRODUCTION_LABEL}'


def sd_variant(production: str, kind: str) -> str:
    """Harness-only descriptor ``kind`` derived from the production SDDL."""
    if type(production) is not str or not production.endswith(')' + PRODUCTION_LABEL):
        raise ValueError('NOT_A_PRODUCTION_SDDL')
    if kind not in SD_KINDS:
        raise ValueError('UNKNOWN_SD_KIND')
    body = production[:-len(PRODUCTION_LABEL)]
    return {'production': production,
            'control': body + AC_ACE + OPEN_LABEL,
            'label_only': body + OPEN_LABEL,
            'acace_only': body + AC_ACE + PRODUCTION_LABEL}[kind]


def control_sddl(production: str) -> str:
    """Layer-2 control SD: + ALL APPLICATION PACKAGES ACE, Low label. Harness only."""
    return sd_variant(production, 'control')


def parse_probe_denial(text):
    """The C++ probe's single stderr line ``UDX_PROBE_DENIED k=v ...`` (W25.1) as
    a dict of ints, ``{'facts': 'unavailable'}``, or None (absent/repeated/malformed)."""
    if type(text) is not str:
        return None
    hits = [ln.strip() for ln in text.splitlines() if ln.strip().startswith('UDX_PROBE_DENIED')]
    if len(hits) != 1:
        return None
    parts = hits[0].split(' ')[1:]
    if parts == ['facts=unavailable']:
        return {'facts': 'unavailable'}
    keys = ('level', 'rid', 'appc', 'restricted', 'session_ok', 'sid_ok')
    out = {}
    for part in parts:
        k, sep, v = part.partition('=')
        if not sep or k not in keys or k in out or not v.isdigit() or len(v) > 10:
            return None
        out[k] = int(v)
    return out if tuple(sorted(out)) == tuple(sorted(keys)) else None


def _principal_issues(name: str, principal: str, facts, parent: dict, ac_sid) -> list[str]:
    if not isinstance(facts, dict):
        return ['CHILD_FACTS_MISSING:' + name]
    issues = []
    if facts.get('user_sid') != parent.get('user_sid') or facts.get('user_sid') is None:
        issues.append('CHILD_USER_DRIFT:' + name)
    rid, appc, restricted = facts.get('integrity_rid'), facts.get('appcontainer'), facts.get('restricted')
    want = {
        'same_token': (parent.get('integrity_rid'), False, False),
        'low_il': (LOW_RID, False, False),
        'appcontainer': (LOW_RID, True, False),
        'restricted': (parent.get('integrity_rid'), False, True),
    }[principal]
    if type(rid) is not int or rid != want[0]:
        issues.append('CHILD_INTEGRITY_WRONG:' + name)
    if appc is not want[1]:
        issues.append('CHILD_APPCONTAINER_WRONG:' + name)
    if restricted is not want[2]:
        issues.append('CHILD_RESTRICTED_WRONG:' + name)
    if principal == 'appcontainer':
        if facts.get('appcontainer_sid') != ac_sid or ac_sid is None:
            issues.append('CHILD_APPCONTAINER_SID_WRONG:' + name)
    elif facts.get('appcontainer_sid') is not None:
        issues.append('CHILD_APPCONTAINER_SID_WRONG:' + name)
    return issues


def _parent_issues(report: dict, parent: dict) -> list[str]:
    """W25.1: the parent's kind is a claim of the report and must match its facts."""
    mode = report.get('mode')
    if mode not in MODES:
        return ['MODE_INVALID']
    admin, rid = parent.get('administrators_member'), parent.get('integrity_rid')
    if mode == 'elevated_admin':
        if admin is not True or type(rid) is not int or rid < HIGH_RID:
            return ['PARENT_NOT_ELEVATED_ADMIN']
        return []
    issues = []
    if admin is not False or rid != MEDIUM_RID:
        issues.append('PARENT_NOT_STANDARD_ACCOUNT')
    acct = report.get('account') if isinstance(report.get('account'), dict) else {}
    if acct.get('sid') is None or acct.get('sid') != parent.get('user_sid'):
        issues.append('PARENT_NOT_THE_THROWAWAY_ACCOUNT')
    return issues


def _squat_issues(name: str, c, parent: dict, mode) -> list[str]:
    """Fail-closed, exact decision for one squatter case (see SQUAT_CASES)."""
    if not isinstance(c, dict) or c.get('error'):
        return ['CASE_ERROR:' + name]
    issues = []
    sq = c.get('squatter') if isinstance(c.get('squatter'), dict) else {}
    issues += _principal_issues(name, 'low_il', sq.get('facts'), parent, None)
    cpp = c.get('cpp_client') if isinstance(c.get('cpp_client'), dict) else {}
    py = c.get('py_client') if isinstance(c.get('py_client'), dict) else {}
    for proc in (sq, cpp):
        if proc.get('inherit') != INHERIT:
            issues.append('CHILD_INHERITANCE_NOT_LIMITED:' + name)
            break
    rep_ = sq.get('report') if isinstance(sq.get('report'), dict) else {}
    if name == 'squat_low_il_medium_label':
        if rep_.get('created') is not False or rep_.get('create_error') != ERROR_PRIVILEGE_NOT_HELD:
            issues.append('SQUATTER_RAISED_ITS_LABEL:' + name)
        if (cpp.get('exit'), cpp.get('open_error')) != (EXIT_OPEN_FAILED, ERROR_FILE_NOT_FOUND):
            issues.append('CPP_CLIENT_OUTCOME_WRONG:' + name)
        if (py.get('reason'), py.get('open_error'), py.get('sent')) != ('OPEN_FAILED', ERROR_FILE_NOT_FOUND, False):
            issues.append('PY_CLIENT_OUTCOME_WRONG:' + name)
        return issues
    if rep_.get('created') is not True:
        issues.append('SQUATTER_COULD_NOT_CREATE:' + name)
        return issues
    if type(rep_.get('received')) is not int or rep_['received'] != 0:
        issues.append('SQUATTER_RECEIVED_DATA:' + name)
    if rep_.get('label_rid') != LOW_RID:
        issues.append('SQUATTER_LABEL_NOT_LOW:' + name)
    owner = rep_.get('owner')
    if mode == 'standard_account':
        # The decisive case: the owner check alone would have passed.
        if owner is None or owner != parent.get('user_sid'):
            issues.append('SQUATTER_OWNER_NOT_THE_USER:' + name)
        if cpp.get('exit') != EXIT_PIPE_LABEL:
            issues.append('CPP_CLIENT_ACCEPTED_SQUATTER:' + name)
        if (py.get('reason'), py.get('sent'), py.get('pipe_label')) != ('PIPE_LABEL_TOO_LOW', False, LOW_RID):
            issues.append('PY_CLIENT_ACCEPTED_SQUATTER:' + name)
    else:
        if owner != ADMINISTRATORS_SID_TEXT:
            issues.append('SQUATTER_OWNER_NOT_ADMINISTRATORS:' + name)
        if cpp.get('exit') != EXIT_OWNER_MISMATCH:
            issues.append('CPP_CLIENT_ACCEPTED_SQUATTER:' + name)
        if (py.get('reason'), py.get('sent')) != ('PIPE_OWNER_MISMATCH', False):
            issues.append('PY_CLIENT_ACCEPTED_SQUATTER:' + name)
    return issues


def evaluate(report) -> tuple[str, list[str]]:
    """Return (verdict, issues). Every expectation must be observed explicitly."""
    if not isinstance(report, dict):
        return 'BLOCKED', ['REPORT_NOT_OBJECT']
    issues = []
    if report.get('error'):
        issues.append('ORCHESTRATION_ERROR')
    if report.get('release_authorized') is not False:
        issues.append('RELEASE_CLAIM')
    parent = report.get('parent') if isinstance(report.get('parent'), dict) else {}
    sid = parent.get('user_sid')
    if not isinstance(sid, str) or not sid.startswith('S-1-5-21-'):
        issues.append('PARENT_SID_INVALID')
        sid = None
    if type(parent.get('integrity_rid')) is not int or parent['integrity_rid'] < MEDIUM_RID:
        issues.append('PARENT_INTEGRITY_BELOW_MEDIUM')
    if parent.get('appcontainer') is not False or parent.get('restricted') is not False:
        issues.append('PARENT_NOT_PLAIN')
    issues += _parent_issues(report, parent)
    sddl = report.get('sddl') if isinstance(report.get('sddl'), dict) else {}
    if sid is None or sddl.get('production') != production_sddl(sid):
        issues.append('PRODUCTION_SDDL_DRIFT')
    else:
        for kind in SD_KINDS[1:]:
            if sddl.get(kind) != sd_variant(sddl['production'], kind):
                issues.append('SD_VARIANT_DRIFT:' + kind)
        if set(sddl) != set(SD_KINDS):
            issues.append('SD_SET_DRIFT')
    bins = report.get('binaries') if isinstance(report.get('binaries'), dict) else {}
    for key in ('client', 'probe'):
        b = bins.get(key) if isinstance(bins.get(key), dict) else {}
        if not isinstance(b.get('built'), str) or len(b['built']) != 64 or b.get('used') != b['built']:
            issues.append('BINARY_NOT_THE_BUILT_ONE:' + key)
    ac = report.get('appcontainer') if isinstance(report.get('appcontainer'), dict) else {}
    ac_sid = ac.get('sid') if isinstance(ac.get('sid'), str) and ac['sid'].startswith('S-1-15-2-') else None
    if ac_sid is None:
        issues.append('APPCONTAINER_SID_INVALID')
    cases = report.get('cases') if isinstance(report.get('cases'), dict) else {}
    if set(cases) != set(EXPECTED):
        issues.append('CASE_SET_DRIFT')
    for name in sorted(set(EXPECTED) & set(cases)):
        server, sd, principal, cexit, oerr, sexp = EXPECTED[name]
        c = cases[name]
        if not isinstance(c, dict) or c.get('error'):
            issues.append('CASE_ERROR:' + name)
            continue
        if (c.get('server'), c.get('sd'), c.get('principal')) != (server, sd, principal):
            issues.append('CASE_SHAPE_DRIFT:' + name)
        if server == 'python' and (c.get('server_sddl') is None or c.get('server_sddl') != sddl.get(sd)):
            issues.append('SERVER_SD_NOT_THE_DECLARED_ONE:' + name)
        child = c.get('child') if isinstance(c.get('child'), dict) else {}
        issues += _principal_issues(name, principal, child.get('facts'), parent, ac_sid)
        if child.get('inherit') != INHERIT:
            issues.append('CHILD_INHERITANCE_NOT_LIMITED:' + name)
        if type(child.get('exit')) is not int or child['exit'] != cexit:
            issues.append('CLIENT_EXIT_WRONG:' + name)
        if child.get('open_error') != oerr or (oerr is not None and type(child.get('open_error')) is not int):
            issues.append('CLIENT_OPEN_ERROR_WRONG:' + name)
        el = child.get('elapsed_s')
        if type(el) not in (int, float) or not math.isfinite(el) or el < 0 or el > CHILD_LIMIT_S:
            issues.append('CLIENT_NOT_BOUNDED:' + name)
        srv = c.get('server_result') if isinstance(c.get('server_result'), dict) else {}
        if server == 'python':
            verdict, reason, identified = sexp
            if (srv.get('verdict'), srv.get('reason')) != (verdict, reason):
                issues.append('SERVER_DECISION_WRONG:' + name)
            if identified and (sid is None or srv.get('client_sid') != sid):
                issues.append('SERVER_DID_NOT_IDENTIFY_USER:' + name)
            if not identified and srv.get('client_sid') is not None:
                issues.append('SERVER_SAW_A_CLIENT:' + name)
            if srv.get('sent') is not (verdict == 'PEER_OK'):
                issues.append('SERVER_SENT_WRONG:' + name)
        else:
            code, denial = sexp
            if type(srv.get('exit')) is not int or srv['exit'] != code:
                issues.append('CPP_SERVER_EXIT_WRONG:' + name)
            got = srv.get('denial')
            if denial is None:
                if got is not None:
                    issues.append('CPP_UNEXPECTED_DENIAL:' + name)
            elif not isinstance(got, dict) or any(got.get(k) != v for k, v in denial.items()) \
                    or type(got.get('rid')) is not int or got['rid'] < MEDIUM_RID \
                    or type(got.get('level')) is not int or got['level'] < 1:
                issues.append('CPP_DENIAL_NOT_ATTRIBUTED:' + name)
    squats = report.get('squat') if isinstance(report.get('squat'), dict) else {}
    if set(squats) != set(SQUAT_CASES):
        issues.append('SQUAT_SET_DRIFT')
    for name in sorted(set(SQUAT_CASES) & set(squats)):
        issues += _squat_issues(name, squats[name], parent, report.get('mode'))
    cleanup = report.get('cleanup') if isinstance(report.get('cleanup'), dict) else {}
    want = {'appcontainer_profile': 'deleted', 'workdir': 'deleted'}
    if report.get('mode') == 'standard_account':
        want.update(account='deleted', batch_logon_right='removed', workroot='deleted')
    if any(cleanup.get(k) != v for k, v in want.items()):
        issues.append('CLEANUP_INCOMPLETE')
    return ('PRINCIPAL_MATRIX_OK' if not issues else 'BLOCKED'), issues


def parse_open_error(text) -> int | None:
    """The C++ client's single stderr line ``UDX_CLIENT_OPEN_ERROR <n>`` (W25).
    Anything else (absent, repeated, malformed) is None."""
    if type(text) is not str:
        return None
    hits = [ln.strip() for ln in text.splitlines() if ln.strip().startswith('UDX_CLIENT_OPEN_ERROR')]
    if len(hits) != 1:
        return None
    parts = hits[0].split(' ')
    if len(parts) != 2 or not parts[1].isdigit() or len(parts[1]) > 10:
        return None
    return int(parts[1])


def summary_lines(report) -> list[str]:
    """One line per case for the CI log (synthetic data only: SIDs, codes, times)."""
    if not isinstance(report, dict) or not isinstance(report.get('cases'), dict):
        return []
    out = []
    for name in sorted(report['cases']):
        c = report['cases'][name]
        if not isinstance(c, dict):
            continue
        child = c.get('child') if isinstance(c.get('child'), dict) else {}
        f = child.get('facts') if isinstance(child.get('facts'), dict) else {}
        srv = c.get('server_result') if isinstance(c.get('server_result'), dict) else {}
        server = srv.get('exit') if 'exit' in srv else f"{srv.get('verdict')}/{srv.get('reason')}"
        rid = f.get('integrity_rid')
        out.append(f"CASE {name}: rid={rid:#x} " if type(rid) is int else f"CASE {name}: rid=None ")
        out[-1] += (f"appc={f.get('appcontainer')} restricted={f.get('restricted')} "
                    f"client_exit={child.get('exit')} open_error={child.get('open_error')} "
                    f"t={child.get('elapsed_s')}s inherit={child.get('inherit')} server={server} "
                    f"denial={srv.get('denial')} error={c.get('error')}")
    for name in sorted(report.get('squat') or {}):
        c = report['squat'][name]
        if not isinstance(c, dict):
            continue
        sq = c.get('squatter') if isinstance(c.get('squatter'), dict) else {}
        rep_ = sq.get('report') if isinstance(sq.get('report'), dict) else {}
        cpp = c.get('cpp_client') if isinstance(c.get('cpp_client'), dict) else {}
        py = c.get('py_client') if isinstance(c.get('py_client'), dict) else {}
        f = sq.get('facts') if isinstance(sq.get('facts'), dict) else {}
        out.append(f"SQUAT {name}: squatter_rid={f.get('integrity_rid')} created={rep_.get('created')} "
                   f"create_error={rep_.get('create_error')} owner_is_user={rep_.get('owner') is not None} "
                   f"label_rid={rep_.get('label_rid')} received={rep_.get('received')} "
                   f"cpp_exit={cpp.get('exit')} cpp_stderr={(cpp.get('stderr') or '').strip()[:80]!r} "
                   f"py={py.get('reason')}/{py.get('open_error')} error={c.get('error')}")
    return out


# --- Windows-only launcher -----------------------------------------------------
def _win():
    """ctypes bindings, created lazily so the module imports on Linux."""
    import ctypes
    from ctypes import wintypes as w

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', w.DWORD)]

    class TOKEN_MANDATORY_LABEL(ctypes.Structure):
        _fields_ = [('Label', SID_AND_ATTRIBUTES)]

    class SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [('AppContainerSid', ctypes.c_void_p), ('Capabilities', ctypes.c_void_p),
                    ('CapabilityCount', w.DWORD), ('Reserved', w.DWORD)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR),
                    ('lpTitle', w.LPWSTR), ('dwX', w.DWORD), ('dwY', w.DWORD), ('dwXSize', w.DWORD),
                    ('dwYSize', w.DWORD), ('dwXCountChars', w.DWORD), ('dwYCountChars', w.DWORD),
                    ('dwFillAttribute', w.DWORD), ('dwFlags', w.DWORD), ('wShowWindow', w.WORD),
                    ('cbReserved2', w.WORD), ('lpReserved2', ctypes.c_void_p), ('hStdInput', w.HANDLE),
                    ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE)]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE), ('dwProcessId', w.DWORD),
                    ('dwThreadId', w.DWORD)]

    k = ctypes.WinDLL('kernel32', use_last_error=True)
    a = ctypes.WinDLL('advapi32', use_last_error=True)
    u = ctypes.WinDLL('userenv', use_last_error=True)
    P, H, D, B = ctypes.c_void_p, w.HANDLE, w.DWORD, w.BOOL

    def fn(dll, name, res, *args):
        f = getattr(dll, name)
        f.restype, f.argtypes = res, args
        return f

    api = {
        'GetCurrentProcess': fn(k, 'GetCurrentProcess', H),
        'CloseHandle': fn(k, 'CloseHandle', B, H),
        'ResumeThread': fn(k, 'ResumeThread', D, H),
        'WaitForSingleObject': fn(k, 'WaitForSingleObject', D, H, D),
        'GetExitCodeProcess': fn(k, 'GetExitCodeProcess', B, H, ctypes.POINTER(D)),
        'TerminateProcess': fn(k, 'TerminateProcess', B, H, ctypes.c_uint),
        'LocalFree': fn(k, 'LocalFree', P, P),
        'InitializeProcThreadAttributeList': fn(k, 'InitializeProcThreadAttributeList', B, P, D, D,
                                                ctypes.POINTER(ctypes.c_size_t)),
        'UpdateProcThreadAttribute': fn(k, 'UpdateProcThreadAttribute', B, P, D, ctypes.c_size_t, P,
                                        ctypes.c_size_t, P, P),
        'DeleteProcThreadAttributeList': fn(k, 'DeleteProcThreadAttributeList', None, P),
        'CreateProcessW': fn(k, 'CreateProcessW', B, w.LPCWSTR, w.LPWSTR, P, P, B, D, P, w.LPCWSTR, P, P),
        'OpenProcessToken': fn(a, 'OpenProcessToken', B, H, D, ctypes.POINTER(H)),
        'DuplicateTokenEx': fn(a, 'DuplicateTokenEx', B, H, D, P, ctypes.c_int, ctypes.c_int,
                               ctypes.POINTER(H)),
        'SetTokenInformation': fn(a, 'SetTokenInformation', B, H, ctypes.c_int, P, D),
        'GetTokenInformation': fn(a, 'GetTokenInformation', B, H, ctypes.c_int, P, D, ctypes.POINTER(D)),
        'IsTokenRestricted': fn(a, 'IsTokenRestricted', B, H),
        'CreateRestrictedToken': fn(a, 'CreateRestrictedToken', B, H, D, D, P, D, P, D, P, ctypes.POINTER(H)),
        'CreateProcessAsUserW': fn(a, 'CreateProcessAsUserW', B, H, w.LPCWSTR, w.LPWSTR, P, P, B, D, P,
                                   w.LPCWSTR, P, P),
        'ConvertStringSidToSidW': fn(a, 'ConvertStringSidToSidW', B, w.LPCWSTR, ctypes.POINTER(P)),
        'ConvertSidToStringSidW': fn(a, 'ConvertSidToStringSidW', B, P, ctypes.POINTER(w.LPWSTR)),
        'GetLengthSid': fn(a, 'GetLengthSid', D, P),
        'FreeSid': fn(a, 'FreeSid', P, P),
        'CreateAppContainerProfile': fn(u, 'CreateAppContainerProfile', ctypes.c_long, w.LPCWSTR,
                                        w.LPCWSTR, w.LPCWSTR, P, D, ctypes.POINTER(P)),
        'DeriveAppContainerSidFromAppContainerName': fn(u, 'DeriveAppContainerSidFromAppContainerName',
                                                        ctypes.c_long, w.LPCWSTR, ctypes.POINTER(P)),
        'DeleteAppContainerProfile': fn(u, 'DeleteAppContainerProfile', ctypes.c_long, w.LPCWSTR),
    }
    types = {'SID_AND_ATTRIBUTES': SID_AND_ATTRIBUTES, 'TOKEN_MANDATORY_LABEL': TOKEN_MANDATORY_LABEL,
             'SECURITY_CAPABILITIES': SECURITY_CAPABILITIES, 'STARTUPINFOW': STARTUPINFOW,
             'STARTUPINFOEXW': STARTUPINFOEXW, 'PROCESS_INFORMATION': PROCESS_INFORMATION}
    return ctypes, w, api, types


TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_DEFAULT = 0x1, 0x2, 0x8, 0x80
TOKEN_ALL_ACCESS = 0xF01FF
TokenUser, TokenGroups, TokenIntegrityLevel = 1, 2, 25
TokenIsAppContainer, TokenAppContainerSid = 29, 31
SecurityImpersonation, TokenPrimary = 2, 1
SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY = 0x4, 0x10
SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED = 0x20, 0x40
CREATE_SUSPENDED, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT = 0x4, 0x08000000, 0x80000
STARTF_USESTDHANDLES = 0x100
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
ADMINISTRATORS_SID = 'S-1-5-32-544'
WAIT_OBJECT_0 = 0
HRESULT_ALREADY_EXISTS = -2147024713          # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7


class Win:
    def __init__(self):
        self.ctypes, self.w, self.api, self.t = _win()

    def err(self) -> int:
        return self.ctypes.get_last_error()

    def check(self, ok, what: str):
        if not ok:
            raise OSError(self.err(), what)

    def sid_text(self, psid) -> str:
        out = self.w.LPWSTR()
        self.check(self.api['ConvertSidToStringSidW'](psid, self.ctypes.byref(out)), 'ConvertSidToStringSidW')
        try:
            return out.value
        finally:
            self.api['LocalFree'](self.ctypes.cast(out, self.ctypes.c_void_p))

    def token_info(self, tok, klass: int):
        need = self.w.DWORD(0)
        self.api['GetTokenInformation'](tok, klass, None, 0, self.ctypes.byref(need))
        if need.value == 0 or need.value > 65536:
            raise OSError(self.err(), f'GetTokenInformation size {klass}')
        buf = self.ctypes.create_string_buffer(need.value)
        self.check(self.api['GetTokenInformation'](tok, klass, buf, need, self.ctypes.byref(need)),
                   f'GetTokenInformation {klass}')
        return buf

    def token_facts(self, tok) -> dict:
        # Every buffer stays bound to a local while a SID pointer into it is used.
        c = self.ctypes
        ubuf = self.token_info(tok, TokenUser)
        user_text = self.sid_text(c.c_void_p.from_buffer(ubuf, 0).value)
        lbuf = self.token_info(tok, TokenIntegrityLevel)
        rid = int(self.sid_text(c.c_void_p.from_buffer(lbuf, 0).value).rsplit('-', 1)[1])
        abuf = self.token_info(tok, TokenIsAppContainer)
        appc = c.c_uint32.from_buffer(abuf, 0).value
        ac_sid = None
        if appc:
            sbuf = self.token_info(tok, TokenAppContainerSid)
            p = c.c_void_p.from_buffer(sbuf, 0).value
            ac_sid = self.sid_text(p) if p else None
        return {'user_sid': user_text, 'integrity_rid': rid, 'appcontainer': bool(appc),
                'appcontainer_sid': ac_sid, 'restricted': bool(self.api['IsTokenRestricted'](tok))}

    def process_token(self, hproc, access=TOKEN_QUERY):
        tok = self.w.HANDLE()
        self.check(self.api['OpenProcessToken'](hproc, access, self.ctypes.byref(tok)), 'OpenProcessToken')
        return tok

    def own_facts(self) -> dict:
        """Token facts plus ``administrators_member``: BUILTIN\\Administrators
        enabled and not deny-only (a UAC-filtered token counts as NOT a member)."""
        c = self.ctypes
        tok = self.process_token(self.api['GetCurrentProcess']())
        try:
            facts = self.token_facts(tok)
            gbuf = self.token_info(tok, TokenGroups)
            count = c.c_uint32.from_buffer(gbuf, 0).value
            arr = c.cast(c.addressof(gbuf) + c.sizeof(c.c_void_p), c.POINTER(self.t['SID_AND_ATTRIBUTES']))
            member = False
            for i in range(count):
                if self.sid_text(arr[i].Sid) == ADMINISTRATORS_SID:
                    a = arr[i].Attributes
                    member = bool(a & SE_GROUP_ENABLED) and not a & SE_GROUP_USE_FOR_DENY_ONLY
            facts['administrators_member'] = member
            return facts
        finally:
            self.api['CloseHandle'](tok)

    # -- principals -------------------------------------------------------
    def primary_token(self, principal: str):
        """A primary token for same_token / low_il / restricted (caller closes it)."""
        c, api = self.ctypes, self.api
        base = self.process_token(api['GetCurrentProcess'](),
                                  TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)
        try:
            new = self.w.HANDLE()
            if principal == 'restricted':
                sids = self._restricting_sids(base)
                arr = (self.t['SID_AND_ATTRIBUTES'] * len(sids))()
                for i, s in enumerate(sids):
                    arr[i].Sid, arr[i].Attributes = s, 0
                self.check(api['CreateRestrictedToken'](base, 0, 0, None, 0, None, len(sids), arr,
                                                        c.byref(new)), 'CreateRestrictedToken')
                return new
            self.check(api['DuplicateTokenEx'](base, TOKEN_ALL_ACCESS, None, SecurityImpersonation,
                                               TokenPrimary, c.byref(new)), 'DuplicateTokenEx')
            if principal == 'low_il':
                low = c.c_void_p()
                self.check(api['ConvertStringSidToSidW']('S-1-16-4096', c.byref(low)), 'ConvertStringSidToSidW')
                try:
                    tml = self.t['TOKEN_MANDATORY_LABEL']()
                    tml.Label.Sid, tml.Label.Attributes = low, SE_GROUP_INTEGRITY
                    size = c.sizeof(tml) + api['GetLengthSid'](low)
                    ok = api['SetTokenInformation'](new, TokenIntegrityLevel, c.byref(tml), size)
                    if not ok:
                        e = self.err()
                        api['CloseHandle'](new)
                        raise OSError(e, 'SetTokenInformation(TokenIntegrityLevel)')
                finally:
                    api['LocalFree'](low)
            return new
        finally:
            api['CloseHandle'](base)

    def _restricting_sids(self, tok) -> list:
        """User SID plus every enabled, non-deny-only, non-integrity group SID.
        The pointers live in buffers kept on self until the token exists."""
        c = self.ctypes
        ubuf = self.token_info(tok, TokenUser)
        gbuf = self.token_info(tok, TokenGroups)
        self._keep = (ubuf, gbuf)
        sids = [c.c_void_p.from_buffer(ubuf, 0).value]
        count = c.c_uint32.from_buffer(gbuf, 0).value
        arr = c.cast(c.addressof(gbuf) + c.sizeof(c.c_void_p),
                     c.POINTER(self.t['SID_AND_ATTRIBUTES']))
        for i in range(count):
            attrs = arr[i].Attributes
            if attrs & SE_GROUP_ENABLED and not attrs & (SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_INTEGRITY
                                                         | SE_GROUP_INTEGRITY_ENABLED):
                sids.append(arr[i].Sid)
        return sids

    def appcontainer_profile(self, name: str):
        """(psid, text, created). psid is freed with FreeSid by the caller."""
        c = self.ctypes
        psid = c.c_void_p()
        hr = self.api['CreateAppContainerProfile'](name, 'UDX W25 probe', 'UDX W25 research probe', None, 0,
                                                   c.byref(psid))
        created = True
        if hr == HRESULT_ALREADY_EXISTS:
            created = False
            hr = self.api['DeriveAppContainerSidFromAppContainerName'](name, c.byref(psid))
        if hr != 0 or not psid.value:
            raise OSError(hr & 0xFFFFFFFF, 'CreateAppContainerProfile')
        return psid, self.sid_text(psid), created

    # -- launch -----------------------------------------------------------
    def launch(self, argv: list[str], principal: str, ac_psid=None, cwd: str | None = None) -> dict:
        """Start argv suspended as ``principal``, read the child's token facts,
        resume, wait (bounded). Returns exit, stderr text, facts, elapsed."""
        import msvcrt
        c, api = self.ctypes, self.api
        rfd, wfd = os.pipe()
        hw = msvcrt.get_osfhandle(wfd)
        os.set_handle_inheritable(hw, True)
        cmd = c.create_unicode_buffer(subprocess.list2cmdline(argv))
        pi = self.t['PROCESS_INFORMATION']()
        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT
        token = None
        attr = None
        # W25.1: bInheritHandles=TRUE would hand EVERY inheritable handle of this
        # process to a sandboxed child. PROC_THREAD_ATTRIBUTE_HANDLE_LIST limits
        # inheritance to exactly the stdout/stderr pipe (Microsoft Learn,
        # UpdateProcThreadAttribute; same pattern as CPython subprocess/Go).
        handles = (self.w.HANDLE * 1)(hw)
        try:
            n_attr = 2 if principal == 'appcontainer' else 1
            siex = self.t['STARTUPINFOEXW']()
            si = siex.StartupInfo
            si.cb = c.sizeof(siex)
            si.dwFlags = STARTF_USESTDHANDLES
            si.hStdOutput = si.hStdError = hw
            size = c.c_size_t(0)
            api['InitializeProcThreadAttributeList'](None, n_attr, 0, c.byref(size))
            attr = c.create_string_buffer(size.value)
            self.check(api['InitializeProcThreadAttributeList'](attr, n_attr, 0, c.byref(size)),
                       'InitializeProcThreadAttributeList')
            self.check(api['UpdateProcThreadAttribute'](attr, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                                        c.sizeof(handles), None, None),
                       'UpdateProcThreadAttribute(HANDLE_LIST)')
            if principal == 'appcontainer':
                caps = self.t['SECURITY_CAPABILITIES']()
                caps.AppContainerSid, caps.Capabilities, caps.CapabilityCount = ac_psid, None, 0
                self._caps = caps
                self.check(api['UpdateProcThreadAttribute'](attr, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                            c.byref(caps), c.sizeof(caps), None, None),
                           'UpdateProcThreadAttribute(SECURITY_CAPABILITIES)')
            siex.lpAttributeList = c.addressof(attr)
            if principal == 'appcontainer':
                ok = api['CreateProcessW'](argv[0], cmd, None, None, True, flags, None, cwd,
                                           c.byref(siex), c.byref(pi))
                self.check(ok, 'CreateProcessW(AppContainer)')
            else:
                token = self.primary_token(principal)
                ok = api['CreateProcessAsUserW'](token, argv[0], cmd, None, None, True, flags, None, cwd,
                                                 c.byref(siex), c.byref(pi))
                self.check(ok, 'CreateProcessAsUserW(' + principal + ')')
        except BaseException:
            os.close(rfd)                      # no reader thread will own it
            raise
        finally:
            os.close(wfd)
            if token is not None:
                api['CloseHandle'](token)
            if attr is not None:
                api['DeleteProcThreadAttributeList'](attr)
        chunks = []
        reader = threading.Thread(target=lambda: chunks.append(_read_all(rfd)), daemon=True)
        reader.start()
        try:
            try:
                ctok = self.process_token(pi.hProcess)
                try:
                    facts = self.token_facts(ctok)
                finally:
                    api['CloseHandle'](ctok)
            except OSError:
                api['TerminateProcess'](pi.hProcess, 99)
                raise
            t0 = time.monotonic()
            api['ResumeThread'](pi.hThread)
            killed = api['WaitForSingleObject'](pi.hProcess, int(CHILD_LIMIT_S * 1000) + 5000) != WAIT_OBJECT_0
            if killed:
                api['TerminateProcess'](pi.hProcess, 98)
                api['WaitForSingleObject'](pi.hProcess, 5000)
            elapsed = time.monotonic() - t0
            code = self.w.DWORD(0)
            api['GetExitCodeProcess'](pi.hProcess, c.byref(code))
        finally:
            api['CloseHandle'](pi.hThread)
            api['CloseHandle'](pi.hProcess)
        reader.join(10)
        text = chunks[0] if chunks else ''
        return {'exit': None if killed else int(code.value), 'elapsed_s': round(elapsed, 3), 'facts': facts,
                'stderr': text[-400:], 'output': text[-4000:], 'open_error': parse_open_error(text),
                'inherit': INHERIT}


def _read_all(fd: int) -> str:
    out = b''
    try:
        while len(out) < 65536:
            b = os.read(fd, 4096)
            if not b:
                break
            out += b
    finally:
        os.close(fd)
    return out.decode('utf-8', 'replace')


@contextlib.contextmanager
def _sd_kind(wp, kind: str):
    """Harness only: OneShotPipeServer builds its SD from wp.build_sddl."""
    if kind == 'production':
        yield
        return
    real = wp.build_sddl
    wp.build_sddl = lambda sid: sd_variant(real(sid), kind)
    try:
        yield
    finally:
        wp.build_sddl = real


def _load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / 'tools' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha256(path) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def run_case(win: Win, wp, crossrun, name: str, client: str, probe: str, ac_psid) -> dict:
    server, sd, principal, cexit, _, _ = EXPECTED[name]
    refused = cexit == EXIT_OPEN_FAILED
    case = {'server': server, 'sd': sd, 'principal': principal}
    argv = [client, '--budget-ms', str(CLIENT_BUDGET_MS)]
    cwd = str(pathlib.Path(client).parent)
    if server == 'python':
        box = {}
        with _sd_kind(wp, sd), wp.OneShotPipeServer(wp.DEFAULT_PIPE_NAME) as srv:
            case['server_sddl'] = srv.sddl
            t = threading.Thread(target=lambda: box.setdefault(
                'r', srv.serve(REFUSED_SERVER_S if refused else SERVE_S)), daemon=True)
            t.start()
            case['child'] = win.launch(argv, principal, ac_psid, cwd)
            t.join(SERVE_S + 10)
        r = box.get('r')
        case['server_result'] = None if r is None else {
            'verdict': r.verdict, 'reason': r.reason, 'client_sid': r.client_sid,
            'sent': r.response_sent, 'winerror': r.winerror}
    else:
        budget = CPP_REFUSED_BUDGET_MS if refused else 10000
        proc = subprocess.Popen([probe, '--budget-ms', str(budget)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            if not crossrun._wait_for_pipe(wp, time.monotonic() + 20):
                raise RuntimeError('CPP_SERVER_PIPE_NOT_CREATED')
            case['child'] = win.launch(argv, principal, ac_psid, cwd)
            try:
                _, err = proc.communicate(timeout=crossrun.TIMEOUT_S)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
                code = None
            text = err.decode('utf-8', 'replace')
            case['server_result'] = {'exit': code, 'denial': parse_probe_denial(text), 'stderr': text[-300:]}
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    return case


def _json_lines(text: str) -> dict:
    out = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if line.startswith('{'):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.update(obj)
    return out


def run_squat_case(win: Win, wp, name: str, client: str) -> dict:
    kind = 'medium' if name.endswith('medium_label') else 'default'
    api = wp.default_api()
    argv = [sys.executable, '-I', '-B', str(REPO / 'tools' / 'w25_principal_matrix.py'), '--squatter',
            '--squat-label', kind]
    box = {}
    t = threading.Thread(target=lambda: box.setdefault(
        'child', win.launch(argv, 'low_il', None, str(REPO))), daemon=True)
    t.start()
    end = time.monotonic() + 8.0
    present = False
    while time.monotonic() < end and not present and t.is_alive():
        present = wp.pipe_name_present(api, wp.DEFAULT_PIPE_NAME)
        time.sleep(0.05)
    case = {'kind': kind, 'pipe_seen': present}
    case['cpp_client'] = win.launch([client, '--budget-ms', '3000'], 'same_token', None,
                                    str(pathlib.Path(client).parent))
    r = wp.client_ping(wp.DEFAULT_PIPE_NAME, connect_timeout_s=3.0, response_timeout_s=2.0)
    case['py_client'] = {'reason': r.reason, 'open_error': r.open_error, 'sent': r.sent,
                         'pipe_owner': r.pipe_owner, 'pipe_label': r.pipe_label, 'winerror': r.winerror}
    t.join(SQUAT_LIFETIME_S + 15)
    child = box.get('child')
    if child is None:
        raise RuntimeError('SQUATTER_DID_NOT_FINISH')
    child['report'] = _json_lines(child.get('output'))
    case['squatter'] = child
    return case


def squatter(kind: str) -> int:
    """Runs as a Low-IL process of the same user: create the production pipe
    name first (FIRST_PIPE_INSTANCE), report owner and label, then accept up to
    two connections and count the bytes received. Never outlives SQUAT_LIFETIME_S."""
    import ctypes
    sys.path.insert(0, str(REPO))
    from udx_ref import windows_pipe as wp
    threading.Timer(SQUAT_LIFETIME_S, lambda: os._exit(0)).start()
    api = wp.default_api()
    out = {'kind': kind}
    sa_ref, sd = None, ctypes.c_void_p()
    if kind == 'medium':
        sid = wp.current_user_sid(api)
        ok = api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f'O:{sid}D:(A;;GA;;;{sid})S:(ML;;NWNR;;;ME)', wp.SDDL_REVISION_1, ctypes.byref(sd), None)
        out['sd_converted'] = bool(ok)
        sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
        sa_ref = ctypes.byref(sa)
    h = api.CreateNamedPipeW(wp.DEFAULT_PIPE_NAME, wp.PIPE_ACCESS_DUPLEX | wp.FILE_FLAG_FIRST_PIPE_INSTANCE,
                             0, 1, 4096, 4096, 0, sa_ref)
    err = api.last_error()
    if sd.value:
        api.LocalFree(sd)
    if h is None or h == wp.INVALID_HANDLE_VALUE:
        out.update(created=False, create_error=err)
        print(json.dumps(out), flush=True)
        return 0
    owner, osd, rc = wp.pipe_owner_sid(api, h)
    try:
        out['owner'] = wp.sid_to_text(api, owner) if owner is not None else None
    finally:
        if osd is not None and osd.value:
            api.LocalFree(osd)
    rid, lrc = wp.pipe_label_rid(api, h)
    out.update(created=True, label_rid=rid, label_rc=lrc)
    print(json.dumps(out), flush=True)
    received = 0
    for _ in range(2):
        api.ConnectNamedPipe(h, None)                 # returns when a client opened (or already closed)
        buf = ctypes.create_string_buffer(1)
        n = ctypes.c_ulong(0)
        api.ReadFile(h, buf, 1, ctypes.byref(n), None)
        received += n.value
        api.DisconnectNamedPipe(h)
    print(json.dumps({'received': received}), flush=True)
    os._exit(0)


def _new_report(mode: str) -> dict:
    return {'tool': 'w25_principal_matrix', 'release_authorized': False, 'mode': mode, 'cases': {},
            'cleanup': {}, 'host': {'platform': sys.platform, 'python': sys.version.split()[0],
                                    'windows': '.'.join(map(str, sys.getwindowsversion()[:3]))}}


def run_matrix(report: dict, binaries: pathlib.Path, work_parent: str | None = None) -> dict:
    """Runs all EXPECTED cases as the CURRENT user (admin or standard account).
    The built binaries are copied into a private work directory of this user
    (it must own it to grant the AppContainer SID read access); their hashes are
    compared with the build by evaluate()."""
    sys.path.insert(0, str(REPO))
    from udx_ref import windows_pipe as wp
    crossrun = _load_tool('w18_cpp_crossrun')
    win = Win()
    import shutil
    parent = win.own_facts()
    report['parent'] = parent
    prod = wp.build_sddl(parent['user_sid'])
    report['sddl'] = {kind: sd_variant(prod, kind) for kind in SD_KINDS}
    ac_name = AC_NAME_PREFIX + uuid.uuid4().hex[:12]
    ac_psid = None
    work = pathlib.Path(tempfile.mkdtemp(prefix='udx_w25_', dir=work_parent))
    try:
        bins = report.setdefault('binaries', {})
        for key, exe in (('client', 'udx_sid_client.exe'), ('probe', 'udx_sid_probe.exe')):
            shutil.copyfile(binaries / exe, work / exe)
            bins.setdefault(key, {})['used'] = _sha256(work / exe)
        ac_psid, ac_text, created = win.appcontainer_profile(ac_name)
        report['appcontainer'] = {'name': ac_name, 'sid': ac_text, 'created': created}
        # The AppContainer child must be able to load its image: grant its SID RX
        # on this private work directory only (deleted below).
        g = subprocess.run(['icacls', str(work), '/grant', f'*{ac_text}:(OI)(CI)RX'], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60)
        report['appcontainer']['dir_grant_exit'] = g.returncode
        client, probe = str(work / 'udx_sid_client.exe'), str(work / 'udx_sid_probe.exe')
        for name in EXPECTED:
            try:
                report['cases'][name] = run_case(win, wp, crossrun, name, client, probe, ac_psid)
            except Exception as exc:                       # recorded, the verdict fails closed
                report['cases'][name] = {'error': f'{type(exc).__name__}: {exc}'[:300]}
        report['squat'] = {}
        for name in SQUAT_CASES:                           # last: they hold the production name
            try:
                report['squat'][name] = run_squat_case(win, wp, name, client)
            except Exception as exc:
                report['squat'][name] = {'error': f'{type(exc).__name__}: {exc}'[:300]}
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:300]
    finally:
        if ac_psid is not None:
            win.api['FreeSid'](ac_psid)
            hr = win.api['DeleteAppContainerProfile'](ac_name)
            report['cleanup']['appcontainer_profile'] = 'deleted' if hr == 0 else f'hr={hr & 0xFFFFFFFF:#x}'
        shutil.rmtree(work, ignore_errors=True)
        report['cleanup']['workdir'] = 'deleted' if not work.exists() else 'LEFT_BEHIND'
    return report


def _build(report: dict, out: pathlib.Path) -> bool:
    build = _load_tool('w18_cpp_crossrun').build(REPO, out)
    report['build'] = build
    if 'error' in build:
        report['error'] = 'BUILD_FAILED'
        return False
    report['binaries'] = {key: {'built': build['binaries'][key]['sha256']} for key in ('client', 'probe')}
    return True


def orchestrate_admin() -> dict:
    import shutil
    report = _new_report('elevated_admin')
    out = pathlib.Path(tempfile.mkdtemp(prefix='udx_w25_build_'))
    try:
        if _build(report, out):
            run_matrix(report, out)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return report


# --- standard-account mode (W25.1; reuses the W20 account and task machinery) ---
WORKROOT = pathlib.Path(r'C:\udx_w25')
STD_USER = 'udxw25s'
STD_TIMEOUT_S = 420.0
CHILD_FILES = ('tools/w25_principal_matrix.py', 'tools/w18_cpp_crossrun.py')


def orchestrate_standard() -> dict:
    """Elevated orchestrator: build, create a throwaway Users-only account, run the
    whole matrix AS that account (scheduled task, batch logon), delete it."""
    import shutil
    w20 = _load_tool('w20_account_matrix')
    report = _new_report('standard_account')
    lsa, netuser = w20._Lsa(), w20._NetUser()
    password = w20._password()
    created = sid = None
    task = None
    try:
        if WORKROOT.exists():
            shutil.rmtree(WORKROOT)
        WORKROOT.mkdir()
        w20._lock_dir(WORKROOT, None, 'RX')
        (WORKROOT / 'bin').mkdir()                 # cl /Fo needs the directory
        if not _build(report, WORKROOT / 'bin'):
            return report
        # The child runs from a read-only copy of exactly the files it imports.
        repo = WORKROOT / 'repo'
        shutil.copytree(REPO / 'udx_ref', repo / 'udx_ref', ignore=shutil.ignore_patterns('__pycache__'))
        for rel in CHILD_FILES:
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, repo / rel)
        report['child_sources'] = {rel: _sha256(repo / rel) for rel in CHILD_FILES}
        netuser.add(STD_USER, password)
        created = True
        sid = w20._account_sid(STD_USER)
        report['account'] = {'name': STD_USER, 'sid': sid}
        lsa.add(sid)
        outdir = WORKROOT / 'out'
        w20._lock_dir(outdir, STD_USER, 'M')
        result = outdir / 'matrix.json'
        task = 'UDX_W25_' + uuid.uuid4().hex[:8]
        argv = [sys.executable, '-I', str(repo / 'tools' / 'w25_principal_matrix.py'), '--child-matrix',
                '--bin', str(WORKROOT / 'bin'), '--work', str(outdir), '--output', str(result)]
        cmd = WORKROOT / 'bin' / (task + '.cmd')
        cmd.write_text('@echo off\r\n' + subprocess.list2cmdline(argv) + ' > "%s" 2>&1\r\n'
                       % (outdir / 'child.log'), encoding='utf-8')
        xml = WORKROOT / 'bin' / (task + '.xml')
        xml.write_text(w20._TASK_XML.format(user=STD_USER, command=str(cmd)), encoding='utf-16')
        script = ('$pw = [Console]::In.ReadLine(); '
                  'Register-ScheduledTask -TaskName $env:UDX_TN -Xml (Get-Content -Raw $env:UDX_XML) '
                  '-User $env:UDX_USER -Password $pw -Force | Out-Null')
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                           input=password + '\n', capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, UDX_TN=task, UDX_XML=str(xml), UDX_USER=STD_USER))
        if r.returncode != 0:
            raise RuntimeError('TASK_REGISTER_FAILED: ' + (r.stdout + r.stderr).replace(password, '***')[-400:])
        r = w20._run(['schtasks', '/Run', '/TN', task])
        if r.returncode != 0:
            raise RuntimeError('SCHTASKS_RUN_FAILED: ' + (r.stdout + r.stderr)[-400:])
        child = w20._wait_json(result, STD_TIMEOUT_S)
        # The child's own findings; orchestration facts stay authoritative.
        for key in ('parent', 'sddl', 'appcontainer', 'cases', 'squat', 'host', 'error'):
            if key in child:
                report[key] = child[key]
        for key, val in (child.get('binaries') or {}).items():
            if isinstance(val, dict) and key in report['binaries']:
                report['binaries'][key]['used'] = val.get('used')
        report['cleanup'].update(child.get('cleanup') or {})
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:300].replace(password, '***')
    finally:
        if task:
            w20._run(['schtasks', '/End', '/TN', task])
            w20._run(['schtasks', '/Delete', '/TN', task, '/F'])
        if sid:
            try:
                lsa.remove(sid)
                report['cleanup']['batch_logon_right'] = 'removed'
            except OSError as exc:
                report['cleanup']['batch_logon_right'] = 'REMOVE_FAILED:%s' % exc.errno
        if created:
            report['cleanup']['account'] = 'deleted' if netuser.delete(STD_USER) == 0 else 'DELETE_FAILED'
        shutil.rmtree(WORKROOT, ignore_errors=True)
        report['cleanup']['workroot'] = 'deleted' if not WORKROOT.exists() else 'LEFT_BEHIND'
    return report


def child_matrix(args) -> int:
    """Runs as the throwaway standard account; writes its report atomically."""
    report = _new_report('standard_account')
    try:
        run_matrix(report, pathlib.Path(args.bin), args.work)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:300]
    target = pathlib.Path(args.output)
    tmp = target.with_suffix('.tmp')
    tmp.write_text(json.dumps(report, sort_keys=True), encoding='utf-8')
    os.replace(tmp, target)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX W25 principal matrix (research only)')
    p.add_argument('--output')
    p.add_argument('--squatter', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--squat-label', choices=('default', 'medium'), default='default', help=argparse.SUPPRESS)
    p.add_argument('--mode', choices=MODES, default='elevated_admin')
    p.add_argument('--evaluate', action='store_true', help='only evaluate an existing report (portable)')
    p.add_argument('--child-matrix', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--bin', help=argparse.SUPPRESS)
    p.add_argument('--work', help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    if args.squatter:
        return squatter(args.squat_label)
    if not args.output:
        p.error('--output is required')
    if args.child_matrix:
        return child_matrix(args)
    if args.evaluate:
        report = json.loads(pathlib.Path(args.output).read_text(encoding='utf-8'))
    else:
        if sys.platform != 'win32':
            print(json.dumps({'verdict': 'BLOCKED', 'issues': ['NOT_WINDOWS']}))
            return 2
        report = orchestrate_admin() if args.mode == 'elevated_admin' else orchestrate_standard()
    verdict, issues = evaluate(report)
    report['verdict'], report['issues'] = verdict, issues
    text = json.dumps(report, indent=1, sort_keys=True)
    if not args.evaluate:
        pathlib.Path(args.output).write_text(text, encoding='utf-8')
        report['report_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
    print(f"MODE {report.get('mode')} parent={report.get('parent')}")
    for line in summary_lines(report):
        print(line)
    print(json.dumps({'verdict': verdict, 'issues': issues, 'report_sha256': report.get('report_sha256')}))
    return 0 if verdict == 'PRINCIPAL_MATRIX_OK' else 1


if __name__ == '__main__':
    sys.exit(main())
