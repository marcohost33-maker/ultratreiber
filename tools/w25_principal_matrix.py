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
LOW_RID, MEDIUM_RID = 0x1000, 0x2000
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
CONTROL_DELTA = ('(A;;0x12008b;;;AC)', 'S:(ML;;NWNR;;;LW)')
PRINCIPALS = ('same_token', 'low_il', 'appcontainer', 'restricted')

# name: (server, sd, principal, client_exit, open_error, server expectation)
# server expectation: python -> (verdict, reason, identified_user: bool); cpp -> exit code
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
    'cpp_same_token':  ('cpp', 'production', 'same_token', EXIT_OK, None, EXIT_OK),
    'cpp_low_il':      ('cpp', 'production', 'low_il', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED, EXIT_TIMEOUT),
    'cpp_appcontainer': ('cpp', 'production', 'appcontainer', EXIT_OPEN_FAILED, ERROR_ACCESS_DENIED,
                         EXIT_TIMEOUT),
    'cpp_restricted':  ('cpp', 'production', 'restricted', EXIT_BAD_RESPONSE, None, EXIT_DENIED),
}


# --- pure decision logic (portable, tested on Linux) ---------------------------
def production_sddl(sid: str) -> str:
    """Same string as udx_ref.windows_pipe.build_sddl (kept literal on purpose:
    evaluate() must not trust the module that is under test)."""
    a = '0x12008b'
    return f'O:{sid}D:P(A;;{a};;;SY)(A;;{a};;;{sid})(A;;{a};;;OW){PRODUCTION_LABEL}'


def control_sddl(production: str) -> str:
    """Layer-2 control SD: + ALL APPLICATION PACKAGES ACE, Low label. Harness only."""
    if type(production) is not str or not production.endswith(')' + PRODUCTION_LABEL):
        raise ValueError('NOT_A_PRODUCTION_SDDL')
    return production[:-len(PRODUCTION_LABEL)] + CONTROL_DELTA[0] + CONTROL_DELTA[1]


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
    sddl = report.get('sddl') if isinstance(report.get('sddl'), dict) else {}
    if sid is None or sddl.get('production') != production_sddl(sid):
        issues.append('PRODUCTION_SDDL_DRIFT')
    elif sddl.get('control') != control_sddl(sddl['production']):
        issues.append('CONTROL_SDDL_DRIFT')
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
        child = c.get('child') if isinstance(c.get('child'), dict) else {}
        issues += _principal_issues(name, principal, child.get('facts'), parent, ac_sid)
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
            if type(srv.get('exit')) is not int or srv['exit'] != sexp:
                issues.append('CPP_SERVER_EXIT_WRONG:' + name)
    cleanup = report.get('cleanup') if isinstance(report.get('cleanup'), dict) else {}
    if cleanup.get('appcontainer_profile') != 'deleted':
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
                    f"t={child.get('elapsed_s')}s server={server} error={c.get('error')}")
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
        tok = self.process_token(self.api['GetCurrentProcess']())
        try:
            return self.token_facts(tok)
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
        flags = CREATE_SUSPENDED | CREATE_NO_WINDOW
        token = None
        attr = None
        try:
            if principal == 'appcontainer':
                siex = self.t['STARTUPINFOEXW']()
                si = siex.StartupInfo
                si.cb = c.sizeof(siex)
                size = c.c_size_t(0)
                api['InitializeProcThreadAttributeList'](None, 1, 0, c.byref(size))
                attr = c.create_string_buffer(size.value)
                self.check(api['InitializeProcThreadAttributeList'](attr, 1, 0, c.byref(size)),
                           'InitializeProcThreadAttributeList')
                caps = self.t['SECURITY_CAPABILITIES']()
                caps.AppContainerSid, caps.Capabilities, caps.CapabilityCount = ac_psid, None, 0
                self._caps = caps
                self.check(api['UpdateProcThreadAttribute'](attr, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                            c.byref(caps), c.sizeof(caps), None, None),
                           'UpdateProcThreadAttribute')
                siex.lpAttributeList = c.addressof(attr)
                si.dwFlags = STARTF_USESTDHANDLES
                si.hStdOutput = si.hStdError = hw
                siex.StartupInfo = si
                ok = api['CreateProcessW'](argv[0], cmd, None, None, True, flags | EXTENDED_STARTUPINFO_PRESENT,
                                           None, cwd, c.byref(siex), c.byref(pi))
                self.check(ok, 'CreateProcessW(AppContainer)')
            else:
                token = self.primary_token(principal)
                si = self.t['STARTUPINFOW']()
                si.cb = c.sizeof(si)
                si.dwFlags = STARTF_USESTDHANDLES
                si.hStdOutput = si.hStdError = hw
                ok = api['CreateProcessAsUserW'](token, argv[0], cmd, None, None, True, flags, None, cwd,
                                                 c.byref(si), c.byref(pi))
                self.check(ok, 'CreateProcessAsUserW(' + principal + ')')
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
                'stderr': text[-400:], 'open_error': parse_open_error(text)}


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
def _control_sd(wp):
    """Layer 2 only: OneShotPipeServer builds its SD from wp.build_sddl."""
    real = wp.build_sddl
    wp.build_sddl = lambda sid: control_sddl(real(sid))
    try:
        yield
    finally:
        wp.build_sddl = real


def _load_crossrun():
    spec = importlib.util.spec_from_file_location('w18_cpp_crossrun', REPO / 'tools' / 'w18_cpp_crossrun.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_case(win: Win, wp, crossrun, name: str, client: str, probe: str, ac_psid) -> dict:
    server, sd, principal, cexit, _, _ = EXPECTED[name]
    refused = cexit == EXIT_OPEN_FAILED
    case = {'server': server, 'sd': sd, 'principal': principal}
    argv = [client, '--budget-ms', str(CLIENT_BUDGET_MS)]
    cwd = str(pathlib.Path(client).parent)
    if server == 'python':
        ctx = _control_sd(wp) if sd == 'control' else contextlib.nullcontext()
        box = {}
        with ctx, wp.OneShotPipeServer(wp.DEFAULT_PIPE_NAME) as srv:
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
        proc = subprocess.Popen([probe, '--budget-ms', str(budget)], stdin=subprocess.DEVNULL)
        try:
            if not crossrun._wait_for_pipe(wp, time.monotonic() + 20):
                raise RuntimeError('CPP_SERVER_PIPE_NOT_CREATED')
            case['child'] = win.launch(argv, principal, ac_psid, cwd)
            case['server_result'] = {'exit': crossrun._stop(proc)}
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    return case


def orchestrate(repo: pathlib.Path) -> dict:
    sys.path.insert(0, str(repo))
    from udx_ref import windows_pipe as wp
    crossrun = _load_crossrun()
    win = Win()
    report = {'tool': 'w25_principal_matrix', 'release_authorized': False, 'cases': {}, 'cleanup': {},
              'host': {'platform': sys.platform, 'python': sys.version.split()[0],
                       'windows': '.'.join(map(str, sys.getwindowsversion()[:3]))}}
    parent = win.own_facts()
    report['parent'] = parent
    prod = wp.build_sddl(parent['user_sid'])
    report['sddl'] = {'production': prod, 'control': control_sddl(prod)}
    ac_name = AC_NAME_PREFIX + uuid.uuid4().hex[:12]
    ac_psid = None
    work = pathlib.Path(tempfile.mkdtemp(prefix='udx_w25_'))
    try:
        report['build'] = crossrun.build(repo, work)
        if 'error' in report['build']:
            report['error'] = 'BUILD_FAILED'
            return report
        ac_psid, ac_text, created = win.appcontainer_profile(ac_name)
        report['appcontainer'] = {'name': ac_name, 'sid': ac_text, 'created': created}
        # The AppContainer child must be able to load its image: grant its SID RX
        # on the throwaway build directory only.
        g = subprocess.run(['icacls', str(work), '/grant', f'*{ac_text}:(OI)(CI)RX'], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60)
        report['appcontainer']['dir_grant_exit'] = g.returncode
        client, probe = str(work / 'udx_sid_client.exe'), str(work / 'udx_sid_probe.exe')
        for name in EXPECTED:
            try:
                report['cases'][name] = run_case(win, wp, crossrun, name, client, probe, ac_psid)
            except Exception as exc:                       # recorded, the verdict fails closed
                report['cases'][name] = {'error': f'{type(exc).__name__}: {exc}'[:300]}
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:300]
    finally:
        if ac_psid is not None:
            win.api['FreeSid'](ac_psid)
            hr = win.api['DeleteAppContainerProfile'](ac_name)
            report['cleanup']['appcontainer_profile'] = 'deleted' if hr == 0 else f'hr={hr & 0xFFFFFFFF:#x}'
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='UDX W25 principal matrix (research only)')
    p.add_argument('--output', required=True)
    p.add_argument('--evaluate', action='store_true', help='only evaluate an existing report (portable)')
    args = p.parse_args(argv)
    if args.evaluate:
        report = json.loads(pathlib.Path(args.output).read_text(encoding='utf-8'))
    else:
        if sys.platform != 'win32':
            print(json.dumps({'verdict': 'BLOCKED', 'issues': ['NOT_WINDOWS']}))
            return 2
        report = orchestrate(REPO)
    verdict, issues = evaluate(report)
    report['verdict'], report['issues'] = verdict, issues
    text = json.dumps(report, indent=1, sort_keys=True)
    if not args.evaluate:
        pathlib.Path(args.output).write_text(text, encoding='utf-8')
        report['report_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
    for line in summary_lines(report):
        print(line)
    print(json.dumps({'verdict': verdict, 'issues': issues, 'report_sha256': report.get('report_sha256')}))
    return 0 if verdict == 'PRINCIPAL_MATRIX_OK' else 1


if __name__ == '__main__':
    sys.exit(main())
