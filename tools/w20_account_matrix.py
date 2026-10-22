"""W20: standard-account and second-account lane on a disposable Windows host.

RESEARCH ONLY. Run as an elevated administrator on a THROWAWAY machine (the CI
job ``windows-account-matrix`` uses the hosted runner, which is discarded after
the job). The orchestrator

  1. creates two local accounts A and B that are members of ``Users`` only
     (no Administrators membership at all, so no UAC split token);
  2. grants them ``SeBatchLogonRight`` and runs every step as a scheduled task
     under that account (Task Scheduler gives the batch logon its own window
     station; CreateProcessWithLogonW from a service context fails on window
     station access, Microsoft: "The application must add permission for the
     specified user account to the specified window station and desktop");
  3. records the token facts of each account (user SID, Administrators
     membership, elevation type, integrity level, session);
  4. runs the matrix
       admin_open     the elevated administrator opens A's pipe  -> ERROR_ACCESS_DENIED
       second_account B runs client_ping against A's pipe         -> OPEN_FAILED / 5
       same_account   A runs client_ping against A's pipe         -> OK, server PEER_OK
     The denied opens come first; the same-account control afterwards shows
     they did not consume the single instance;
  5. runs the W15 native collector (47 pinned tests) and ``--verify`` as A;
  6. deletes the tasks, removes the logon right and deletes both accounts.

``evaluate`` decides the verdict from the report alone and fails closed on any
missing, extra or contradicting fact. Passwords are random, handed to NetUserAdd
and (on stdin) to Register-ScheduledTask only, never on a command line, in the
report or in a log.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import string
import subprocess
import sys
import time
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
WORK = pathlib.Path(r'C:\udx_w20')
ADMINISTRATORS_SID = 'S-1-5-32-544'
MEDIUM_RID = 0x2000
HIGH_RID = 0x3000
ELEVATION_DEFAULT, ELEVATION_FULL, ELEVATION_LIMITED = 1, 2, 3
ERROR_ACCESS_DENIED = 5
EXPECTED_NATIVE_CASES = 47
SERVER_DEADLINE_S = 120.0
STEP_TIMEOUT_S = 90.0
COLLECT_TIMEOUT_S = 420.0
TokenGroups, TokenElevationType = 2, 18
SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY = 0x4, 0x10


# --- verdict (pure, portable) ------------------------------------------------
def evaluate(report: dict) -> tuple[str, list[str]]:
    """Return (verdict, issues). Every expectation must be observed explicitly."""
    issues = []
    if not isinstance(report, dict):
        return 'BLOCKED', ['REPORT_NOT_OBJECT']
    if report.get('error'):
        issues.append('ORCHESTRATION_ERROR')
    facts = report.get('facts') if isinstance(report.get('facts'), dict) else {}
    sids = {}
    for who in ('A', 'B'):
        f = facts.get(who)
        if not isinstance(f, dict):
            issues.append('FACTS_MISSING:' + who)
            continue
        if f.get('administrators_member') is not False:
            issues.append('NOT_STANDARD_ACCOUNT:' + who)
        if f.get('elevation_type') != ELEVATION_DEFAULT:
            issues.append('ELEVATION_TYPE_NOT_DEFAULT:' + who)
        if f.get('integrity_rid') != MEDIUM_RID:
            issues.append('INTEGRITY_NOT_MEDIUM:' + who)
        if not isinstance(f.get('user_sid'), str) or not f['user_sid'].startswith('S-1-5-21-'):
            issues.append('USER_SID_INVALID:' + who)
        sids[who] = f.get('user_sid')
    admin = facts.get('admin')
    if not isinstance(admin, dict) or admin.get('administrators_member') is not True:
        issues.append('ADMIN_FACTS_MISSING')
    elif admin.get('administrators_deny_only') is not False or not isinstance(admin.get('integrity_rid'), int) \
            or admin['integrity_rid'] < HIGH_RID:
        issues.append('ADMIN_NOT_ELEVATED')
    if len(sids) == 2 and (sids['A'] == sids['B']
                           or (isinstance(admin, dict) and admin.get('user_sid') in sids.values())):
        issues.append('PRINCIPALS_NOT_DISTINCT')
    cases = report.get('cases') if isinstance(report.get('cases'), dict) else {}
    expected_cases = {'admin_open', 'second_account', 'same_account', 'server'}
    if set(cases) != expected_cases:
        issues.append('CASE_SET_DRIFT')
    for name in sorted(expected_cases & set(cases)):
        if not isinstance(cases[name], dict) or cases[name].get('error'):
            issues.append('CASE_ERROR:' + name)
    c = cases.get('admin_open') or {}
    if c.get('opened') is not False or c.get('winerror') != ERROR_ACCESS_DENIED:
        issues.append('ADMIN_OPEN_NOT_DENIED')
    c = cases.get('second_account') or {}
    if c.get('reason') != 'OPEN_FAILED' or c.get('open_error') != ERROR_ACCESS_DENIED or c.get('sent') is not False:
        issues.append('SECOND_ACCOUNT_NOT_DENIED')
    c = cases.get('same_account') or {}
    if c.get('reason') != 'OK':
        issues.append('SAME_ACCOUNT_CONTROL_FAILED')
    c = cases.get('server') or {}
    if c.get('verdict') != 'PEER_OK' or c.get('client_sid') != sids.get('A') or c.get('client_sid') is None:
        issues.append('SERVER_DID_NOT_IDENTIFY_A')
    col = report.get('collector')
    if not isinstance(col, dict):
        issues.append('COLLECTOR_MISSING')
    else:
        if col.get('collect_exit') != 0 or col.get('verify_exit') != 0:
            issues.append('COLLECTOR_EXIT_NONZERO')
        if col.get('verify_verdict') != 'UNTRUSTED_REPORT_SCHEMA_VALID':
            issues.append('COLLECTOR_VERIFY_VERDICT')
        if col.get('passed') != EXPECTED_NATIVE_CASES or col.get('cases') != EXPECTED_NATIVE_CASES:
            issues.append('COLLECTOR_NOT_47_OF_47')
        if col.get('run_as') != 'A' or col.get('facts_match') is not True:
            issues.append('COLLECTOR_NOT_RUN_AS_A')
        if col.get('error'):
            issues.append('COLLECTOR_ERROR')
    cleanup = report.get('cleanup') if isinstance(report.get('cleanup'), dict) else {}
    if cleanup != {'A': 'deleted', 'B': 'deleted', 'rights_A': 'removed', 'rights_B': 'removed'}:
        issues.append('CLEANUP_INCOMPLETE')
    if report.get('release_authorized') is not False:
        issues.append('RELEASE_CLAIM')
    return ('STANDARD_ACCOUNT_LANE_OK' if not issues else 'BLOCKED'), issues


# --- child roles (run as A or B) ---------------------------------------------
def token_facts(wp) -> dict:
    from ctypes import wintypes
    api = wp.default_api()
    tok = wintypes.HANDLE()
    if not api.OpenProcessToken(api.GetCurrentProcess(), wp.TOKEN_QUERY, ctypes.byref(tok)):
        raise OSError(api.last_error(), 'OpenProcessToken failed')
    try:
        buf, err = wp._token_info(api, tok, TokenGroups)
        if buf is None:
            raise OSError(err, 'TokenGroups failed')
        count = ctypes.c_uint32.from_buffer(buf, 0).value
        ptr = ctypes.sizeof(ctypes.c_void_p)
        admin_attrs = None
        for i in range(count):
            off = ptr + i * 2 * ptr
            sid = ctypes.c_void_p.from_buffer(buf, off).value
            if wp.sid_to_text(api, sid) == ADMINISTRATORS_SID:
                admin_attrs = ctypes.c_uint32.from_buffer(buf, off + ptr).value
        elevation, _ = wp._token_dword(api, tok, TokenElevationType)
        rid, _ = wp._token_integrity_rid(api, tok)
    finally:
        api.CloseHandle(tok)
    return {'user_sid': wp.current_user_sid(api),
            'administrators_member': admin_attrs is not None,
            'administrators_deny_only': None if admin_attrs is None else bool(admin_attrs & SE_GROUP_USE_FOR_DENY_ONLY),
            'elevation_type': elevation, 'integrity_rid': rid, 'session_id': wp.own_session_id(api)}


def run_child(args) -> int:
    repo = pathlib.Path(args.repo)
    sys.path.insert(0, str(repo))
    from udx_ref import windows_pipe as wp
    out = {'role': args.child}
    try:
        out['facts'] = token_facts(wp)
        if args.child == 'server':
            with wp.OneShotPipeServer(args.name) as srv:
                (pathlib.Path(args.out).parent / 'server.ready').write_text(srv.name, encoding='utf-8')
                r = srv.serve(args.deadline)
            out['result'] = {'verdict': r.verdict, 'reason': r.reason, 'winerror': r.winerror,
                             'client_sid': r.client_sid}
        elif args.child == 'client':
            r = wp.client_ping(args.name, connect_timeout_s=10.0, response_timeout_s=10.0)
            out['result'] = {'reason': r.reason, 'open_error': r.open_error, 'sent': r.sent,
                             'response': r.response.decode('latin-1')}
        elif args.child == 'collect':
            tmp = pathlib.Path(args.out).parent
            report = tmp / 'native.json'
            tool = repo / 'tools' / 'w15_windows_evidence.py'
            c = subprocess.run([sys.executable, str(tool), '--collect', '--repo', str(repo), '--timeout', '300',
                                '--output', str(report)], stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=COLLECT_TIMEOUT_S)
            v = subprocess.run([sys.executable, str(tool), '--verify', str(report), '--repo', str(repo)],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
            data = json.loads(report.read_text(encoding='utf-8')) if report.is_file() else {}
            suite = data.get('native_suite') if isinstance(data.get('native_suite'), dict) else {}
            cases = suite.get('cases') if isinstance(suite.get('cases'), list) else []
            try:
                parsed = json.loads(v.stdout)
            except ValueError:
                parsed = None
            verdict = parsed.get('verdict') if isinstance(parsed, dict) else None
            out['result'] = {'collect_exit': c.returncode, 'verify_exit': v.returncode, 'verify_verdict': verdict,
                             'cases': len(cases),
                             'passed': sum(1 for x in cases if isinstance(x, dict) and x.get('status') == 'PASS'),
                             'diagnostic_code': data.get('diagnostic_code'),
                             'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest()
                             if report.is_file() else None,
                             'stderr_tail': (c.stderr + v.stderr)[-1500:]}
    except Exception as exc:                               # reported, judged by evaluate()
        out['error'] = '%s: %s' % (type(exc).__name__, exc)
    target = pathlib.Path(args.out)
    tmp = target.with_suffix('.tmp')
    tmp.write_text(json.dumps(out, sort_keys=True), encoding='utf-8')
    os.replace(tmp, target)
    return 0


# --- orchestrator (elevated administrator, Windows only) ----------------------
def _run(cmd, **kw):
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, **kw)


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    core = ''.join(secrets.choice(alphabet) for _ in range(24))
    return core + secrets.choice('ABCDEFGH') + secrets.choice('abcdefgh') + secrets.choice('23456789') + '#!'


class _Lsa:
    """LsaAddAccountRights / LsaRemoveAccountRights for SeBatchLogonRight."""

    def __init__(self):
        from ctypes import wintypes
        self.w = wintypes
        a = ctypes.WinDLL('advapi32', use_last_error=True)
        self.a = a

        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT),
                        ('Buffer', wintypes.LPWSTR)]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('RootDirectory', wintypes.HANDLE),
                        ('ObjectName', ctypes.c_void_p), ('Attributes', wintypes.ULONG),
                        ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQualityOfService', ctypes.c_void_p)]
        self.US, self.OA = UNICODE_STRING, OBJECT_ATTRIBUTES
        a.LsaOpenPolicy.argtypes = [ctypes.c_void_p, ctypes.POINTER(OBJECT_ATTRIBUTES), wintypes.ULONG,
                                    ctypes.POINTER(wintypes.HANDLE)]
        a.LsaOpenPolicy.restype = wintypes.ULONG
        for name in ('LsaAddAccountRights', 'LsaRemoveAccountRights'):
            fn = getattr(a, name)
            fn.restype = wintypes.ULONG
        a.LsaAddAccountRights.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(UNICODE_STRING),
                                          wintypes.ULONG]
        a.LsaRemoveAccountRights.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.BOOLEAN,
                                             ctypes.POINTER(UNICODE_STRING), wintypes.ULONG]
        a.LsaClose.argtypes = [wintypes.HANDLE]
        a.LsaNtStatusToWinError.argtypes = [wintypes.ULONG]
        a.LsaNtStatusToWinError.restype = wintypes.ULONG
        a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        a.ConvertStringSidToSidW.restype = wintypes.BOOL

    def _call(self, sid_text, add: bool):
        w, a = self.w, self.a
        oa = self.OA()
        oa.Length = ctypes.sizeof(self.OA)
        h = w.HANDLE()
        st = a.LsaOpenPolicy(None, ctypes.byref(oa), 0x00000010 | 0x00000800, ctypes.byref(h))  # CREATE_ACCOUNT|LOOKUP_NAMES
        if st:
            raise OSError(a.LsaNtStatusToWinError(st), 'LsaOpenPolicy failed')
        sid = ctypes.c_void_p()
        try:
            if not a.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                raise OSError(ctypes.get_last_error(), 'ConvertStringSidToSidW failed')
            name = 'SeBatchLogonRight'
            right = self.US(len(name) * 2, (len(name) + 1) * 2, name)
            st = (a.LsaAddAccountRights(h, sid, ctypes.byref(right), 1) if add
                  else a.LsaRemoveAccountRights(h, sid, False, ctypes.byref(right), 1))
            if st:
                raise OSError(a.LsaNtStatusToWinError(st), 'LsaAdd/RemoveAccountRights failed')
        finally:
            if sid.value:
                ctypes.windll.kernel32.LocalFree(sid)
            a.LsaClose(h)

    def add(self, sid_text):
        self._call(sid_text, True)

    def remove(self, sid_text):
        self._call(sid_text, False)


class _NetUser:
    """NetUserAdd / NetUserDel (netapi32). ``net user`` prompts (Y/N) for
    passwords longer than 14 characters and would put the password on a command
    line; the API does neither."""

    def __init__(self):
        from ctypes import wintypes
        n = ctypes.WinDLL('netapi32')

        class USER_INFO_1(ctypes.Structure):
            _fields_ = [('name', wintypes.LPWSTR), ('password', wintypes.LPWSTR),
                        ('password_age', wintypes.DWORD), ('priv', wintypes.DWORD),
                        ('home_dir', wintypes.LPWSTR), ('comment', wintypes.LPWSTR),
                        ('flags', wintypes.DWORD), ('script_path', wintypes.LPWSTR)]
        self.UI1 = USER_INFO_1
        n.NetUserAdd.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        n.NetUserAdd.restype = wintypes.DWORD
        n.NetUserDel.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        n.NetUserDel.restype = wintypes.DWORD
        self.n, self.w = n, wintypes

    def add(self, user: str, password: str) -> None:
        # USER_PRIV_USER; UF_SCRIPT | UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD
        info = self.UI1(user, password, 0, 1, None, 'UDX W20 throwaway test account', 0x1 | 0x40 | 0x10000, None)
        parm = self.w.DWORD(0)
        st = self.n.NetUserAdd(None, 1, ctypes.byref(info), ctypes.byref(parm))
        if st:
            raise RuntimeError('NetUserAdd failed: status %d parm %d' % (st, parm.value))

    def delete(self, user: str) -> int:
        return self.n.NetUserDel(None, user)


def _account_sid(user: str) -> str:
    r = _run(['powershell', '-NoProfile', '-Command',
              "(New-Object System.Security.Principal.NTAccount('%s')).Translate("
              "[System.Security.Principal.SecurityIdentifier]).Value" % user])
    sid = r.stdout.strip()
    if r.returncode != 0 or not sid.startswith('S-1-5-21-'):
        raise RuntimeError('SID_LOOKUP_FAILED: ' + (r.stdout + r.stderr)[-300:])
    return sid


def _lock_dir(path: pathlib.Path, user: str | None, rights: str) -> None:
    """Protected ACL: SYSTEM + Administrators full, ``user`` gets ``rights`` (or Users RX)."""
    path.mkdir(parents=True, exist_ok=True)
    grantee = user if user else '*S-1-5-32-545'
    r = _run(['icacls', str(path), '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
              '*S-1-5-32-544:(OI)(CI)F', '%s:(OI)(CI)%s' % (grantee, rights)])
    if r.returncode != 0:
        raise RuntimeError('ICACLS_FAILED: ' + (r.stdout + r.stderr)[-300:])


_TASK_XML = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
    </Exec>
  </Actions>
</Task>
'''


class _Tasks:
    def __init__(self, bindir: pathlib.Path):
        self.bindir, self.names = bindir, []

    def start(self, user, password, outdir: pathlib.Path, role, extra) -> pathlib.Path:
        tid = 'UDX_W20_%s_%s' % (role, uuid.uuid4().hex[:8])
        out = outdir / (role + '.json')
        cmd = self.bindir / (tid + '.cmd')
        argv = [sys.executable, '-I', str(WORK / 'repo' / 'tools' / 'w20_account_matrix.py'),
                '--child', role, '--out', str(out), '--repo', str(WORK / 'repo')] + extra
        cmd.write_text('@echo off\r\n' + subprocess.list2cmdline(argv) + ' > "%s" 2>&1\r\n'
                       % (outdir / (role + '.log')), encoding='utf-8')
        # No trigger at all: the task only runs on /Run (a time trigger could fire a
        # second run of the same role). The password goes to Register-ScheduledTask
        # on stdin, never onto a command line.
        xml = self.bindir / (tid + '.xml')
        xml.write_text(_TASK_XML.format(user=user, command=str(cmd)), encoding='utf-16')
        script = ('$pw = [Console]::In.ReadLine(); '
                  'Register-ScheduledTask -TaskName $env:UDX_TN -Xml (Get-Content -Raw $env:UDX_XML) '
                  '-User $env:UDX_USER -Password $pw -Force | Out-Null')
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                           input=password + '\n', capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, UDX_TN=tid, UDX_XML=str(xml), UDX_USER=user))
        if r.returncode != 0:
            raise RuntimeError('TASK_REGISTER_FAILED: ' + (r.stdout + r.stderr).replace(password, '***')[-400:])
        self.names.append(tid)
        r = _run(['schtasks', '/Run', '/TN', tid])
        if r.returncode != 0:
            raise RuntimeError('SCHTASKS_RUN_FAILED: ' + (r.stdout + r.stderr)[-400:])
        return out

    def cleanup(self):
        for tid in self.names:
            _run(['schtasks', '/End', '/TN', tid])
            _run(['schtasks', '/Delete', '/TN', tid, '/F'])


def _wait_json(path: pathlib.Path, timeout: float) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.is_file():
            return json.loads(path.read_text(encoding='utf-8'))
        time.sleep(0.25)
    log = path.with_suffix('.log')
    tail = log.read_text(encoding='utf-8', errors='replace')[-1500:] if log.is_file() else ''
    raise RuntimeError('CHILD_TIMEOUT:%s %s' % (path.name, tail))


def orchestrate(repo: pathlib.Path) -> dict:
    sys.path.insert(0, str(repo))
    from udx_ref import windows_pipe as wp
    report = {'schema_version': 1, 'tool': 'W20_ACCOUNT_MATRIX', 'research_only': True,
              'release_authorized': False, 'facts': {}, 'cases': {}}
    r = _run(['git', '-C', str(repo), 'rev-parse', 'HEAD'])
    head = r.stdout.strip()
    report['head'] = head
    users = {'A': 'udxw20a', 'B': 'udxw20b'}
    pw = {k: _password() for k in users}
    sids = {}
    lsa = _Lsa()
    netuser, created = _NetUser(), set()
    tasks = _Tasks(WORK / 'bin')
    try:
        if r.returncode != 0 or len(head) != 40:
            raise RuntimeError('HEAD_UNKNOWN')
        if WORK.exists():
            shutil.rmtree(WORK)
        WORK.mkdir()
        _lock_dir(WORK, None, 'RX')
        r = _run(['git', 'clone', '--quiet', '--no-local', str(repo), str(WORK / 'repo')])
        if r.returncode != 0:
            raise RuntimeError('CLONE_FAILED: ' + r.stderr[-300:])
        for cmd in (['git', '-C', str(WORK / 'repo'), 'checkout', '--quiet', head],
                    ['git', 'config', '--system', '--add', 'safe.directory', str(WORK / 'repo').replace('\\', '/')]):
            if _run(cmd).returncode != 0:
                raise RuntimeError('GIT_STEP_FAILED: ' + ' '.join(cmd[1:4]))
        if _run(['git', '-C', str(WORK / 'repo'), 'rev-parse', 'HEAD']).stdout.strip() != head:
            raise RuntimeError('CLONE_NOT_AT_HEAD')
        _lock_dir(WORK / 'bin', None, 'RX')
        report['facts']['admin'] = token_facts(wp)
        for k, u in users.items():
            netuser.add(u, pw[k])
            created.add(k)
            sids[k] = _account_sid(u)
            lsa.add(sids[k])
            _lock_dir(WORK / ('out_' + k), u, 'M')
        # facts per account (each in its own batch logon)
        for k, u in users.items():
            out = tasks.start(u, pw[k], WORK / ('out_' + k), 'facts', [])
            report['facts'][k] = _wait_json(out, STEP_TIMEOUT_S).get('facts')
        # matrix: A serves, denied opens first, same-account control last
        name = wp.PIPE_PREFIX + 'UDX_W20_' + uuid.uuid4().hex
        srv_out = tasks.start(users['A'], pw['A'], WORK / 'out_A', 'server',
                              ['--name', name, '--deadline', str(SERVER_DEADLINE_S)])
        ready = WORK / 'out_A' / 'server.ready'
        end = time.monotonic() + STEP_TIMEOUT_S
        while not ready.is_file() and time.monotonic() < end:
            time.sleep(0.1)
        if not ready.is_file():
            raise RuntimeError('SERVER_NOT_READY')
        api = wp.default_api()
        h = api.CreateFileW(name, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING, 0, None)
        if h is None or h == wp.INVALID_HANDLE_VALUE:
            report['cases']['admin_open'] = {'opened': False, 'winerror': api.last_error()}
        else:
            api.CloseHandle(h)
            report['cases']['admin_open'] = {'opened': True, 'winerror': 0}
        b = _wait_json(tasks.start(users['B'], pw['B'], WORK / 'out_B', 'client', ['--name', name]), STEP_TIMEOUT_S)
        report['cases']['second_account'] = dict(b.get('result') or {}, error=b.get('error'))
        a = _wait_json(tasks.start(users['A'], pw['A'], WORK / 'out_A', 'client', ['--name', name]), STEP_TIMEOUT_S)
        report['cases']['same_account'] = dict(a.get('result') or {}, error=a.get('error'))
        s = _wait_json(srv_out, SERVER_DEADLINE_S + 10)
        report['cases']['server'] = dict(s.get('result') or {}, error=s.get('error'))
        # native collector as A
        c = _wait_json(tasks.start(users['A'], pw['A'], WORK / 'out_A', 'collect', []), COLLECT_TIMEOUT_S + 60)
        report['collector'] = dict(c.get('result') or {}, run_as='A', error=c.get('error'),
                                   facts_match=c.get('facts') == report['facts'].get('A'))
    except Exception as exc:
        report['error'] = '%s: %s' % (type(exc).__name__, exc)
    finally:
        tasks.cleanup()
        for k, u in users.items():
            if k in sids:
                try:
                    lsa.remove(sids[k])
                    report.setdefault('cleanup', {})['rights_' + k] = 'removed'
                except OSError as exc:
                    report.setdefault('cleanup', {})['rights_' + k] = 'REMOVE_FAILED:%s' % exc.errno
            if k in created:
                report.setdefault('cleanup', {})[k] = 'deleted' if netuser.delete(u) == 0 else 'DELETE_FAILED'
    report['verdict'], report['issues'] = evaluate(report)
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--child', choices=['facts', 'server', 'client', 'collect'])
    p.add_argument('--out')
    p.add_argument('--repo', default=str(REPO))
    p.add_argument('--name')
    p.add_argument('--deadline', type=float, default=SERVER_DEADLINE_S)
    p.add_argument('--output', type=pathlib.Path)
    args = p.parse_args(argv)
    if args.child:
        return run_child(args)
    if sys.platform != 'win32':
        report = {'schema_version': 1, 'tool': 'W20_ACCOUNT_MATRIX', 'research_only': True,
                  'release_authorized': False, 'verdict': 'NATIVE_WINDOWS_REQUIRED'}
        code = 2
    elif not ctypes.windll.shell32.IsUserAnAdmin():
        report = {'schema_version': 1, 'tool': 'W20_ACCOUNT_MATRIX', 'research_only': True,
                  'release_authorized': False, 'verdict': 'ELEVATED_ADMIN_REQUIRED'}
        code = 2
    else:
        report = orchestrate(pathlib.Path(args.repo).resolve())
        code = 0 if report['verdict'] == 'STANDARD_ACCOUNT_LANE_OK' else 1
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(payload, encoding='utf-8')
    print(payload, end='')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
