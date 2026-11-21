"""W18: build the C++ candidates with MSVC and cross-run them against the Python lane.

RESEARCH ONLY. Until W17 ``windows/*.cpp`` had never been compiled (UDX14-04).
This tool compiles both sources with ``cl /W4 /WX`` (located via vswhere) and
runs the fixed-name handshake in every combination:

  cpp_server+cpp_client       C++ probe <-> C++ client
  cpp_server+py_client        C++ probe <-> udx_ref.windows_pipe.client_ping
  py_server+cpp_client        OneShotPipeServer <-> C++ client
  cpp_server_name_occupied    W20: name held by the Python server -> C++ probe
                              exits 21 (PIPE_NAME_OCCUPIED parity), holder still works
  cpp_server_legacy_open      against the C++ probe a GENERIC_READ|GENERIC_WRITE
                              open is refused (W18 DACL has no 0x4), and the
                              refused open does not consume the single instance:
                              a CLIENT_ACCESS client completes afterwards

W24 adds negative-first cases for the bounded overlapped I/O
(windows/udx_bounded_pipe_io.hpp). Each stall is held by a real second party
for HOLD_S seconds, far longer than the STALL_BUDGET_MS budget given to the
C++ binary; PASS requires the typed exit code AND an exit well before the
holder lets go (W20 sources block until the holder closes, or forever):

  cpp_server_connect_timeout  no client ever connects -> probe exits 22, and the
                              pipe name is gone from the namespace afterwards
  cpp_server_read_stall       client connects and never sends -> probe exits 22
  cpp_server_drain_stall      client sends, never reads, keeps the handle open
                              -> PEER_OK is written, probe exits 23 (bounded
                              replacement for FlushFileBuffers)
  cpp_client_silent_server    server connects and never answers -> C++ client
                              exits 22
  cpp_bad_arguments           malformed --budget-ms -> both binaries exit 24
  cpp_pair_small_budget       positive control: C++ <-> C++ with the stall
                              budget completes PEER_OK (exit 0 / 0)

Exit 0 only if everything above holds. The JSON report records the compiler
banner and the SHA-256 of both binaries. It is NOT a release approval, not a
standard-user result on the hosted runner (elevated Administrator), and the
stall cases do not exercise the cancel-race / exit-31 path (no fault injection
into the kernel); they show the deadline and cancellation on the normal path.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {'probe': 'windows/udx_sid_probe.cpp', 'client': 'windows/udx_sid_client.cpp'}
HEADER = 'windows/udx_bounded_pipe_io.hpp'          # included by both sources (W24)
CL_FLAGS = '/nologo /W4 /WX /EHsc /std:c++17'
TIMEOUT_S = 20.0
# W24 stall cases: the binary gets STALL_BUDGET_MS for the whole exchange, the
# stalling party holds HOLD_S. A bounded binary exits after the budget plus at
# most the cancel grace (1 s); STALL_LIMIT_S adds scheduling slack and stays
# far below HOLD_S, so "exited because the holder let go" can never pass.
STALL_BUDGET_MS = 1500
HOLD_S = 8.0
STALL_LIMIT_S = 5.0
EXIT_TIMEOUT, EXIT_PEER_NOT_CLOSED, EXIT_BAD_ARGUMENTS = 22, 23, 24
EXPECTED_CASES = ('cpp_server+cpp_client', 'cpp_server+py_client', 'py_server+cpp_client',
                  'cpp_server_name_occupied', 'cpp_server_legacy_open',
                  'cpp_server_connect_timeout', 'cpp_server_read_stall', 'cpp_server_drain_stall',
                  'cpp_client_silent_server', 'cpp_bad_arguments', 'cpp_pair_small_budget')
BAD_ARGUMENTS = (['--budget-ms'], ['--budget-ms', '99'], ['--budget-ms', '300001'],
                 ['--budget-ms', '1e3'], ['--budget-ms', '-5'], ['--budget-ms', '1500', 'x'],
                 ['--bogus', '1500'], ['--budget-ms', '0001500'])


def reference_parse_budget(args):
    """Python reference of udx::parse_budget (windows/udx_bounded_pipe_io.hpp).

    Returns the budget in ms, or None where the C++ parser must refuse (exit 24).
    The native case cpp_bad_arguments checks the binaries agree on BAD_ARGUMENTS.
    """
    if args == []:
        return 10000
    if (type(args) is not list or len(args) != 2 or args[0] != '--budget-ms' or type(args[1]) is not str
            or not 1 <= len(args[1]) <= 6 or any(c not in '0123456789' for c in args[1])):
        return None
    value = int(args[1])
    return value if 100 <= value <= 300000 else None


def stall_verdict(exit_code, elapsed_s, expected_exit: int) -> bool:
    """Fail-closed decision for one W24 stall case (pure; tested portably).

    PASS only for the exact typed exit code of a process that ended on its own
    (``exit_code`` is None when the harness had to kill it) within
    STALL_LIMIT_S. A wrong code, a kill, a non-finite or negative time, or a
    bool posing as an int is a FAIL.
    """
    if type(exit_code) is not int or type(expected_exit) is not int:
        return False
    if type(elapsed_s) not in (int, float) or not math.isfinite(elapsed_s) or elapsed_s < 0:
        return False
    return exit_code == expected_exit and elapsed_s <= STALL_LIMIT_S


def all_cases_pass(cases) -> bool:
    """Exactly EXPECTED_CASES, each with ``ok is True``."""
    return (type(cases) is dict and set(cases) == set(EXPECTED_CASES)
            and all(type(c) is dict and c.get('ok') is True for c in cases.values()))


def find_vcvars() -> pathlib.Path:
    base = pathlib.Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'))
    vswhere = base / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
    out = subprocess.run([str(vswhere), '-latest', '-products', '*', '-requires',
                          'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout.strip()
    vcvars = pathlib.Path(out.splitlines()[0]) / 'VC' / 'Auxiliary' / 'Build' / 'vcvars64.bat'
    if not vcvars.is_file():
        raise FileNotFoundError(str(vcvars))
    return vcvars


def build(repo: pathlib.Path, out: pathlib.Path) -> dict:
    vcvars = find_vcvars()
    # /nologo hides the banner, so ask cl once without arguments for its version.
    banner = subprocess.run('cmd /d /s /c "call "' + str(vcvars) + '" >nul && cl"', stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=120).stderr
    result = {'flags': CL_FLAGS, 'binaries': {},
              'compiler': next((x.strip() for x in banner.splitlines() if 'Compiler Version' in x), None)}
    for key, src in SOURCES.items():
        exe = out / (pathlib.Path(src).stem + '.exe')
        line = (f'call "{vcvars}" >nul && cl {CL_FLAGS} /Fe"{exe}" /Fo"{out}\\\\" '
                f'"{repo / src}" advapi32.lib')
        proc = subprocess.run('cmd /d /s /c "' + line + '"', stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0 or not exe.is_file():
            result['error'] = {'source': src, 'exit': proc.returncode,
                               'output': (proc.stdout + proc.stderr)[-4000:]}
            return result
        result['binaries'][key] = {'source': src,
                                   'source_sha256': hashlib.sha256((repo / src).read_bytes()).hexdigest(),
                                   'sha256': hashlib.sha256(exe.read_bytes()).hexdigest()}
    result['header_sha256'] = hashlib.sha256((repo / HEADER).read_bytes()).hexdigest()
    return result


def _wait_for_pipe(wp, deadline: float) -> bool:
    api = wp.default_api()
    while time.monotonic() < deadline:
        if api.WaitNamedPipeW(wp.DEFAULT_PIPE_NAME, 50):
            return True
        time.sleep(0.02)
    return False


def _stop(proc) -> int | None:
    try:
        return proc.wait(TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return None


def run_cases(out: pathlib.Path, cases: dict, spawned: list) -> dict:
    """Fills ``cases`` in place; every started probe is appended to ``spawned``
    so main() can kill leftovers if a step raises (timeout, missing pipe)."""
    from udx_ref import windows_pipe as wp
    probe, client = str(out / 'udx_sid_probe.exe'), str(out / 'udx_sid_client.exe')

    def cpp_server():
        proc = subprocess.Popen([probe], stdin=subprocess.DEVNULL)
        spawned.append(proc)
        if not _wait_for_pipe(wp, time.monotonic() + TIMEOUT_S):
            proc.kill()
            proc.wait()
            raise RuntimeError('CPP_SERVER_PIPE_NOT_CREATED')
        return proc

    srv = cpp_server()
    cli = subprocess.run([client], stdin=subprocess.DEVNULL, timeout=TIMEOUT_S)
    code = _stop(srv)
    cases['cpp_server+cpp_client'] = {'server_exit': code, 'client_exit': cli.returncode,
                                      'ok': code == 0 and cli.returncode == 0}

    srv = cpp_server()
    r = wp.client_ping(wp.DEFAULT_PIPE_NAME, connect_timeout_s=TIMEOUT_S, response_timeout_s=TIMEOUT_S)
    code = _stop(srv)
    cases['cpp_server+py_client'] = {'server_exit': code, 'client_reason': r.reason,
                                     'ok': code == 0 and r.reason == 'OK'}

    box = {}
    with wp.OneShotPipeServer(wp.DEFAULT_PIPE_NAME) as py_srv:
        t = threading.Thread(target=lambda: box.setdefault('r', py_srv.serve(TIMEOUT_S)), daemon=True)
        t.start()
        cli = subprocess.run([client], stdin=subprocess.DEVNULL, timeout=TIMEOUT_S)
        t.join(TIMEOUT_S + 5)
    res = box.get('r')
    cases['py_server+cpp_client'] = {'server_verdict': res.verdict if res else None,
                                     'server_reason': res.reason if res else None,
                                     'client_exit': cli.returncode,
                                     'ok': bool(res and res.ok) and cli.returncode == 0}

    # W20: C++ parity of W19 PIPE_NAME_OCCUPIED. The name is held by the Python
    # server; the C++ probe must exit 21 (not the generic 14), and the holder's
    # instance stays usable (a client still completes the handshake with it).
    box = {}
    with wp.OneShotPipeServer(wp.DEFAULT_PIPE_NAME) as holder:
        occupied = subprocess.run([probe], stdin=subprocess.DEVNULL, timeout=TIMEOUT_S)
        t = threading.Thread(target=lambda: box.setdefault('r', holder.serve(TIMEOUT_S)), daemon=True)
        t.start()
        r = wp.client_ping(wp.DEFAULT_PIPE_NAME, connect_timeout_s=TIMEOUT_S, response_timeout_s=TIMEOUT_S)
        t.join(TIMEOUT_S + 5)
    held = box.get('r')
    cases['cpp_server_name_occupied'] = {'probe_exit': occupied.returncode, 'holder_client_reason': r.reason,
                                         'holder_verdict': held.verdict if held else None,
                                         'ok': occupied.returncode == 21 and r.reason == 'OK'
                                         and bool(held and held.ok)}

    srv = cpp_server()
    api = wp.default_api()
    h = api.CreateFileW(wp.DEFAULT_PIPE_NAME, wp.GENERIC_READ | wp.GENERIC_WRITE, 0, None,
                        wp.OPEN_EXISTING, 0, None)
    legacy_err = None
    if h is None or h == wp.INVALID_HANDLE_VALUE:
        legacy_err = api.last_error()
    else:
        api.CloseHandle(h)
    r = wp.client_ping(wp.DEFAULT_PIPE_NAME, connect_timeout_s=TIMEOUT_S, response_timeout_s=TIMEOUT_S)
    code = _stop(srv)
    cases['cpp_server_legacy_open'] = {'legacy_open_winerror': legacy_err, 'then_client_reason': r.reason,
                                       'server_exit': code,
                                       'ok': legacy_err == wp.ERROR_ACCESS_DENIED and r.reason == 'OK' and code == 0}
    run_w24_cases(wp, probe, client, cases, spawned)
    return cases


def _timed_exit(proc, t0: float):
    """(exit code or None if it had to be killed, seconds since ``t0``)."""
    try:
        code = proc.wait(TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        code = None
    return code, round(time.monotonic() - t0, 3)


def _raw_client_send_then_hold(wp, hold_s: float, box: dict) -> None:
    """Drain stall: open like client_ping, send the ping, never read, keep the
    handle open for ``hold_s``. Records the write result in ``box``."""
    api = wp.default_api()
    flags = wp.client_sqos_flags('identification') | wp.FILE_FLAG_OVERLAPPED
    end = time.monotonic() + TIMEOUT_S
    while True:
        h = api.CreateFileW(wp.DEFAULT_PIPE_NAME, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING, flags, None)
        if h is not None and h != wp.INVALID_HANDLE_VALUE:
            break
        if time.monotonic() >= end:
            box['open_error'] = api.last_error()
            return
        time.sleep(0.02)
    try:
        ping = ctypes.create_string_buffer(b'\x55', 1)
        ok, n, err = wp._overlapped_io(api, h, lambda ov: api.WriteFile(h, ping, 1, None, ov),
                                       time.monotonic() + 5.0)
        box['sent'] = bool(ok and n == 1)
        time.sleep(hold_s)
    finally:
        api.CloseHandle(h)


class _SilentServer:
    """Fake server for the C++ client: same name, explicit owner = this user
    (so the client's owner check passes), accepts the connection and never
    answers for HOLD_S. Single instance, no impersonation, no token use."""

    def __init__(self, wp):
        self.wp, self.api = wp, wp.default_api()
        sd = ctypes.c_void_p()
        # UT6-02: the C++ client accepts only a label equal to its own level, so
        # the fake server labels at this process' level like a real server would.
        sddl = wp.build_sddl(wp.current_user_sid(self.api), wp.own_integrity_rid(self.api))
        if not self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, wp.SDDL_REVISION_1,
                                                                             ctypes.byref(sd), None):
            raise OSError(self.api.last_error(), 'SDDL conversion failed')
        try:
            sa = wp.SECURITY_ATTRIBUTES(ctypes.sizeof(wp.SECURITY_ATTRIBUTES), sd, False)
            mode = wp.PIPE_TYPE_BYTE | wp.PIPE_READMODE_BYTE | wp.PIPE_WAIT | wp.PIPE_REJECT_REMOTE_CLIENTS
            h = self.api.CreateNamedPipeW(wp.DEFAULT_PIPE_NAME, wp.PIPE_ACCESS_DUPLEX
                                          | wp.FILE_FLAG_FIRST_PIPE_INSTANCE | wp.FILE_FLAG_OVERLAPPED,
                                          mode, 1, 4096, 4096, 0, ctypes.byref(sa))
        finally:
            self.api.LocalFree(sd)
        if h is None or h == wp.INVALID_HANDLE_VALUE:
            raise OSError(self.api.last_error(), 'CreateNamedPipeW failed')
        self.handle, self.connected = h, False

    def hold(self, hold_s: float) -> None:
        end = time.monotonic() + hold_s
        try:
            ok, _, _ = self.wp._overlapped_io(self.api, self.handle,
                                              lambda ov: self.api.ConnectNamedPipe(self.handle, ov), end)
            self.connected = bool(ok)
        except self.wp._Timeout:
            self.connected = False
        time.sleep(max(0.0, end - time.monotonic()))

    def close(self) -> None:
        if self.handle is not None:
            self.api.DisconnectNamedPipe(self.handle)
            self.api.CloseHandle(self.handle)
            self.handle = None


def run_w24_cases(wp, probe: str, client: str, cases: dict, spawned: list) -> None:
    """W24 negative-first cases for the bounded C++ I/O; see the module docstring."""
    budget = ['--budget-ms', str(STALL_BUDGET_MS)]

    def start_probe():
        proc = subprocess.Popen([probe] + budget, stdin=subprocess.DEVNULL)
        spawned.append(proc)
        t0 = time.monotonic()
        if not _wait_for_pipe(wp, t0 + TIMEOUT_S):
            proc.kill()
            proc.wait()
            raise RuntimeError('CPP_SERVER_PIPE_NOT_CREATED')
        return proc, t0

    # (1) nobody connects. W20: ConnectNamedPipe blocked forever.
    proc, t0 = start_probe()
    code, elapsed = _timed_exit(proc, t0)
    gone = not wp.pipe_name_present(wp.default_api(), wp.DEFAULT_PIPE_NAME)
    cases['cpp_server_connect_timeout'] = {'probe_exit': code, 'elapsed_s': elapsed, 'name_released': gone,
                                           'ok': stall_verdict(code, elapsed, EXIT_TIMEOUT) and gone}

    # (2) the client connects and never sends. W20: ReadFile blocked until the client closed.
    proc, _ = start_probe()
    box = {}
    holder = threading.Thread(target=lambda: box.setdefault('r', wp.client_ping(
        wp.DEFAULT_PIPE_NAME, send=False, hold_s=HOLD_S, connect_timeout_s=TIMEOUT_S)), daemon=True)
    t0 = time.monotonic()
    holder.start()
    code, elapsed = _timed_exit(proc, t0)
    holder.join(HOLD_S + TIMEOUT_S)
    held = box.get('r')
    cases['cpp_server_read_stall'] = {'probe_exit': code, 'elapsed_s': elapsed,
                                      'holder_reason': held.reason if held else None,
                                      'ok': stall_verdict(code, elapsed, EXIT_TIMEOUT)
                                      and bool(held and held.reason == 'SILENT_HOLD')}

    # (3) the client sends, never reads, keeps the handle. W20: FlushFileBuffers
    # waited for the client to read, i.e. until it closed.
    proc, _ = start_probe()
    box = {}
    holder = threading.Thread(target=_raw_client_send_then_hold, args=(wp, HOLD_S, box), daemon=True)
    t0 = time.monotonic()
    holder.start()
    code, elapsed = _timed_exit(proc, t0)
    holder.join(HOLD_S + TIMEOUT_S)
    cases['cpp_server_drain_stall'] = {'probe_exit': code, 'elapsed_s': elapsed, 'holder_sent': box.get('sent'),
                                       'ok': stall_verdict(code, elapsed, EXIT_PEER_NOT_CLOSED)
                                       and box.get('sent') is True}

    # (4) a silent server; the C++ client must not wait for it forever.
    srv = _SilentServer(wp)
    try:
        holder = threading.Thread(target=srv.hold, args=(HOLD_S,), daemon=True)
        holder.start()
        t0 = time.monotonic()
        cli = subprocess.Popen([client] + budget, stdin=subprocess.DEVNULL)
        spawned.append(cli)
        code, elapsed = _timed_exit(cli, t0)
        holder.join(HOLD_S + TIMEOUT_S)
    finally:
        srv.close()
    cases['cpp_client_silent_server'] = {'client_exit': code, 'elapsed_s': elapsed,
                                         'server_saw_connect': srv.connected,
                                         'ok': stall_verdict(code, elapsed, EXIT_TIMEOUT) and srv.connected}

    # (5) fail-closed argument parser in both binaries; nothing is created.
    exits = {}
    for exe, label in ((probe, 'probe'), (client, 'client')):
        for args in BAD_ARGUMENTS:
            r = subprocess.run([exe] + args, stdin=subprocess.DEVNULL, timeout=TIMEOUT_S)
            exits[label + ' ' + ' '.join(args)] = r.returncode
    cases['cpp_bad_arguments'] = {'exits': exits,
                                  'ok': len(exits) == 2 * len(BAD_ARGUMENTS)
                                  and all(v == EXIT_BAD_ARGUMENTS for v in exits.values())}

    # (6) positive control with the same small budget: the deadline does not
    # break the normal exchange.
    proc, _ = start_probe()
    cli = subprocess.run([client] + budget, stdin=subprocess.DEVNULL, timeout=TIMEOUT_S)
    code = _stop(proc)
    cases['cpp_pair_small_budget'] = {'server_exit': code, 'client_exit': cli.returncode,
                                      'ok': code == 0 and cli.returncode == 0}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--repo', type=pathlib.Path, default=REPO)
    p.add_argument('--output', type=pathlib.Path)
    args = p.parse_args(argv)
    report = {'schema_version': 1, 'tool': 'W18_CPP_CROSSRUN', 'research_only': True,
              'release_authorized': False}
    if sys.platform != 'win32':
        report['verdict'] = 'NATIVE_WINDOWS_REQUIRED'
        code = 2
    else:
        repo = args.repo.resolve()
        sys.path.insert(0, str(repo))
        with tempfile.TemporaryDirectory(prefix='udx_w18_cpp_') as tmp:
            out = pathlib.Path(tmp)
            report['build'] = build(repo, out)
            if 'error' in report['build']:
                report['verdict'] = 'BUILD_FAILED'
                code = 1
            else:
                report['cases'], spawned = {}, []
                try:
                    run_cases(out, report['cases'], spawned)
                except Exception as exc:                    # report it, never lose the JSON
                    report['error'] = '%s: %s' % (type(exc).__name__, exc)
                finally:
                    for proc in spawned:
                        if proc.poll() is None:
                            proc.kill()
                            proc.wait()
                ok = not report.get('error') and all_cases_pass(report['cases'])
                report['verdict'] = 'CROSSRUN_OK' if ok else 'CROSSRUN_FAILED'
                code = 0 if ok else 1
        report['host'] = {'platform': sys.platform, 'python': sys.version.split()[0],
                          'elevated': bool(ctypes.windll.shell32.IsUserAnAdmin())}
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(payload, encoding='utf-8')
    print(payload, end='')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
