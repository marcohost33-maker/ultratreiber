"""W30: the C++ cancel path on a real Windows kernel (exit 31, completion in the race, boundary races).

RESEARCH ONLY. W24 bounded every C++ pipe operation but could not reach two
branches of ``udx::cancel_and_settle`` on a real kernel: the fail-closed exit 31
(cancelled I/O does not settle) and "completed in the race: still a timeout".
W24 test coverage for them was source guards + mutations only.

This tool builds three variants of both binaries with MSVC ``/W4 /WX``:

  production   no /D: the bytes CI ships (also used by tools/w18_cpp_crossrun.py)
  fi_skip      /DUDX_FI_SKIP_CANCEL: at the deadline CancelIoEx is NOT requested,
               so a stalled I/O stays really pending through the 1 s grace
  fi_sleep     /DUDX_FI_PRE_CANCEL_SLEEP_MS=1500: sleep before CancelIoEx, so a
               peer can complete the I/O after the deadline but before the cancel

Fault-injection binaries print ``UDX_FAULT_INJECTION_BUILD`` before main and one
marker per reached branch (stderr). Cases (every one with a real second process
or a real second party holding the pipe):

  fi_banner                  production binaries print no FI marker; FI ones do
  fi_skip_server_exit31      silent client holds -> probe exit 31, markers
                             CANCEL_SKIPPED + DIE_CANCEL_UNCERTAIN, name released
  fi_skip_client_exit31      silent server holds -> C++ client exit 31
  fi_sleep_server_race       client sends the ping after the deadline, before the
                             cancel -> read completed, still exit 22, the client
                             gets 0 bytes (no PEER_OK after the deadline)
  fi_sleep_client_race       server answers PEER_OK after the client deadline,
                             before its cancel -> client exit 22, not 0
  fi_controls                both FI variants still complete a normal exchange 0/0
  race_server_campaign       100 production runs, client ping at a seeded offset
                             around the server deadline (guard-band oracle)
  race_client_campaign       100 production runs, fake server answers at a seeded
                             offset around the client deadline (guard-band oracle)

Exit 0 only if every case holds. NOT shown: handle/memory profiles, a cancel
that fails (CancelIoEx returning FALSE for a pending I/O is not provokable from
user mode), standard-account / Windows 11 runs. Never a release approval.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import pathlib
import random
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import w18_cpp_crossrun as w18  # noqa: E402  (shared MSVC lookup, helpers)
sys.path.pop(0)

SOURCES = w18.SOURCES
HEADER = w18.HEADER
CL_FLAGS = w18.CL_FLAGS
VARIANTS = {
    'production': '',
    'fi_skip': '/DUDX_FI_SKIP_CANCEL',
    'fi_sleep': '/DUDX_FI_PRE_CANCEL_SLEEP_MS=1500',
}
FI_SLEEP_S = 1.5
CANCEL_GRACE_S = 1.0          # udx::kCancelGraceMs
TIMEOUT_S = 20.0
HOLD_S = 8.0
LIMIT_S = 5.0                 # budget + grace + scheduling slack, far below HOLD_S
EXIT_TIMEOUT, EXIT_PEER_NOT_CLOSED, EXIT_BAD_ARGUMENTS, EXIT_CANCEL_UNCERTAIN = 22, 23, 24, 31
BANNER = 'UDX_FAULT_INJECTION_BUILD'
MARK_SKIPPED = 'UDX_FI_CANCEL_SKIPPED'
MARK_DIE = 'UDX_FI_DIE_CANCEL_UNCERTAIN'
MARK_RACE = 'UDX_FI_COMPLETED_IN_RACE bytes>0'
FI_MARKERS = (BANNER, MARK_SKIPPED, MARK_DIE, MARK_RACE, 'UDX_FI_COMPLETED_IN_RACE bytes=0')

# Race campaigns (production binaries only).
CAMPAIGN_RUNS = 100
CAMPAIGN_SEED = 20261122
CAMPAIGN_BUDGET_MS = 400
CAMPAIGN_OFFSETS_S = (0.0, 0.8)    # server campaign, uniform; the deadline (0.4 s) in the middle
CLIENT_OFFSETS_S = (0.0, 1.2)      # client campaign: its deadline starts with the process
GUARD_S = 0.2                      # band around the deadline in which any side may win
CLIENT_LATE_S = 0.6                # client campaign: upper band covers the client's start-up
MIN_PER_SIDE = 10                  # each side of the boundary must really be exercised

EXPECTED_CASES = ('fi_banner', 'fi_skip_server_exit31', 'fi_skip_client_exit31', 'fi_sleep_server_race',
                  'fi_sleep_client_race', 'fi_controls', 'race_server_campaign', 'race_client_campaign')


# --- pure decisions (tested portably) ----------------------------------------
def _finite_time(t) -> bool:
    return type(t) in (int, float) and math.isfinite(t) and t >= 0


def markers_ok(stderr_text, required, forbidden=()) -> bool:
    """Every ``required`` marker line present, no ``forbidden`` one. Lines are
    compared exactly (a marker inside another line does not count)."""
    if type(stderr_text) is not str:
        return False
    lines = {line.strip() for line in stderr_text.splitlines()}
    return all(m in lines for m in required) and not any(m in lines for m in forbidden)


def exit31_verdict(exit_code, elapsed_s, stderr_text, budget_s) -> bool:
    """FI skip-cancel: exit 31 after (at least) the budget plus most of the grace,
    within LIMIT_S, with both markers. Exiting before budget + grace would mean the
    grace wait was not bounded by the kernel completion but skipped."""
    if type(exit_code) is not int or not _finite_time(elapsed_s) or not _finite_time(budget_s):
        return False
    return (exit_code == EXIT_CANCEL_UNCERTAIN
            and budget_s + 0.8 * CANCEL_GRACE_S <= elapsed_s <= LIMIT_S
            and markers_ok(stderr_text, (BANNER, MARK_SKIPPED, MARK_DIE)))


def race_verdict(exit_code, elapsed_s, stderr_text, received) -> bool:
    """FI sleep: the I/O completed after the deadline (marker with bytes>0), the
    outcome is still the timeout (22), no die marker, the peer got no PEER_OK."""
    if type(exit_code) is not int or not _finite_time(elapsed_s) or type(received) is not bytes:
        return False
    return (exit_code == EXIT_TIMEOUT and elapsed_s <= LIMIT_S + FI_SLEEP_S
            and markers_ok(stderr_text, (BANNER, MARK_RACE), (MARK_DIE, MARK_SKIPPED))
            and b'PEER_OK' not in received)


def server_run_ok(offset_s, budget_s, exit_code, elapsed_s, received) -> bool:
    """One server-campaign run. Always: exit in {0, 22, 23}, never 31 or a kill,
    the client sees either nothing or exactly PEER_OK (never a fragment), 0 =>
    PEER_OK delivered, 22 => nothing delivered. Outside the guard band the side is
    forced: ping clearly before the deadline -> 0, clearly after -> 22."""
    if type(exit_code) is not int or type(received) is not bytes or not _finite_time(elapsed_s):
        return False
    if not _finite_time(offset_s) or not _finite_time(budget_s):
        return False
    if exit_code not in (0, EXIT_TIMEOUT, EXIT_PEER_NOT_CLOSED) or elapsed_s > LIMIT_S:
        return False
    if received not in (b'', b'PEER_OK'):
        return False
    if exit_code == 0 and received != b'PEER_OK':
        return False
    if exit_code == EXIT_TIMEOUT and received != b'':
        return False
    if offset_s <= budget_s - GUARD_S and exit_code != 0:
        return False
    if offset_s >= budget_s + GUARD_S and exit_code != EXIT_TIMEOUT:
        return False
    return True


def client_run_ok(offset_s, budget_s, exit_code, elapsed_s) -> bool:
    """One client-campaign run (offset from the client's launch; its deadline
    starts a little later, when the process runs). Always exit 0 or 22. Answer
    clearly before the deadline -> 0; later than budget + CLIENT_LATE_S -> 22."""
    if type(exit_code) is not int or not _finite_time(elapsed_s):
        return False
    if not _finite_time(offset_s) or not _finite_time(budget_s):
        return False
    if exit_code not in (0, EXIT_TIMEOUT) or elapsed_s > LIMIT_S:
        return False
    if offset_s <= budget_s - GUARD_S and exit_code != 0:
        return False
    if offset_s >= budget_s + CLIENT_LATE_S and exit_code != EXIT_TIMEOUT:
        return False
    return True


def campaign_verdict(runs, n_expected: int, ok_codes) -> bool:
    """All runs present and ok, and both sides of the boundary really occurred
    (>= MIN_PER_SIDE runs ending 0 and >= MIN_PER_SIDE ending 22)."""
    if type(runs) is not list or len(runs) != n_expected:
        return False
    if not all(type(r) is dict and r.get('ok') is True for r in runs):
        return False
    codes = [r.get('exit') for r in runs]
    if any(c not in ok_codes for c in codes):
        return False
    return codes.count(0) >= MIN_PER_SIDE and codes.count(EXIT_TIMEOUT) >= MIN_PER_SIDE


def campaign_offsets(seed: int = CAMPAIGN_SEED, n: int = CAMPAIGN_RUNS, bounds=CAMPAIGN_OFFSETS_S):
    rng = random.Random(seed)
    lo, hi = bounds
    return [round(rng.uniform(lo, hi), 4) for _ in range(n)]


def all_cases_pass(cases) -> bool:
    return (type(cases) is dict and set(cases) == set(EXPECTED_CASES)
            and all(type(c) is dict and c.get('ok') is True for c in cases.values()))


# --- native part ---------------------------------------------------------------
def build(repo: pathlib.Path, out: pathlib.Path) -> dict:
    vcvars = w18.find_vcvars()
    banner = subprocess.run('cmd /d /s /c "call "' + str(vcvars) + '" >nul && cl"', stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=120).stderr
    result = {'flags': CL_FLAGS, 'variants': {},
              'compiler': next((x.strip() for x in banner.splitlines() if 'Compiler Version' in x), None),
              'header_sha256': hashlib.sha256((repo / HEADER).read_bytes()).hexdigest()}
    for variant, define in VARIANTS.items():
        vdir = out / variant
        vdir.mkdir()
        result['variants'][variant] = {'define': define, 'binaries': {}}
        for key, src in SOURCES.items():
            exe = vdir / (pathlib.Path(src).stem + '.exe')
            line = (f'call "{vcvars}" >nul && cl {CL_FLAGS} {define} /Fe"{exe}" /Fo"{vdir}\\\\" '
                    f'"{repo / src}" advapi32.lib')
            proc = subprocess.run('cmd /d /s /c "' + line + '"', stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=300)
            if proc.returncode != 0 or not exe.is_file():
                result['error'] = {'variant': variant, 'source': src, 'exit': proc.returncode,
                                   'output': (proc.stdout + proc.stderr)[-4000:]}
                return result
            result['variants'][variant]['binaries'][key] = hashlib.sha256(exe.read_bytes()).hexdigest()
    return result


def _exe(out: pathlib.Path, variant: str, key: str) -> str:
    return str(out / variant / (pathlib.Path(SOURCES[key]).stem + '.exe'))


def _start(exe: str, args, spawned: list):
    proc = subprocess.Popen([exe] + list(args), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    spawned.append(proc)
    return proc


def _finish(proc, t0: float):
    """(exit code or None if killed, seconds since t0, stderr text)."""
    try:
        _, err = proc.communicate(timeout=TIMEOUT_S)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
        code = None
    return code, round(time.monotonic() - t0, 3), err or ''


def _start_server(wp, exe: str, budget_ms: int, spawned: list):
    proc = _start(exe, ['--budget-ms', str(budget_ms)], spawned)
    if not w18._wait_for_pipe(wp, time.monotonic() + TIMEOUT_S):
        proc.kill()
        proc.wait()
        raise RuntimeError('CPP_SERVER_PIPE_NOT_CREATED')
    return proc, time.monotonic()


def _raw_client(wp, t_ready: float, send_at_s: float, box: dict) -> None:
    """Open like client_ping, send the ping at t_ready + send_at_s, then read until
    7 bytes, EOF or 4 s. ``box``: open_error, sent, received."""
    api = wp.default_api()
    flags = wp.client_sqos_flags('identification') | wp.FILE_FLAG_OVERLAPPED
    end = time.monotonic() + TIMEOUT_S
    while True:
        h = api.CreateFileW(wp.DEFAULT_PIPE_NAME, wp.CLIENT_ACCESS, 0, None, wp.OPEN_EXISTING, flags, None)
        if h is not None and h != wp.INVALID_HANDLE_VALUE:
            break
        if time.monotonic() >= end:
            box['open_error'] = api.last_error()
            box['received'] = b''
            return
        time.sleep(0.01)
    data = b''
    try:
        time.sleep(max(0.0, t_ready + send_at_s - time.monotonic()))
        ping = ctypes.create_string_buffer(b'\x55', 1)
        try:
            ok, n, _ = wp._overlapped_io(api, h, lambda ov: api.WriteFile(h, ping, 1, None, ov),
                                         time.monotonic() + 2.0)
            box['sent'] = bool(ok and n == 1)
        except wp._Timeout:
            box['sent'] = False
        if box['sent']:
            buf = ctypes.create_string_buffer(7)
            deadline = time.monotonic() + 4.0
            while len(data) < 7:
                want = 7 - len(data)
                try:
                    ok, got, _ = wp._overlapped_io(api, h, lambda ov: api.ReadFile(h, buf, want, None, ov),
                                                   deadline)
                except wp._Timeout:
                    break
                if not ok or got == 0:
                    break
                data += buf.raw[:got]
    finally:
        api.CloseHandle(h)
        box['received'] = data


class _AnsweringServer(w18._SilentServer):
    """Fake server (own-level label, like w18._SilentServer): accepts, reads the
    ping, answers PEER_OK at t_launch + answer_at_s, then keeps the pipe open
    briefly so the client's read is not cut by an early close."""

    def serve(self, t_launch: float, answer_at_s: float, box: dict) -> None:
        wp, api, h = self.wp, self.api, self.handle
        end = time.monotonic() + TIMEOUT_S
        try:
            ok, _, _ = wp._overlapped_io(api, h, lambda ov: api.ConnectNamedPipe(h, ov), end)
            self.connected = bool(ok)
            ping = ctypes.create_string_buffer(1)
            ok, n, _ = wp._overlapped_io(api, h, lambda ov: api.ReadFile(h, ping, 1, None, ov), end)
            box['got_ping'] = bool(ok and n == 1)
            time.sleep(max(0.0, t_launch + answer_at_s - time.monotonic()))
            out = ctypes.create_string_buffer(b'PEER_OK', 7)
            ok, n, err = wp._overlapped_io(api, h, lambda ov: api.WriteFile(h, out, 7, None, ov),
                                           time.monotonic() + 2.0)
            box['wrote'] = bool(ok and n == 7)
            box['write_error'] = err
            time.sleep(0.3)
        except wp._Timeout:
            box['timeout'] = True


def run_cases(out: pathlib.Path, cases: dict, spawned: list) -> None:
    from udx_ref import windows_pipe as wp
    prod_probe, prod_client = _exe(out, 'production', 'probe'), _exe(out, 'production', 'client')

    # fi_banner: production binaries carry no FI marker; FI binaries announce themselves.
    seen = {}
    for variant in VARIANTS:
        for key in SOURCES:
            r = subprocess.run([_exe(out, variant, key), '--bogus'], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=TIMEOUT_S)
            seen[variant + ':' + key] = {'exit': r.returncode, 'banner': markers_ok(r.stderr, (BANNER,))}
    cases['fi_banner'] = {'runs': seen, 'ok': all(
        v['exit'] == EXIT_BAD_ARGUMENTS and v['banner'] == (not k.startswith('production'))
        for k, v in seen.items()) and len(seen) == len(VARIANTS) * len(SOURCES)}

    # fi_skip_server_exit31: the silent client never sends; with the cancel skipped
    # the read stays pending through the grace -> exit 31.
    budget = 800
    proc, t_ready = _start_server(wp, _exe(out, 'fi_skip', 'probe'), budget, spawned)
    box = {}
    holder = threading.Thread(target=lambda: box.setdefault('r', wp.client_ping(
        wp.DEFAULT_PIPE_NAME, send=False, hold_s=HOLD_S, connect_timeout_s=TIMEOUT_S)), daemon=True)
    holder.start()
    code, elapsed, err = _finish(proc, t_ready)
    released = not wp.pipe_name_present(wp.default_api(), wp.DEFAULT_PIPE_NAME)
    holder.join(HOLD_S + TIMEOUT_S)
    cases['fi_skip_server_exit31'] = {'exit': code, 'elapsed_s': elapsed, 'name_released': released,
                                      'stderr': err.strip().splitlines(),
                                      'ok': exit31_verdict(code, elapsed, err, budget / 1000) and released}

    # fi_skip_client_exit31: silent server; the client's read stays pending.
    srv = w18._SilentServer(wp)
    try:
        holder = threading.Thread(target=srv.hold, args=(HOLD_S,), daemon=True)
        holder.start()
        t0 = time.monotonic()
        cli = _start(_exe(out, 'fi_skip', 'client'), ['--budget-ms', str(budget)], spawned)
        code, elapsed, err = _finish(cli, t0)
        holder.join(HOLD_S + TIMEOUT_S)
    finally:
        srv.close()
    cases['fi_skip_client_exit31'] = {'exit': code, 'elapsed_s': elapsed, 'server_saw_connect': srv.connected,
                                      'stderr': err.strip().splitlines(),
                                      'ok': exit31_verdict(code, elapsed, err, budget / 1000) and srv.connected}

    # fi_sleep_server_race: budget 1.0 s, cancel at ~2.5 s; the ping arrives at
    # 1.75 s, i.e. after the deadline and before the cancel.
    proc, t_ready = _start_server(wp, _exe(out, 'fi_sleep', 'probe'), 1000, spawned)
    box = {}
    cl = threading.Thread(target=_raw_client, args=(wp, t_ready, 1.75, box), daemon=True)
    cl.start()
    code, elapsed, err = _finish(proc, t_ready)
    cl.join(TIMEOUT_S)
    received = box.get('received', b'')
    cases['fi_sleep_server_race'] = {'exit': code, 'elapsed_s': elapsed, 'client_sent': box.get('sent'),
                                     'client_received': received.decode('latin-1'),
                                     'stderr': err.strip().splitlines(),
                                     'ok': race_verdict(code, elapsed, err, received) and box.get('sent') is True}

    # fi_sleep_client_race: the fake server answers at 1.75 s after the launch;
    # the client's deadline is ~1.0 s after its start, its cancel ~1.5 s later.
    srv = _AnsweringServer(wp)
    box = {}
    try:
        t0 = time.monotonic()
        th = threading.Thread(target=srv.serve, args=(t0, 1.75, box), daemon=True)
        th.start()
        cli = _start(_exe(out, 'fi_sleep', 'client'), ['--budget-ms', '1000'], spawned)
        code, elapsed, err = _finish(cli, t0)
        th.join(TIMEOUT_S)
    finally:
        srv.close()
    # The answer was written into the pipe buffer (wrote=True) but completed the
    # client's read only after its deadline: the client must still exit 22.
    cases['fi_sleep_client_race'] = {'exit': code, 'elapsed_s': elapsed, 'server': {
        k: box.get(k) for k in ('got_ping', 'wrote', 'write_error', 'timeout')},
        'stderr': err.strip().splitlines(),
        'ok': race_verdict(code, elapsed, err, b'') and box.get('got_ping') is True
        and box.get('wrote') is True}

    # fi_controls: both FI variants behave normally when nothing stalls.
    ctl = {}
    for variant in ('fi_skip', 'fi_sleep'):
        proc, t_ready = _start_server(wp, _exe(out, variant, 'probe'), 5000, spawned)
        cli = subprocess.run([_exe(out, variant, 'client'), '--budget-ms', '5000'], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=TIMEOUT_S)
        code, elapsed, err = _finish(proc, t_ready)
        ctl[variant] = {'server_exit': code, 'client_exit': cli.returncode,
                        'only_banner': markers_ok(err, (BANNER,), FI_MARKERS[1:])
                        and markers_ok(cli.stderr, (BANNER,), FI_MARKERS[1:])}
    cases['fi_controls'] = {'runs': ctl, 'ok': all(
        v['server_exit'] == 0 and v['client_exit'] == 0 and v['only_banner'] for v in ctl.values())}

    # race_server_campaign: production probe, ping at a seeded offset.
    budget_s = CAMPAIGN_BUDGET_MS / 1000
    runs = []
    for offset in campaign_offsets():
        proc, t_ready = _start_server(wp, prod_probe, CAMPAIGN_BUDGET_MS, spawned)
        box = {}
        cl = threading.Thread(target=_raw_client, args=(wp, t_ready, offset, box), daemon=True)
        cl.start()
        code, elapsed, err = _finish(proc, t_ready)
        cl.join(TIMEOUT_S)
        received = box.get('received', b'')
        runs.append({'offset_s': offset, 'exit': code, 'elapsed_s': elapsed,
                     'received': received.decode('latin-1'),
                     'ok': server_run_ok(offset, budget_s, code, elapsed, received)
                     and not markers_ok(err, (BANNER,))})
    cases['race_server_campaign'] = {
        'seed': CAMPAIGN_SEED, 'budget_ms': CAMPAIGN_BUDGET_MS, 'histogram': _histogram(runs),
        'failed_runs': [r for r in runs if not r['ok']],
        'ok': campaign_verdict(runs, CAMPAIGN_RUNS, (0, EXIT_TIMEOUT, EXIT_PEER_NOT_CLOSED))}

    # race_client_campaign: production client, fake server answers at a seeded offset.
    runs = []
    for offset in campaign_offsets(CAMPAIGN_SEED + 1, bounds=CLIENT_OFFSETS_S):
        srv = _AnsweringServer(wp)
        box = {}
        try:
            t0 = time.monotonic()
            th = threading.Thread(target=srv.serve, args=(t0, offset, box), daemon=True)
            th.start()
            cli = _start(prod_client, ['--budget-ms', str(CAMPAIGN_BUDGET_MS)], spawned)
            code, elapsed, err = _finish(cli, t0)
            th.join(TIMEOUT_S)
        finally:
            srv.close()
        runs.append({'offset_s': offset, 'exit': code, 'elapsed_s': elapsed,
                     'ok': client_run_ok(offset, budget_s, code, elapsed) and box.get('got_ping') is True
                     and not markers_ok(err, (BANNER,))})
    cases['race_client_campaign'] = {
        'seed': CAMPAIGN_SEED + 1, 'budget_ms': CAMPAIGN_BUDGET_MS, 'histogram': _histogram(runs),
        'failed_runs': [r for r in runs if not r['ok']],
        'ok': campaign_verdict(runs, CAMPAIGN_RUNS, (0, EXIT_TIMEOUT))}


def _histogram(runs) -> dict:
    out = {}
    for r in runs:
        key = str(r.get('exit'))
        out[key] = out.get(key, 0) + 1
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--repo', type=pathlib.Path, default=REPO)
    p.add_argument('--output', type=pathlib.Path)
    args = p.parse_args(argv)
    report = {'schema_version': 1, 'tool': 'W30_CPP_CANCEL_RACE', 'research_only': True,
              'release_authorized': False}
    if sys.platform != 'win32':
        report['verdict'] = 'NATIVE_WINDOWS_REQUIRED'
        code = 2
    else:
        repo = args.repo.resolve()
        sys.path.insert(0, str(repo))
        with tempfile.TemporaryDirectory(prefix='udx_w30_') as tmp:
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
                report['verdict'] = 'CANCEL_RACE_OK' if ok else 'CANCEL_RACE_FAILED'
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
