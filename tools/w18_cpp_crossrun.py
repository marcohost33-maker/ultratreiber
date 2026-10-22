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

Exit 0 only if everything above holds. The JSON report records the compiler
banner and the SHA-256 of both binaries. It is NOT evidence for the open C++
gaps (blocking I/O without deadlines, no CancelIoEx), not a release approval and
not a standard-user result on the hosted runner (elevated Administrator).
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {'probe': 'windows/udx_sid_probe.cpp', 'client': 'windows/udx_sid_client.cpp'}
CL_FLAGS = '/nologo /W4 /WX /EHsc /std:c++17'
TIMEOUT_S = 20.0


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


def run_cases(out: pathlib.Path) -> dict:
    from udx_ref import windows_pipe as wp
    probe, client = str(out / 'udx_sid_probe.exe'), str(out / 'udx_sid_client.exe')
    cases = {}

    def cpp_server():
        proc = subprocess.Popen([probe], stdin=subprocess.DEVNULL)
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
    return cases


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
                report['cases'] = run_cases(out)
                ok = all(c['ok'] for c in report['cases'].values())
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
