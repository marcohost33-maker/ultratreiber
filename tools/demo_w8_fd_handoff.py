"""Real Linux inter-process SCM_RIGHTS demo on trusted *fixture* data.
No graphical consent claims; no general OS-path/IPC exposure.

W27 (UDX14-06): the parent separates three phases, each with its own typed
outcome, instead of charging everything to the 2 s protocol timeout:

* startup  - the child interpreter starts and signals readiness with one byte
             on a private pipe. Budget: ``STARTUP_BUDGET_S`` (a liveness bound
             for process creation; no security property depends on it).
* protocol - descriptor handoff and status reply. Budget: the unchanged 2 s
             socket timeout of ``udx_ref.fd_handoff.private_pair``.
* teardown - the child exits. Budget: ``EXIT_BUDGET_S``.

Measured cause of the flake (``evidence/W27_FD_HANDOFF_LOAD.json``): the old
parent sent the descriptor right after ``Popen`` and waited 2 s for the status,
so the start-up time of the child interpreter was charged to the protocol
timeout. Start-up time grows linearly with CPU oversubscription.

Second finding of W27: ``settimeout`` on the parent's socket sets O_NONBLOCK on
the open file description, which the child shares. ``socket.socket(fileno=fd)``
in the child reports a blocking socket, yet a receive on an empty queue raises
``BlockingIOError`` at once. The old child therefore only worked because the
message was always queued before it looked. The child now sets its own timeout.

``--child-start-delay``, ``--parent-send-delay`` and ``--child-fault`` are fault
injection for ``tests/test_w27_fd_handoff_startup.py``; they only ever make one
side slower or less cooperative.
"""
import argparse, json, math, os, select, socket, subprocess, sys, tempfile, time, uuid
from pathlib import Path
from udx_ref.fd_handoff import private_pair, send_approved_fd, recv_status, handle_once, HandoffError

PROTOCOL_TIMEOUT_S = 2.0          # same value as udx_ref.fd_handoff.private_pair
STARTUP_BUDGET_S = 60.0
EXIT_BUDGET_S = 60.0
MAX_INJECTED_DELAY_S = 30.0
READY = b'R'
FAULTS = ('none', 'exit_before_ready', 'ready_then_silent')

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CHILD_NOT_READY = 3
EXIT_CHILD_EXITED_BEFORE_READY = 4
EXIT_PROTOCOL = 5
EXIT_CHILD_FAILED = 6


class DemoFailure(Exception):
    def __init__(self, code, reason, phase):
        super().__init__(reason)
        self.code, self.reason, self.phase = code, reason, phase


def _child(argv):
    fd, ready_fd, delay, fault = int(argv[0]), int(argv[1]), float(argv[2]), argv[3]
    if fault not in FAULTS or not 0.0 <= delay <= MAX_INJECTED_DELAY_S:
        return EXIT_USAGE
    time.sleep(delay)
    if fault == 'exit_before_ready':
        return 9
    s = socket.socket(fileno=fd)
    try:
        s.settimeout(PROTOCOL_TIMEOUT_S)
        os.write(ready_fd, READY)
        os.close(ready_fd)
        if fault == 'ready_then_silent':
            time.sleep(MAX_INJECTED_DELAY_S)
            return 9
        handle_once(s, expected_uid=os.getuid(), owner_uid=os.getuid())
    finally:
        s.close()
    return EXIT_OK


def wait_ready(ready_fd, budget_s):
    """One READY byte within ``budget_s``; EOF and timeout are distinct, typed failures."""
    deadline = time.monotonic() + budget_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DemoFailure(EXIT_CHILD_NOT_READY, 'CHILD_NOT_READY', 'startup')
        readable, _, _ = select.select([ready_fd], [], [], remaining)
        if not readable:
            continue
        data = os.read(ready_fd, 1)
        if data == READY:
            return
        if data == b'':
            raise DemoFailure(EXIT_CHILD_EXITED_BEFORE_READY, 'CHILD_EXITED_BEFORE_READY', 'startup')
        raise DemoFailure(EXIT_CHILD_EXITED_BEFORE_READY, 'BAD_READY_BYTE', 'startup')


def _reap(proc, budget_s):
    """Kill if still running; True only if the child is gone afterwards."""
    if proc.poll() is None:
        proc.kill()
    try:
        proc.communicate(timeout=budget_s)
    except subprocess.TimeoutExpired:
        return False
    return True


def run(child_start_delay=0.0, startup_budget=STARTUP_BUDGET_S, child_fault='none', lifecycle=False,
        parent_send_delay=0.0):
    phases = {}
    proc = None
    with tempfile.TemporaryDirectory(prefix='udx-w8-fixture-') as d:
        p = Path(d) / 'fixture.bin'
        p.write_bytes(b'UDX-W8-in-process-and-interprocess-safety-fixture')
        left, right = private_pair()
        ready_r, ready_w = os.pipe()
        try:
            t0 = time.monotonic()
            try:
                proc = subprocess.Popen(
                    [sys.executable, __file__, 'child', str(right.fileno()), str(ready_w),
                     repr(float(child_start_delay)), child_fault],
                    pass_fds=(right.fileno(), ready_w),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            finally:
                right.close()
                os.close(ready_w)
                ready_w = None
            wait_ready(ready_r, startup_budget)
            t1 = time.monotonic()
            phases['startup_ms'] = round((t1 - t0) * 1000, 3)
            time.sleep(parent_send_delay)
            request_id = str(uuid.uuid4())
            data_fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                try:
                    send_approved_fd(left, data_fd, request_id)
                finally:
                    os.close(data_fd)
                ans = recv_status(left, request_id)
            except TimeoutError:
                raise DemoFailure(EXIT_PROTOCOL, 'PROTOCOL_TIMEOUT', 'protocol') from None
            except (HandoffError, OSError) as exc:
                raise DemoFailure(EXIT_PROTOCOL, f'PROTOCOL_{type(exc).__name__}', 'protocol') from None
            t2 = time.monotonic()
            phases['protocol_ms'] = round((t2 - t1) * 1000, 3)
            try:
                proc.communicate(timeout=EXIT_BUDGET_S)
            except subprocess.TimeoutExpired:
                raise DemoFailure(EXIT_CHILD_FAILED, 'CHILD_EXIT_TIMEOUT', 'teardown') from None
            phases['teardown_ms'] = round((time.monotonic() - t2) * 1000, 3)
            if proc.returncode != 0:
                raise DemoFailure(EXIT_CHILD_FAILED, f'CHILD_RETURN_{proc.returncode}', 'teardown')
            out = {'result': ans, 'child_exit': proc.returncode, 'fixture_only': True}
            if lifecycle:
                out['phases_ms'] = phases
            return EXIT_OK, out
        except DemoFailure as failure:
            reaped = _reap(proc, EXIT_BUDGET_S) if proc is not None else True
            return failure.code, {'error': failure.reason, 'phase': failure.phase, 'child_reaped': reaped,
                                  'fixture_only': True, 'phases_ms': phases}
        finally:
            left.close()
            os.close(ready_r)
            if ready_w is not None:
                os.close(ready_w)
            if proc is not None and proc.poll() is None:
                _reap(proc, EXIT_BUDGET_S)


def _bounded(low, high, low_open=False):
    def parse(text):
        value = float(text)
        if not math.isfinite(value) or value > high or value < low or (low_open and value == low):
            raise argparse.ArgumentTypeError(f'out of range: {text}')
        return value
    return parse


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'child':
        return _child(argv[1:]) if len(argv) == 5 else EXIT_USAGE
    parser = argparse.ArgumentParser(description='UDX W8 fd-handoff demo (fixture data only)')
    parser.add_argument('--child-start-delay', type=_bounded(0.0, MAX_INJECTED_DELAY_S), default=0.0,
                        help='fault injection: seconds the child waits before it signals readiness')
    parser.add_argument('--parent-send-delay', type=_bounded(0.0, PROTOCOL_TIMEOUT_S / 2), default=0.0,
                        help='fault injection: seconds the parent waits after READY before it sends')
    parser.add_argument('--startup-budget', type=_bounded(0.0, 600.0, low_open=True), default=STARTUP_BUDGET_S)
    parser.add_argument('--child-fault', choices=FAULTS, default='none', help='fault injection')
    parser.add_argument('--lifecycle', action='store_true', help='report per-phase durations')
    args = parser.parse_args(argv)
    code, out = run(args.child_start_delay, args.startup_budget, args.child_fault, args.lifecycle,
                    args.parent_send_delay)
    print(json.dumps(out, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
