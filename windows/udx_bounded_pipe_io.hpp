// UDX W24 - bounded overlapped named-pipe I/O for the research C++ candidates.
// RESEARCH ONLY. Shared by udx_sid_probe.cpp (server) and udx_sid_client.cpp.
//
// Closes UDX14-04 / UDX-W21-01 / UDX22-01 at the source level: every pipe
// operation (connect, read, write, peer-close drain) runs as an OVERLAPPED
// operation under ONE absolute monotonic deadline for the whole exchange
// (W23 PR-1: fresh per-call timeouts would let the total exceed the budget).
//
// Rules this file implements (Microsoft Learn, checked 2026-11-04):
//  * GetOverlappedResultEx(dwMilliseconds > 0) fails with WAIT_TIMEOUT when the
//    interval elapses, with ERROR_IO_INCOMPLETE when dwMilliseconds == 0 and the
//    I/O is still pending. Both mean "still pending", not "pipe failed".
//  * CancelIoEx only REQUESTS cancellation and does not wait. The OVERLAPPED and
//    the buffer must not be released until the I/O has completed; the cancelled
//    I/O may still complete successfully (race), which is NOT turned into a
//    success here: the deadline had passed, the outcome is a timeout.
//  * If completion cannot be confirmed within kCancelGraceMs, the kernel may
//    still write into this stack frame. The one-shot research process then
//    terminates itself with exit 31 instead of returning (fail-closed).
//  * GetTickCount64 is monotonic (not affected by wall-clock changes).
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cwchar>

namespace udx {

constexpr DWORD kDefaultBudgetMs = 10000;   // whole exchange, not per call
constexpr DWORD kMinBudgetMs = 100;
constexpr DWORD kMaxBudgetMs = 300000;      // same cap as the Python lane (MAX_DEADLINE_S)
constexpr DWORD kCancelGraceMs = 1000;      // same as udx_ref.windows_pipe.CANCEL_GRACE_MS

// Exit codes shared by server and client (W24 contract, see windows/README.md).
constexpr int kExitTimeout = 22;            // the absolute deadline passed; I/O cancelled and settled
constexpr int kExitPeerNotClosed = 23;      // server: PEER_OK written, peer did not close in time
constexpr int kExitBadArguments = 24;       // command line rejected (fail-closed parser)
constexpr int kExitCancelUncertain = 31;    // cancelled I/O did not settle: process killed itself

class Deadline {
public:
    explicit Deadline(DWORD budget_ms) : end_(GetTickCount64() + budget_ms) {}
    bool expired() const { return GetTickCount64() >= end_; }
    DWORD remaining_ms() const {
        const ULONGLONG now = GetTickCount64();
        return now >= end_ ? 0 : static_cast<DWORD>(end_ - now);
    }
private:
    ULONGLONG end_;
};

enum class IoStatus { ok, timeout, failure };

struct IoResult {
    IoStatus status;
    DWORD bytes;
    DWORD error;    // Win32 error of a failed I/O; 0 for ok/timeout unless the cancel settled with one
};

[[noreturn]] inline void die_cancel_uncertain() {
    // Never return into a frame whose OVERLAPPED/buffer the kernel may still own.
    TerminateProcess(GetCurrentProcess(), kExitCancelUncertain);
    ExitProcess(kExitCancelUncertain);      // only if TerminateProcess itself failed
}

// Accepts no arguments (default budget) or exactly `--budget-ms N` with
// N decimal, 1..6 digits, kMinBudgetMs <= N <= kMaxBudgetMs. Anything else: false.
inline bool parse_budget(int argc, wchar_t** argv, DWORD& budget_ms) {
    budget_ms = kDefaultBudgetMs;
    if (argc == 1) return true;
    if (argc != 3 || argv == nullptr || argv[1] == nullptr || argv[2] == nullptr) return false;
    if (wcscmp(argv[1], L"--budget-ms") != 0) return false;
    const wchar_t* digits = argv[2];
    const size_t len = wcslen(digits);
    if (len == 0 || len > 6) return false;
    DWORD value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (digits[i] < L'0' || digits[i] > L'9') return false;
        value = value * 10 + static_cast<DWORD>(digits[i] - L'0');
    }
    if (value < kMinBudgetMs || value > kMaxBudgetMs) return false;
    budget_ms = value;
    return true;
}

// Deadline passed (or the wait failed) while the I/O may still be pending:
// request cancellation, then wait a BOUNDED grace for the completion.
inline IoResult cancel_and_settle(HANDLE handle, OVERLAPPED& ov) {
    CancelIoEx(handle, &ov);                // request only; ERROR_NOT_FOUND = already completing
    DWORD n = 0;
    if (GetOverlappedResultEx(handle, &ov, &n, kCancelGraceMs, FALSE))
        return {IoStatus::timeout, n, ERROR_SUCCESS};   // completed in the race: still a timeout
    const DWORD err = GetLastError();
    if (err == WAIT_TIMEOUT || err == ERROR_IO_INCOMPLETE || !HasOverlappedIoCompleted(&ov))
        die_cancel_uncertain();
    return {IoStatus::timeout, n, err};     // settled, normally ERROR_OPERATION_ABORTED
}

inline IoResult await_completion(HANDLE handle, const Deadline& deadline, OVERLAPPED& ov) {
    DWORD n = 0;
    for (;;) {
        if (GetOverlappedResultEx(handle, &ov, &n, deadline.remaining_ms(), FALSE))
            return {IoStatus::ok, n, ERROR_SUCCESS};
        const DWORD err = GetLastError();
        if (err != WAIT_TIMEOUT && err != ERROR_IO_INCOMPLETE) {
            // A completed I/O reports its own error here. An unexpected wait
            // failure with the I/O still pending must not release `ov`.
            if (HasOverlappedIoCompleted(&ov)) return {IoStatus::failure, n, err};
            return cancel_and_settle(handle, ov);
        }
        // The wait may return a few ms before the tick deadline (timer
        // granularity); only a really expired deadline ends the wait.
        if (deadline.expired()) return cancel_and_settle(handle, ov);
    }
}

// Runs ONE overlapped operation. `start(OVERLAPPED*)` issues it and returns the
// API's BOOL (ConnectNamedPipe / ReadFile / WriteFile with a null byte-count
// pointer, as recommended for overlapped handles). Buffers passed to `start`
// must outlive this call; they do, because it never returns while the I/O is
// pending (completion, settled cancellation, or process exit).
template <class Start>
IoResult bounded_io(HANDLE handle, const Deadline& deadline, Start start) {
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);   // manual-reset, per operation
    if (ov.hEvent == nullptr) return {IoStatus::failure, 0, GetLastError()};
    const BOOL started = start(&ov);
    const DWORD start_error = started ? ERROR_SUCCESS : GetLastError();
    IoResult result = {IoStatus::failure, 0, start_error};
    if (!started && start_error == ERROR_PIPE_CONNECTED) {
        result = {IoStatus::ok, 0, ERROR_SUCCESS};             // client connected before ConnectNamedPipe
    } else if (started || start_error == ERROR_IO_PENDING) {
        result = await_completion(handle, deadline, ov);       // also collects a synchronous completion
    }
    CloseHandle(ov.hEvent);
    return result;
}

}  // namespace udx
