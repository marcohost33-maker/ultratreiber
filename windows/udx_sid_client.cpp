// Windows local transport probe client. Sends a byte so server can identify
// the client from the received message. This is NOT the UDX/0.1 data protocol.
// W13 (Aegis P1-a, UNCOMPILED - no compiler on the W12/W13 host):
//  * SQOS = Identification + EFFECTIVE_ONLY, static tracking. The client never
//    grants Impersonation, so a squatting server only learns who we are.
//  * BEFORE the first write the owner of the pipe object must equal this
//    process' user SID. The server PID is NOT used for this decision
//    (Forshaw 2019: the PID should not be relied upon for security decisions).
//  * W24 (UDX-W23 P1 CLIENT): open, write and read are bounded by ONE absolute
//    deadline (udx_bounded_pipe_io.hpp), like the Python port client_ping. A
//    silent or hanging server can no longer block this client indefinitely.
// Usage: udx_sid_client.exe [--budget-ms N]   (100..300000, default 10000)
// Exit: 0 PEER_OK, 1 open failed (or pipe absent/busy until the deadline),
// 2 write failed, 3 bad/short response, 4 owner query failed, 5 owner mismatch,
// 6 own SID, 22 deadline passed, 24 bad arguments, 31 cancelled I/O did not settle.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include "udx_bounded_pipe_io.hpp"

#pragma comment(lib, "advapi32.lib")

static bool own_user_sid(std::vector<BYTE>& storage, PSID& sid) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    bool ok = required != 0 && required <= 65536;
    if (ok) {
        storage.resize(required);
        ok = GetTokenInformation(token, TokenUser, storage.data(), required, &required) != 0;
    }
    CloseHandle(token);
    if (!ok) return false;
    sid = reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
    return sid != nullptr && IsValidSid(sid);
}

int wmain(int argc, wchar_t** argv) {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
    DWORD budget_ms = 0;
    if (!udx::parse_budget(argc, argv, budget_ms)) return udx::kExitBadArguments;
    const udx::Deadline deadline(budget_ms);
    std::vector<BYTE> self_buf;
    PSID self_sid = nullptr;
    if (!own_user_sid(self_buf, self_sid)) return 6;
    // W18: individual rights. GENERIC_WRITE maps to FILE_GENERIC_WRITE, which
    // contains FILE_APPEND_DATA == FILE_CREATE_PIPE_INSTANCE; the server's DACL
    // no longer grants that bit, so a GENERIC_WRITE open is refused.
    constexpr DWORD access = FILE_GENERIC_READ | FILE_WRITE_DATA;
    constexpr DWORD flags = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY
        | FILE_FLAG_OVERLAPPED;
    // CreateFileW on a pipe does not wait: an absent name fails with
    // ERROR_FILE_NOT_FOUND and a busy instance with ERROR_PIPE_BUSY. Retry both
    // only until the deadline (bounded open, same as client_ping).
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (;;) {
        pipe = CreateFileW(name, access, 0, nullptr, OPEN_EXISTING, flags, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        const DWORD err = GetLastError();
        if ((err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) || deadline.expired()) return 1;
        const DWORD left = deadline.remaining_ms();
        Sleep(left < 20 ? left : 20);
    }
    // Server identity BEFORE any byte is sent: owner of the pipe object.
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                        &owner, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS) {
        CloseHandle(pipe); return 4;
    }
    const bool owner_ok = owner != nullptr && IsValidSid(owner) && EqualSid(owner, self_sid);
    LocalFree(sd);
    if (!owner_ok) { CloseHandle(pipe); return 5; }
    static constexpr BYTE ping = 0x55;
    const udx::IoResult sent = udx::bounded_io(pipe, deadline,
        [&](OVERLAPPED* ov) { return WriteFile(pipe, &ping, 1, nullptr, ov); });
    if (sent.status == udx::IoStatus::timeout) { CloseHandle(pipe); return udx::kExitTimeout; }
    if (sent.status != udx::IoStatus::ok || sent.bytes != 1) { CloseHandle(pipe); return 2; }
    // A byte-mode pipe may deliver the 7 bytes in pieces: read until complete,
    // EOF/error, or the deadline.
    char response[8] = {};
    DWORD got = 0;
    while (got < 7) {
        const udx::IoResult rd = udx::bounded_io(pipe, deadline,
            [&](OVERLAPPED* ov) { return ReadFile(pipe, response + got, 7 - got, nullptr, ov); });
        if (rd.status == udx::IoStatus::timeout) { CloseHandle(pipe); return udx::kExitTimeout; }
        if (rd.status != udx::IoStatus::ok || rd.bytes == 0) break;
        got += rd.bytes;
    }
    const bool ok = got == 7 && memcmp(response, "PEER_OK", 7) == 0;
    CloseHandle(pipe);
    return ok ? 0 : 3;
}
