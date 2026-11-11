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
// W25: a failed open prints "UDX_CLIENT_OPEN_ERROR <win32 error>" to stderr.
// Exit: 0 PEER_OK, 1 open failed (or pipe absent/busy until the deadline),
// 2 write failed, 3 bad/short response, 4 owner query failed, 5 owner mismatch,
// 6 own SID, 7 pipe has no single explicit mandatory label >= Medium (W25.2;
// the label must not be INHERIT_ONLY and must carry NO_WRITE_UP) or the label
// is not EXACTLY this process' own integrity level (UT6-02), 8 own integrity
// level unreadable (UT6-02), 22 deadline passed, 24 bad arguments, 31 cancelled I/O did not settle.
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

// UT6-02 (UNCOMPILED here; CI cpp-candidate job): integrity RID of this
// process' token. The client never impersonates, so the process token is the
// one CreateFileW uses (the Python port reads the thread token if present).
static bool own_integrity_rid(DWORD& rid) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD required = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &required);
    bool ok = required != 0 && required <= 65536;
    std::vector<BYTE> buf;
    if (ok) {
        buf.resize(required);
        ok = GetTokenInformation(token, TokenIntegrityLevel, buf.data(), required, &required) != 0;
    }
    CloseHandle(token);
    if (!ok) return false;
    PSID sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data())->Label.Sid;
    if (sid == nullptr || !IsValidSid(sid) || *GetSidSubAuthorityCount(sid) == 0) return false;
    rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1u);
    return true;
}

int wmain(int argc, wchar_t** argv) {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
    DWORD budget_ms = 0;
    if (!udx::parse_budget(argc, argv, budget_ms)) return udx::kExitBadArguments;
    const udx::Deadline deadline(budget_ms);
    std::vector<BYTE> self_buf;
    PSID self_sid = nullptr;
    if (!own_user_sid(self_buf, self_sid)) return 6;
    // UT6-02: own level read BEFORE the open; unreadable -> exit 8, nothing opened.
    DWORD self_rid = 0;
    if (!own_integrity_rid(self_rid)) return 8;
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
        if ((err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) || deadline.expired()) {
            // W25: the Win32 reason of a failed open, so a harness can tell
            // ERROR_ACCESS_DENIED (DACL / mandatory label) from an absent pipe.
            // One line on stderr only; the exit code contract is unchanged.
            fwprintf(stderr, L"UDX_CLIENT_OPEN_ERROR %lu\n", err);
            return 1;
        }
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
    // W25.2: exactly one explicit mandatory label of at least Medium on the pipe,
    // also BEFORE any byte is sent. ADR-UDX-006: only same SID AND same integrity
    // level is one trust domain; a Low-IL process of the same user can own a pipe
    // with this user's SID, but cannot label an object above its own level.
    PACL sacl = nullptr;
    PSECURITY_DESCRIPTOR lsd = nullptr;
    if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION,
                        nullptr, nullptr, nullptr, &sacl, &lsd) != ERROR_SUCCESS) {
        fwprintf(stderr, L"UDX_CLIENT_PIPE_LABEL query_failed\n");
        CloseHandle(pipe); return 7;
    }
    // Aegis W25.2 hardening: the label must also be EFFECTIVE on the pipe object
    // (no INHERIT_ONLY_ACE flag: such an ACE only seeds children) and enforce
    // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP; otherwise it does not count as Medium.
    unsigned labels = 0;
    DWORD label_rid = 0, label_mask = 0;
    BYTE label_flags = 0;
    for (DWORD i = 0; sacl != nullptr && i < sacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(sacl, i, &ace)) { labels = 0xFFFF; break; }
        if (static_cast<ACE_HEADER*>(ace)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
        PSID label = &static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(ace)->SidStart;
        ++labels;
        label_flags = static_cast<ACE_HEADER*>(ace)->AceFlags;
        label_mask = static_cast<SYSTEM_MANDATORY_LABEL_ACE*>(ace)->Mask;
        if (IsValidSid(label) && *GetSidSubAuthorityCount(label) > 0)
            label_rid = *GetSidSubAuthority(label, *GetSidSubAuthorityCount(label) - 1u);
    }
    LocalFree(lsd);
    const bool label_effective = (label_flags & INHERIT_ONLY_ACE) == 0
        && (label_mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0;
    // UT6-02: and EXACTLY this process' own level (mirror of the server's
    // rid == server_rid): a Medium client never writes to an elevated server's
    // pipe, an elevated client never to a Medium one.
    if (labels != 1 || label_rid < SECURITY_MANDATORY_MEDIUM_RID || !label_effective || label_rid != self_rid) {
        fwprintf(stderr, L"UDX_CLIENT_PIPE_LABEL count=%u rid=%lu flags=%u mask=%lu own=%lu\n",
                 labels, label_rid, static_cast<unsigned>(label_flags), label_mask, self_rid);
        CloseHandle(pipe); return 7;
    }
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
