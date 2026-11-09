// UDX W4 - research-only Windows security transport probe (NOT a UDX broker).
// No filesystem/process actions. Build and test under real Windows with MSVC.
// Implements: first-instance pipe, explicit SID-scoped DACL, remote rejection,
// last-message client impersonation, token SID compare, revert-before-response.
// W24: every pipe operation is OVERLAPPED under ONE absolute deadline for the
// whole exchange (udx_bounded_pipe_io.hpp); FlushFileBuffers (unbounded: it
// waits for the client to read) is replaced by a bounded wait for peer close.
// Usage: udx_sid_probe.exe [--budget-ms N]   (100..300000, default 10000)
// Exit: 0 PEER_OK delivered and peer closed, 20 denied, 21 name occupied,
// 22 deadline passed before PEER_OK was written, 23 PEER_OK written but the
// peer did not close in time, 24 bad arguments, 30 RevertToSelf failed,
// 31 cancelled I/O did not settle, 10-15 setup failures.
// W25: a denial (exit 20) prints one stderr line "UDX_PROBE_DENIED level=.. rid=..
// appc=.. restricted=.. session_ok=.. sid_ok=.." (or "facts=unavailable").
// TODO before use beyond lab: bounded connections, full UDX envelope parser,
// versioned ACK/durable receipts, OS app identity (G2-App), independent review.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include "udx_bounded_pipe_io.hpp"
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

static bool query_sid(HANDLE token, std::vector<BYTE>& storage, PSID& sid) {
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    if (required == 0 || required > 65536) return false;
    storage.resize(required);
    if (!GetTokenInformation(token, TokenUser, storage.data(), required, &required)) return false;
    sid = reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
    return sid != nullptr && IsValidSid(sid);
}

static bool token_dword(HANDLE token, TOKEN_INFORMATION_CLASS klass, DWORD& value) {
    DWORD got = 0;
    return GetTokenInformation(token, klass, &value, sizeof(value), &got) != 0 && got == sizeof(value);
}

static bool integrity_rid(HANDLE token, DWORD& rid) {
    DWORD required = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &required);
    if (required == 0 || required > 65536) return false;
    std::vector<BYTE> buf(required);
    if (!GetTokenInformation(token, TokenIntegrityLevel, buf.data(), required, &required)) return false;
    PSID sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data())->Label.Sid;
    if (sid == nullptr || !IsValidSid(sid) || *GetSidSubAuthorityCount(sid) == 0) return false;
    rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    return true;
}

// W20 (parity with udx_ref/windows_pipe.py W19 PipeNameOccupied): true only if
// the pipe namespace lists exactly `base`. FindFirstFileW enumerates the
// named-pipe file system directory without opening (and without consuming) the
// instance; the API's wildcard match is not trusted, every entry is compared.
static bool pipe_name_present(const wchar_t* full, const wchar_t* base) {
    WIN32_FIND_DATAW data = {};
    HANDLE h = FindFirstFileW(full, &data);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    for (unsigned i = 0; i < 65536; ++i) {
        if (_wcsicmp(data.cFileName, base) == 0) { found = true; break; }
        if (!FindNextFileW(h, &data)) break;
    }
    FindClose(h);
    return found;
}

int wmain(int argc, wchar_t** argv) {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
    DWORD budget_ms = 0;
    if (!udx::parse_budget(argc, argv, budget_ms)) return udx::kExitBadArguments;
    HANDLE server_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &server_token)) return 10;
    std::vector<BYTE> server_sidbuf;
    PSID server_sid = nullptr;
    bool ok = query_sid(server_token, server_sidbuf, server_sid);
    DWORD server_session = 0;
    ok = ok && token_dword(server_token, TokenSessionId, server_session);
    CloseHandle(server_token);
    if (!ok) return 11;

    LPWSTR sid_text = nullptr;
    if (!ConvertSidToStringSidW(server_sid, &sid_text)) return 12;
    // Protected DACL: LocalSystem and the exact current user SID. No Everyone.
    // W14 (UNCOMPILED): user/SYSTEM ACEs GRGW instead of GA; GRGW is NOT
    // client-least-privilege: FILE_APPEND_DATA = FILE_CREATE_PIPE_INSTANCE (0x4).
    // The 1-instance FIRST_PIPE_INSTANCE design limits live additional instances,
    // but NOT same-SID squatting before server startup. Medium label NW|NR,
    // so a Low-IL process cannot even open the single instance for reading.
    // W17 (UNCOMPILED, issue #2): explicit owner = current user. Without O: an
    // elevated administrator's pipe is owned by BUILTIN\Administrators and the
    // client's owner check refuses it.
    std::wstring sddl = L"O:";
    sddl += sid_text;
    // W18: every ACE grants 0x12008b = FILE_GENERIC_READ | FILE_WRITE_DATA
    // instead of GRGW (0x12019f): no FILE_APPEND_DATA == FILE_CREATE_PIPE_INSTANCE
    // (0x4), so no ACE lets anyone create a further instance of this pipe.
    // Creating the first instance is not checked against this DACL.
    sddl += L"D:P(A;;0x12008b;;;SY)(A;;0x12008b;;;";
    sddl += sid_text;
    // W17: OWNER RIGHTS ACE; the owner gets the ACE mask only, no implicit WRITE_DAC.
    sddl += L")(A;;0x12008b;;;OW)S:(ML;;NWNR;;;ME)";
    LocalFree(sid_text);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return 13;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
    HANDLE pipe = CreateNamedPipeW(name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 0, &sa);
    const DWORD create_error = GetLastError();      // before LocalFree can overwrite it
    LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) {
        // W20: 21 = PIPE_NAME_OCCUPIED (same exit code as the Python CLI), only
        // if the name is really listed; every other failure stays 14.
        if ((create_error == ERROR_ACCESS_DENIED || create_error == ERROR_PIPE_BUSY)
            && pipe_name_present(name, L"UDX_W4_SID_PROBE")) return 21;
        return 14;
    }
    // W24: the budget covers connect, request, reply and peer close together.
    const udx::Deadline deadline(budget_ms);
    const udx::IoResult conn = udx::bounded_io(pipe, deadline,
        [&](OVERLAPPED* ov) { return ConnectNamedPipe(pipe, ov); });
    if (conn.status == udx::IoStatus::timeout) {CloseHandle(pipe);return udx::kExitTimeout;}
    if (conn.status != udx::IoStatus::ok) {CloseHandle(pipe);return 15;}

    // ImpersonateNamedPipeClient is based on the LAST message read from client.
    BYTE ping = 0;
    const udx::IoResult req = udx::bounded_io(pipe, deadline,
        [&](OVERLAPPED* ov) { return ReadFile(pipe, &ping, 1, nullptr, ov); });
    if (req.status == udx::IoStatus::timeout) {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return udx::kExitTimeout;
    }
    const bool read_ok = req.status == udx::IoStatus::ok && req.bytes == 1;
    bool authorized = false;
    // W25: the token facts outlive the impersonation block so a denial can name
    // the failing check on stderr (exit code 20 itself stays unspecific).
    bool facts_ok = false, sid_ok = false;
    DWORD level = 0, appc = 1, restricted = 1, session = 0xFFFFFFFF, rid = 0;
    if (read_ok && ImpersonateNamedPipeClient(pipe)) {
        HANDLE client_token = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &client_token)) {
            std::vector<BYTE> client_sidbuf;
            PSID client_sid = nullptr;
            // W13 (UNCOMPILED): client grants Identification only; every fact
            // comes from the token, never from the client PID/session API.
            if (query_sid(client_token, client_sidbuf, client_sid)
                && token_dword(client_token, TokenImpersonationLevel, level)
                && token_dword(client_token, TokenIsAppContainer, appc)
                && token_dword(client_token, TokenIsRestricted, restricted)
                && token_dword(client_token, TokenSessionId, session)
                && integrity_rid(client_token, rid)) {
                facts_ok = true;
                sid_ok = EqualSid(client_sid, server_sid) != 0;
                authorized = level >= SecurityIdentification
                    && rid >= SECURITY_MANDATORY_MEDIUM_RID
                    && appc == 0 && restricted == 0 && session == server_session
                    && sid_ok;
            }
            CloseHandle(client_token);
        }
        // If the server cannot revert, fail fatally; never continue as a client.
        if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), 30);
    }
    if (!authorized) {
        // W25: one line on stderr with the facts the decision used; no SID text.
        if (facts_ok)
            fwprintf(stderr, L"UDX_PROBE_DENIED level=%lu rid=%lu appc=%lu restricted=%lu session_ok=%d sid_ok=%d\n",
                     level, rid, appc, restricted, session == server_session ? 1 : 0, sid_ok ? 1 : 0);
        else
            fwprintf(stderr, L"UDX_PROBE_DENIED facts=unavailable\n");
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return 20;
    }
    // Strict like the Python lane (DEADLINE_EXCEEDED): no response after the deadline.
    if (deadline.expired()) {DisconnectNamedPipe(pipe);CloseHandle(pipe);return udx::kExitTimeout;}
    // The only observable operation is a fixed handshake, no OS action.
    static constexpr char response[] = "PEER_OK";
    const udx::IoResult rep = udx::bounded_io(pipe, deadline,
        [&](OVERLAPPED* ov) { return WriteFile(pipe, response, sizeof(response)-1, nullptr, ov); });
    if (rep.status == udx::IoStatus::timeout) {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return udx::kExitTimeout;
    }
    if (rep.status != udx::IoStatus::ok || rep.bytes != sizeof(response)-1) {
        DisconnectNamedPipe(pipe); CloseHandle(pipe); return 20;
    }
    // Bounded replacement for FlushFileBuffers: wait until the client closes
    // (EOF), so DisconnectNamedPipe does not discard the unread response. This
    // shows the peer CLOSED, not that it processed PEER_OK (no ACK protocol).
    BYTE sink = 0;
    const udx::IoResult drain = udx::bounded_io(pipe, deadline,
        [&](OVERLAPPED* ov) { return ReadFile(pipe, &sink, 1, nullptr, ov); });
    const bool peer_closed = drain.status == udx::IoStatus::failure
        && (drain.error == ERROR_BROKEN_PIPE || drain.error == ERROR_NO_DATA);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return peer_closed ? 0 : udx::kExitPeerNotClosed;
}
