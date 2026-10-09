// UDX W4 - research-only Windows security transport probe (NOT a UDX broker).
// No filesystem/process actions. Build and test under real Windows with MSVC.
// Implements: first-instance pipe, explicit SID-scoped DACL, remote rejection,
// last-message client impersonation, token SID compare, revert-before-response.
// TODO before use beyond lab: overlapped I/O deadlines, bounded connections,
// full UDX envelope parser, status receipts, independent Windows OS tests.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
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

int wmain() {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
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
    std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;";
    sddl += sid_text;
    sddl += L")";
    LocalFree(sid_text);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return 13;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
    HANDLE pipe = CreateNamedPipeW(name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 0, &sa);
    LocalFree(sd);
    if (pipe == INVALID_HANDLE_VALUE) return 14;
    bool connected = ConnectNamedPipe(pipe, nullptr) != 0;
    if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) connected = true;
    if (!connected) {CloseHandle(pipe);return 15;}

    // ImpersonateNamedPipeClient is based on the LAST message read from client.
    BYTE ping = 0;
    DWORD count = 0;
    bool read_ok = ReadFile(pipe, &ping, 1, &count, nullptr) != 0 && count == 1;
    bool authorized = false;
    if (read_ok && ImpersonateNamedPipeClient(pipe)) {
        HANDLE client_token = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &client_token)) {
            std::vector<BYTE> client_sidbuf;
            PSID client_sid = nullptr;
            // W13 (UNCOMPILED): client grants Identification only; every fact
            // comes from the token, never from the client PID/session API.
            DWORD level = 0, appc = 1, restricted = 1, session = 0xFFFFFFFF, rid = 0;
            if (query_sid(client_token, client_sidbuf, client_sid)
                && token_dword(client_token, TokenImpersonationLevel, level)
                && token_dword(client_token, TokenIsAppContainer, appc)
                && token_dword(client_token, TokenIsRestricted, restricted)
                && token_dword(client_token, TokenSessionId, session)
                && integrity_rid(client_token, rid)) {
                authorized = level >= SecurityIdentification
                    && rid >= SECURITY_MANDATORY_MEDIUM_RID
                    && appc == 0 && restricted == 0 && session == server_session
                    && (EqualSid(client_sid, server_sid) != 0);
            }
            CloseHandle(client_token);
        }
        // If the server cannot revert, fail fatally; never continue as a client.
        if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), 30);
    }
    if (authorized) {
        // The only observable operation is a fixed handshake, no OS action.
        constexpr char response[] = "PEER_OK";
        DWORD written = 0;
        if (!WriteFile(pipe, response, sizeof(response)-1, &written, nullptr) || written != sizeof(response)-1)
            authorized = false;
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return authorized ? 0 : 20;
}
