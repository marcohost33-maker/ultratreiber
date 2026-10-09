// Windows local transport probe client. Sends a byte so server can identify
// the client from the received message. This is NOT the UDX/0.1 data protocol.
// W13 (Aegis P1-a, UNCOMPILED - no compiler on the W12/W13 host):
//  * SQOS = Identification + EFFECTIVE_ONLY, static tracking. The client never
//    grants Impersonation, so a squatting server only learns who we are.
//  * BEFORE the first write the owner of the pipe object must equal this
//    process' user SID. The server PID is NOT used for this decision
//    (Forshaw 2019: the PID should not be relied upon for security decisions).
//  * The Python port (udx_ref/windows_pipe.py) adds absolute I/O deadlines;
//    this source still uses blocking calls.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <cstdio>
#include <cstring>
#include <vector>

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

int wmain() {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
    std::vector<BYTE> self_buf;
    PSID self_sid = nullptr;
    if (!own_user_sid(self_buf, self_sid)) return 6;
    HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 1;
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
    BYTE ping = 0x55; DWORD sent = 0;
    if (!WriteFile(pipe, &ping, 1, &sent, nullptr) || sent != 1) { CloseHandle(pipe); return 2; }
    char response[8] = {}; DWORD got = 0;
    const bool ok = ReadFile(pipe, response, 7, &got, nullptr) != 0
        && got == 7 && memcmp(response, "PEER_OK", 7) == 0;
    CloseHandle(pipe);
    return ok ? 0 : 3;
}
