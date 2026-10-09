// Windows local transport probe client. Sends a byte so server can impersonate
// based on the received message. This is NOT the UDX/0.1 data protocol.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
int wmain() {
    constexpr wchar_t name[] = LR"(\\.\pipe\UDX_W4_SID_PROBE)";
    HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 1;
    BYTE ping = 0x55; DWORD sent = 0;
    if (!WriteFile(pipe, &ping, 1, &sent, nullptr) || sent != 1) { CloseHandle(pipe); return 2; }
    char response[8] = {}; DWORD got = 0;
    const bool ok = ReadFile(pipe, response, 7, &got, nullptr) != 0
        && got == 7 && memcmp(response, "PEER_OK", 7) == 0;
    CloseHandle(pipe);
    return ok ? 0 : 3;
}
