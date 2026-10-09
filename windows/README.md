# Windows W4 security handshake candidate — uncompiled

This directory contains two Win32 C++ **research-only source candidates**, not a UDX broker:

- `udx_sid_probe.cpp`: one-shot Named-Pipe server; DACL only `SY` plus exact current user SID; `FILE_FLAG_FIRST_PIPE_INSTANCE`; `PIPE_REJECT_REMOTE_CLIENTS`; reads one byte before `ImpersonateNamedPipeClient`; opens thread token and requires SID match; `RevertToSelf` before a fixed `PEER_OK` response; no device capabilities or host actions.
- `udx_sid_client.cpp`: connects with `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, sends a byte and checks the response.

Candidate build on **real Windows** (Visual Studio Developer Command Prompt):

```
cl /nologo /W4 /EHsc /std:c++17 windows\udx_sid_probe.cpp /link advapi32.lib
cl /nologo /W4 /EHsc /std:c++17 windows\udx_sid_client.cpp
```

Run the server and client as the same ordinary interactive account; then repeat from a second ordinary Windows user. **No Windows compilation or runtime tests were performed in this delivery environment.** Do not use these sources elevated or in production.

**Open blockers for Windows G2:** full request/response protocol; async I/O with absolute header/body/send deadlines and connection budget (these sources use blocking Win32 APIs); actual SID-bound token tests; remote SMB negative test, alternate account denial, integrity-level/UAC interactions, failure-to-impersonate injection, native errors, signed distribution, Windows versions. Same user SID is not same application identity. The DACL only restricts who can connect; authorization to a specific operation must be checked separately.

Microsoft documents the relevant guarantees:
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew
- https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client

Important: server calls `ImpersonateNamedPipeClient` after reading client input because token context reflects the last message read. If impersonation fails it sends no positive response. `RevertToSelf` failure causes process termination.
