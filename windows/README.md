# Windows W4 security handshake candidate

> **W18 (2026-10-22): first compiled.** CI job `cpp-candidate` builds both sources with
> MSVC `cl /nologo /W4 /WX /EHsc /std:c++17` on the hosted `windows-latest` runner
> (`tools/w18_cpp_crossrun.py`) and runs the handshake C++<->C++, C++ server<->Python
> client and Python server<->C++ client. W18 also changes the ACE mask to `0x12008b`
> (no `FILE_CREATE_PIPE_INSTANCE`) and the client open to
> `FILE_GENERIC_READ | FILE_WRITE_DATA`. Still open: blocking I/O without deadlines,
> standard-user and second-account runs. The "uncompiled" notes below are history.
> W20: `udx_sid_probe.exe` exits **21** when the pipe name is already listed in the
> namespace (same code as the Python CLI's `PIPE_NAME_OCCUPIED`), else 14 on a
> `CreateNamedPipeW` failure; checked in the MSVC cross-run.

> **W13 update (2026-10-09, still UNCOMPILED — no C++ compiler on the test host).**
> Protocol inverted after the Aegis audit: the client now connects with
> `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY`
> (static tracking, never Impersonation) and checks the **owner of the pipe
> object** (`GetSecurityInfo(OWNER_SECURITY_INFORMATION)`) against its own user
> SID **before the first write**; the server PID is not used for that decision.
> The server accepts `TokenImpersonationLevel >= SecurityIdentification` and
> additionally requires, from the client token: integrity >= Medium, not an
> AppContainer, not restricted, same session. The statements below describing
> `SECURITY_IMPERSONATION` are the W4 history. Runtime evidence exists only for
> the Python/ctypes port `udx_ref/windows_pipe.py` (see `docs/W12_WINDOWS_LANE.md`).


This directory contains two Win32 C++ **research-only source candidates**, not a UDX broker:

- `udx_sid_probe.cpp`: one-shot Named-Pipe server; DACL only `SY` plus exact current user SID; `FILE_FLAG_FIRST_PIPE_INSTANCE`; `PIPE_REJECT_REMOTE_CLIENTS`; reads one byte before `ImpersonateNamedPipeClient`; opens thread token and requires SID match; `RevertToSelf` before a fixed `PEER_OK` response; no device capabilities or host actions.
- `udx_sid_client.cpp`: **W13/W14** connects with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY` and performs a pipe-owner check before sending. Earlier references to `SECURITY_IMPERSONATION` are historical W4 text, not current behavior.

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
