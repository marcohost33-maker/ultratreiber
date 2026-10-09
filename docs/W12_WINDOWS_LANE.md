# W12 Windows lane — first runtime evidence (research only)

**Status: RESEARCH DEMONSTRATOR. Not production ready. No release claim.**
The W4 C++ candidate (`windows/udx_sid_probe.cpp`, `windows/udx_sid_client.cpp`)
is **still uncompiled**: the test host has no C++ compiler (cl/g++/clang absent).
What W12 adds is a Python/ctypes port of the same Win32 semantics
(`udx_ref/windows_pipe.py`), executed against the real Win32 API.

## Environment (own run, 2026-10-09)

- Windows 11 Home 10.0.26200, Python 3.14.4 (pythoncore, 64-bit), Node v24.17.0
- one interactive account, **not elevated**, no second account
- local git, code state `f7cb9a5`; command:
  `PYTHONPATH=. python -m unittest discover -s tests -v`

## Suite result on Windows

| state | result |
|---|---|
| W11 import `5c0a304` | Ran 183 — FAILED (errors=20, skipped=62), exit 1 |
| after B1 `3070853` | Ran 185 — OK (skipped=82), exit 0 |
| code state `f7cb9a5` | **Ran 214 — OK (skipped=82), exit 0** (132 ok, 0 fail, 0 error) |

The 20 W11 errors were all `AttributeError: os.getuid` in `DurableGrantTests.setUp`
(19) and `ThreadSafety` (1). They now skip ("POSIX uid/mode store checks required")
and `DurableGrantStore` denies non-POSIX hosts with `GrantDenied('UNSUPPORTED_PLATFORM')`.
Consequence: **W11-02 (SQLite transaction serialization) is NOT evidenced on Windows.**

Per file at `f7cb9a5` (ok/skip): contracts 3/0, core 33/0, linux_ipc 0/15,
node_interop 3/0, w10_grants_portal 10/21, w11_audit_hardening 9/1,
w12_platform_guards 2/0, w12_windows_pipe 29/0, w5_hardening 9/3,
w6_source_hardening 20/8, w7_falsification 8/6, w8_fd_handoff 0/16,
w9_boundaries 4/12, windows_source_guards 2/0. Every skip carries a Linux/POSIX reason.

## What is 1:1 with the C++ candidate

| C++ (`udx_sid_probe.cpp`) | Python port |
|---|---|
| L39–41 `D:P(A;;GA;;;SY)(A;;GA;;;` + SID + `)` | `build_sddl` (identical string; SID text validated against SDDL injection) |
| L44 `ConvertStringSecurityDescriptorToSecurityDescriptorW` | same call |
| L46–49 `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, `1, 4096, 4096, 0` | same flags and sizes (+ `FILE_FLAG_OVERLAPPED`) |
| L59 read exactly 1 byte, L61 then `ImpersonateNamedPipeClient` | same order (call-order test) |
| L63 `OpenThreadToken(..., TOKEN_QUERY, TRUE, ...)` | same |
| L18–23 `TokenUser`, cap 65536, `IsValidSid` | same |
| L67 `EqualSid(client_sid, server_sid)` | same (binary SIDs) |
| L72 `RevertToSelf` failure → `TerminateProcess(..., 30)` | same exit code 30 (subprocess test) |
| L76 `PEER_OK`, L84 exit 0 / 20; client L15 reads 7 bytes, exit 0 / 3 | same (CLI) |

Deliberate differences: absolute deadline over connect/read/write/drain via overlapped
I/O + `CancelIoEx` (C++: blocking, no deadline); **explicit `TokenImpersonationLevel >=
SecurityImpersonation`** (absent in C++); `GetNamedPipeClientProcessId` (failure denies);
refuse a server thread that already impersonates; bounded drain instead of
`FlushFileBuffers` (L81, unbounded); thread-safe `close()`.

## Runtime evidence (real Win32, single account)

| check | observed |
|---|---|
| same user, separate process | `PEER_OK`; `client_pid == Popen.pid`; level 2 (Impersonation) |
| Delegation level | `PEER_OK` |
| **Identification level** | token still yields the **same user SID** (recorded in the result); only the new level guard denies. Inference, not a native run: the C++ candidate, which performs only the other checks, would answer `PEER_OK` here; DK3 (guard removed) turns the test red |
| Anonymous level | `OpenThreadToken` fails 1347 (`ERROR_CANT_OPEN_ANONYMOUS`) → denied |
| expected SID ≠ client SID | `SID_MISMATCH` |
| DACL read back (`GetSecurityInfo`) | protected; exactly 2 ACCESS_ALLOWED ACEs: `S-1-5-18`, current user; mask `0x1F01FF`; `D:P(A;;FA;;;SY)(A;;FA;;;<SID>)` |
| own second instance | refused (`ERROR_PIPE_BUSY` 231 — instance limit hits first) |
| pre-created squatter pipe (default DACL, 255 instances) | with FIRST_PIPE_INSTANCE: 5 `ACCESS_DENIED`; **without it: creation succeeds, i.e. joins the foreign pipe** |
| SMB redirector loopback `\\localhost\pipe\…` | with REJECT_REMOTE: client open 5; without the flag (pre-test probe of the same server code): the network-logon client passed every check and received `PEER_OK`; DK6 turns the test red when the flag is removed |
| Low-IL client (thread token S-1-16-4096) | client open 5 (mandatory-integrity no-write-up of the default Medium label); Medium control → `PEER_OK`. This is OS MIC behaviour, not a UDX check |
| silent client / no client | `READ_TIMEOUT` / `CONNECT_TIMEOUT` at the deadline, no hang |
| client never reads response | `PEER_OK`, `response_drained=False`, returns within deadline |
| injected faults (Impersonate, OpenThreadToken, TokenInformation, ClientPid, CancelIoEx, RevertToSelf) | denied / bounded; RevertToSelf failure exits 30 |

Surprise: `ImpersonateNamedPipeClient` **before** any `ReadFile` returned TRUE
(static-tracking client) — "read before impersonate" is not an OS-enforced
precondition on this build; the order is kept and pinned by a call-order test.

## Defects found and fixed during W12

1. W11 suite crashed instead of skipping on Windows (20 errors) — B1.
2. `WaitForSingleObject` returned `WAIT_TIMEOUT` up to 5.05 ms before the monotonic
   deadline (3/12 repeat runs red) — re-wait loop, 0/20 red.
3. `close()` racing `serve()` → `STATUS_HEAP_CORRUPTION 0xc0000374` (found via the
   DK4 mutant) — lock + ownership contract.
4. Deadline guard against itself: a failed `CancelIoEx` followed by
   `GetOverlappedResult(bWait=TRUE)` stretched a 0.3 s deadline to 5.0 s — bounded
   1000 ms grace, pending I/O objects parked, never freed under the kernel.
5. Test harness: pytest fd-capture invalidates the inherited stdin handle →
   `subprocess` WinError 6 (9/15) — `stdin=DEVNULL`.

## Discrimination proofs

`evidence/w12_dk_spec.json`, tool `diskriminierung.py`, run
`DK-20261009T210522-5bdcb2b655e5` at `f7cb9a5`, provenance VOLL: **11/11 DISKRIMINIERT**
(DACL, EqualSid, impersonation level, deadline, FIRST_PIPE_INSTANCE,
REJECT_REMOTE, RevertToSelf→exit 30, already-impersonating, non-POSIX store,
close() ownership, cancel grace). An earlier run at `ac2fb30` scored 7/9; both
gaps were analysed and fixed (items 3 and 5 above).

## Claim ceiling — still BLOCKED for Windows G2

- C++ candidate **not compiled**, not run; no MSVC on this host.
- **Second ordinary account**: not available → alternate-account denial untested
  (SID mismatch only simulated by narrowing the expected SID).
- **Real remote host / SMB from another machine**: untested; only the local SMB
  redirector loopback.
- **UAC / elevated (High IL) clients and servers**: untested (not elevated).
  Impersonation downgrade rules for higher-IL clients are not observed here.
- Full UDX request/response protocol over the pipe, connection budget beyond one
  instance, sustained load, native error matrix, Windows versions other than
  10.0.26200, signed distribution: not done.
- Same user SID ≠ same application identity; the DACL limits who can connect, not
  which operation is authorized.
- No independent (cross-family) review of W12 yet; Python port ≠ native binary.
