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

---

# W13 nach Aegis (2026-10-09/10) — supersedes parts of W12 above

Input: Aegis adversarial audit of `udx_ref/windows_pipe.py` @`c2dcd69` plus the
Quella precision note (primary sources: Forshaw 2019 on pipe server PIDs; Tokio
CVE-2023-22466). Vero decision E2 (W12: server requires >= Impersonation) was
**revised**. Code state for all numbers below: `4b0fa4b` (only docs changed after).

## Protocol after W13

- **Client** (`client_ping`): `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION |
  SECURITY_EFFECTIVE_ONLY`, static tracking; Impersonation/Delegation cannot be
  requested. **Before the first write** the owner of the pipe object
  (`GetSecurityInfo(OWNER_SECURITY_INFORMATION)` on the client handle) must equal
  the expected SID, otherwise typed refusal and no byte is sent. The server PID is
  recorded only (Forshaw: not a basis for security decisions). Write/read run with an
  absolute deadline.
- **Server**: level >= Identification; from the client **token** additionally
  integrity >= Medium, `TokenIsAppContainer == 0`, `TokenIsRestricted == 0`,
  `TokenSessionId ==` own session; then `EqualSid`. Read-then-impersonate kept.
- **SDDL**: `D:P(A;;GA;;;SY)(A;;GRGW;;;<user>)S:(ML;;NWNR;;;ME)`; read back:
  `D:P(A;;FA;;;SY)(A;;0x12019f;;;<user>)S:AI(ML;;NWNR;;;ME)`.
- **W14 (E1010M-05, 2026-10-12)**: the SYSTEM ACE is narrowed to GRGW as well:
  `D:P(A;;GRGW;;;SY)(A;;GRGW;;;<user>)S:(ML;;NWNR;;;ME)`; read back (live, this host):
  `D:P(A;;0x12019f;;;SY)(A;;0x12019f;;;<user>)S:AI(ML;;NWNR;;;ME)`. Neither ACE carries
  WRITE_DAC/WRITE_OWNER. Discrimination: `evidence/w14_dk_spec.json` (3 cases).
- `windows/udx_sid_client.cpp`, `udx_sid_probe.cpp`, `windows/README.md` follow the
  same protocol — **still UNCOMPILED** (no compiler on this host).

## Runtime evidence (real Win32, single account, not elevated)

| check | observed |
|---|---|
| Identification client | `PEER_OK`, level 1 |
| Aegis p1 squatter (same account, default DACL) | squatter's impersonation token has level **1** (was 2), 1 privilege (was 5 in Aegis p1); client returns `READ_TIMEOUT` instead of blocking |
| expected server SID ≠ owner | client `PIPE_OWNER_MISMATCH`, `sent=False`; server never read a byte (`client_pid is None`) |
| injected foreign owner S-1-5-19 / owner query failure | `PIPE_OWNER_MISMATCH` / `PIPE_OWNER_FAILED` (typed), nothing sent |
| server PID query fails | still `PEER_OK` (PID not decisive) |
| real `CreateRestrictedToken` client (restricting SID = user) | opens the pipe (DACL admits), server `RESTRICTED_TOKEN` |
| injected token facts (IL 0x1000, AppContainer, other session, level 0) | `INTEGRITY_TOO_LOW` / `APPCONTAINER_CLIENT` / `SESSION_MISMATCH` / `IMPERSONATION_LEVEL_TOO_LOW` |
| Low-IL `GENERIC_READ` open (Aegis F-LOWIL) | **5** with the NW\|NR label (was: open OK, slot occupied); Medium read-only control OK |
| `dwPipeMode` actually passed to `CreateNamedPipeW` | contains `PIPE_REJECT_REMOTE_CLIENTS`; `FIRST_PIPE_INSTANCE`; `nMaxInstances = 1` |
| Aegis p3-1 async exception after impersonation | thread reverted (was: still impersonating) |
| Aegis p3-2 close() before the write | `DENIED`, nothing sent (was: `PEER_OK`) |
| Aegis p3-3 write complete, re-check late | `PEER_OK`, `response_sent` (was: `DENIED` while client held `PEER_OK`) |
| Aegis p3-4 `ConvertSidToStringSidW` fails | typed `SID_TEXT_FAILED` (was: `OSError`) |
| exception during a pending wait | owner cancels the I/O, nothing parked |
| `DisconnectNamedPipe` raises inside `close()` | handle still closed, name free |
| dropped server without `close()` | `__del__` releases the name |
| `validate_deadline(10**400)` | `ValueError('INVALID_DEADLINE')` |

Observation (fail-closed, documented in the test): `client_ping` running under a
restricted impersonation token got `GetSecurityInfo -> 127` (`ERROR_PROC_NOT_FOUND`)
when the provider DLL was not loaded yet, and refused with `PIPE_OWNER_FAILED`.

## Suite and discrimination at `4b0fa4b`

- `PYTHONPATH=. python -m unittest discover -s tests -v`: **Ran 239, OK
  (skipped=82), exit 0** — 157 ok. Per file (ok/skip): w12_windows_pipe 53/0,
  windows_source_guards 3/0, others unchanged from W12.
- `evidence/w13_dk_spec.json`, run `DK-20261009T221658-9d24bf4aacbf` @`6787513`:
  **22/22 DISKRIMINIERT**, provenance VOLL. An earlier run
  (`DK-20261009T221444-39142574a5d5` @`75e56a8`) had 21/22, W13-DK07 baseline
  red (the order dependence above); fixed in `6787513`.
- `evidence/w13_dk_carryover_spec.json` (W12 guards re-targeted), run
  `DK-20261009T221821-ba1c3a12b550` @`4b0fa4b`: **9/9 DISKRIMINIERT**, VOLL.
  `evidence/w12_dk_spec.json` is now a historical record (its targets moved).

## Claim ceiling after W13 (unchanged where not stated)

- Owner check proves the pipe **object owner**, not the process behind it; an
  attacker with the same user SID is trusted by construction. An **elevated** server
  of an admin account usually has owner = Administrators → the client would refuse
  it (fail-closed, untested here).
- Cross-user squatting by a service account (Aegis A3) is mitigated by protocol
  (Identification only) but **not runtime-tested** (no second account / service context).
- SY ACE remains GA (C++ parity); untested as a client.
- AppContainer, other-session and Low-IL **token** paths are evidenced by injection
  only; the real Low-IL client is blocked earlier by the mandatory label.
- C++ sources remain uncompiled; no cross-family review of W13 yet.
