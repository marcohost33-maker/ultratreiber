# ADR-UDX-006 (W19) — Threat-model split: same-SID trust domain

Status: **Accepted** — decision Vero, 2026-10-23. The repository owner can overrule it.
Scope: the Windows named-pipe peer-SID probe (`udx_ref/windows_pipe.py`,
`windows/udx_sid_probe.cpp`, `windows/udx_sid_client.cpp`). Research only; not a
production security acceptance and not a release approval.

Trigger: cross-family review R25, finding UDX-R25-01 (P1): "DACL + owner alone are
no server authentication under an adversarial same-SID process" (pre-start
squatting). The repository already stated the gap: `udx_ref/windows_pipe.py`
(`build_sddl` docstring, "they do not prevent another same-SID process from
squatting on the pipe name BEFORE server startup"), `docs/ROADMAP.md` W18 item (3)
"UDX14-08 pre-start squatting (needs a server-identity/bootstrap design, not an
ACL edit)", and `docs/W14_INDEPENDENT_FOLLOWUP_2026-10-13.md` "Same-SID processes
trusted? Current design assumes yes." This ADR turns that implicit assumption into
an explicit decision.

## Decision

### 1. Same user SID at the same integrity level is one trust domain

Processes that run with the same user SID **and** the same mandatory integrity
level as the probe are treated as one principal. Authenticating the pipe server
against such a process is out of scope, because it would buy no security: that
process can already read and write the memory of, and start threads in, both the
legitimate server and the legitimate client.

Primary sources (Microsoft Learn, fetched 2026-10-23):

- Process Security and Access Rights,
  <https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights>:
  "If you specify **NULL**, the process gets a default security descriptor. The ACLs
  in the default security descriptor for a process come from the primary or
  impersonation token of the creator." The same page defines `PROCESS_ALL_ACCESS`
  as "All possible access rights for a process object", including
  `PROCESS_CREATE_THREAD` ("Required to create a thread in the process") and
  `PROCESS_VM_WRITE` ("Required to write to memory in a process using
  WriteProcessMemory").
- DACL for a New Object,
  <https://learn.microsoft.com/en-us/windows/win32/secauthz/dacl-for-a-new-object>:
  "If no security descriptor is specified and there are no inheritable ACEs, the
  object's DACL is the default DACL from the primary or impersonation token of the
  creator."
- Mandatory Integrity Control,
  <https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control>:
  "a principal with a low integrity level cannot write to an object with a medium
  integrity level, even if that object's DACL allows write access to the
  principal." and "Standard users receive medium, elevated users receive high."
  MIC is therefore the only boundary *between* processes of one user; at the same
  level it does not apply.

What the documentation does not state literally — that the token's default DACL
grants the user `PROCESS_ALL_ACCESS` — was **measured** on the development host
(Windows 11 Home 10.0.26200, medium integrity, Administrators group deny-only,
i.e. not elevated, 2026-10-23; SIDs redacted):

| target process | DACL + label read back with `GetSecurityInfo` | `OpenProcess(PROCESS_ALL_ACCESS)` from another medium process of the same user |
| --- | --- | --- |
| `explorer.exe` (not started by the probe) | `D:(A;;0x1fffff;;;<user>)(A;;0x1fffff;;;SY)(A;;0x121411;;;<logon SID>)S:AI(ML;;NWNR;;;ME)` | succeeded |
| fresh `python.exe` child (default descriptor) | `D:(A;;0x1fffff;;;<user>)(A;;0x1fffff;;;BA)(A;;0x1fffff;;;SY)S:AI(ML;;NWNR;;;ME)` | succeeded |

`0x1fffff` is `PROCESS_ALL_ACCESS`. No `SeDebugPrivilege` was involved (the token
is not elevated). The page's sentence "To open a handle to another process and
obtain full access rights, you must enable the SeDebugPrivilege privilege" is about
processes whose DACL does not grant that access: Privilege Constants,
<https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>,
describes `SeDebugPrivilege` as "Debug and adjust the memory of any process,
ignoring the DACL for the process." For same-user, same-level processes the DACL
grants the access directly, as measured. The premise is
pinned by a test (`tests/test_w19_same_sid_trust_domain.py`,
`SameSidTrustDomainPremise`), so a change in Windows' default would turn the suite
red instead of silently invalidating this ADR.

Consequence: a hostile same-SID, same-IL process does not need to squat the pipe
name. It can inject into the server or the client and produce any answer it likes.
A pipe-level server authentication against it closes no path that remains open
through the process objects.

### 2. Hostile same-SID is explicitly NOT covered

The probe makes **no** claim against a hostile process of the same user at the
same integrity level. This includes pre-start squatting of the pipe name
(UDX14-08 / UDX-R25-01), which stays open by design under this ADR.

Design sketch, if that threat ever has to be covered (**not built**):

- Run the server under its **own identity** that the user cannot assume: a
  service SID / virtual account (`NT SERVICE\<name>`) of a Windows service, or an
  AppContainer whose package SID is derived from a signed package identity.
- The client checks `owner SID == that identity` (the existing owner check,
  `_verify_pipe_owner`, with a different expected SID) before its first write.
- Why this closes squatting: a non-elevated user process cannot set a foreign
  SID as the owner of the pipe it creates. Measured on the development host
  (2026-10-23, medium IL): `CreateNamedPipeW` with `O:<user>` succeeds; with
  `O:S-1-5-18` (SYSTEM) and with the service SID of `NT SERVICE\TrustedInstaller`
  as owner it fails with `ERROR_INVALID_OWNER` (1307). Only a privilege lifts
  that: Privilege Constants,
  <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>,
  `SeRestorePrivilege`: "this privilege enables you to set any valid user or
  group SID as the owner of a file." A squatting pipe created by the user
  therefore cannot carry the service owner SID, and the client refuses it before
  writing. (A process holding `SeRestorePrivilege` is elevated and outside this
  model anyway.)
- Bootstrap still has to be solved: the client must learn the expected server
  SID from a source the user cannot rewrite (installed service configuration,
  package manifest). A random pipe name without such a distribution channel does
  not solve the problem (as the R25 reviewer noted).
- Cost: service installation needs administrator rights once; the probe then
  becomes a two-identity system. Not justified for a research probe.

### 3. What remains as protection

These controls stay and are covered by existing tests; none of them is server
authentication.

| control | protects against | test |
| --- | --- | --- |
| `FILE_FLAG_FIRST_PIPE_INSTANCE`, `nMaxInstances = 1` | a second server joining a live name; the server joining a pre-created foreign pipe | `tests/test_w12_windows_pipe.py` `test_second_own_instance_refused`, `test_squatted_name_refused_by_first_pipe_instance`, `test_reject_remote_flag_reaches_create_named_pipe` |
| W18 ACE mask `0x12008b` (no `FILE_CREATE_PIPE_INSTANCE`) | any other principal (incl. same SID) adding an instance to the live pipe | `tests/test_w18_least_privilege.py` |
| client owner check before the first write | a pipe owned by a foreign principal (other user, Administrators, SYSTEM) | `test_client_refuses_foreign_owner_without_writing`, `test_client_refuses_injected_foreign_owner`, `tests/test_w17_pipe_owner.py` |
| explicit Medium label `NW+NR` | a Low-IL process opening (and occupying) the single instance | `test_low_integrity_client_cannot_open_pipe`, `test_low_integrity_read_only_open_denied` |
| server-side token checks (integrity, AppContainer, restricted, session) | lower-trust clients of the same user | `test_low_integrity_token_denied`, `test_appcontainer_token_denied`, `test_restricted_flag_denied`, `test_real_restricted_token_client_denied`, `test_other_session_denied` |
| client grants only Identification | a squatter that gets connected learns the identity, but cannot act as the client | `test_squatter_sees_only_identification` |

The last row is the boundary of this ADR made concrete: a same-SID squatter *is*
reached by the client (it passes the owner check, because it can name the user as
owner), and the damage is limited to an identification-level token and a client
that times out instead of hanging.

### 4. Availability boundary: the server must fail loudly

A squatter that holds the name first prevents the legitimate server from
starting. That cannot be prevented inside this trust model; it must not be
silent. The server therefore reports a pre-existing name with its own reason and
exit code:

- `OneShotPipeServer(...)` raises `PipeNameOccupied` (a `PipeSetupError`
  subclass, `reason == 'PIPE_NAME_OCCUPIED'`, `errno` = the Win32 code) when
  `CreateNamedPipeW` fails with `ERROR_ACCESS_DENIED` (5) or `ERROR_PIPE_BUSY`
  (231) **and** the name is present in the pipe namespace. Without that
  confirmation (e.g. an `ERROR_ACCESS_DENIED` for another reason) it stays the
  generic `PipeSetupError`, so the label never claims more than was observed.
- The CLI (`python -m udx_ref.windows_pipe server`) prints one JSON line
  `{"verdict": "DENIED", "reason": "PIPE_NAME_OCCUPIED", ...}` and exits with
  `21` (`NAME_OCCUPIED_EXIT`) instead of a traceback with exit code 1.
- The name is deliberately "occupied", not "squatted": the server cannot tell a
  hostile squatter from a second legitimate instance or a stale process.
- C++ parity is open: `windows/udx_sid_probe.cpp` returns `14` for every
  `CreateNamedPipeW` failure. MSVC is not installed on the development host, so a
  C++ change could not be built or run there and was not made.

Tests: `tests/test_w19_same_sid_trust_domain.py`, class `PipeNameOccupied`
(real pre-created pipes; no mocks in the positive and negative cases).

## Consequences

- Statements about the probe's security are bounded to "different user, lower
  integrity, other session, AppContainer, restricted token, remote". Same-user
  same-level hostility is a documented non-goal, not an open defect.
- UDX14-08 changes from "open" to "out of scope by ADR-UDX-006"; reopening it
  means implementing the design sketch in section 2.
- The G2 matrix rows that test *other* principals (second account, AppContainer,
  Low IL, service) remain required; this ADR does not replace them.
