# ADR-UDX-006 (W19) — Threat-model split: same-SID trust domain

Status: **Accepted** — decision Vero, 2026-10-23. The repository owner can overrule it.
Scope: the Windows named-pipe peer-SID probe (`udx_ref/windows_pipe.py`,
`windows/udx_sid_probe.cpp`, `windows/udx_sid_client.cpp`). Research only; not a
production security acceptance and not a release approval.

> **Product-gate cross-reference (added W24, reviews UDX-W21-03 / UDX22-03):**
> `docs/W5_RELEASE_GATES.md` gate **G2-App remains FAIL/OPEN**, and `docs/ROADMAP.md`
> P0 (OS-enforced application identity; deny same-UID impostors before any sensitive
> adapter) remains mandatory. This ADR only narrows the threat model of the research
> named-pipe probe. UDX14-08 / UDX-R25-01 (pre-start squatting) is **out of scope for
> research, not fixed for a product**. A product broker needs its own OS principal
> (service SID or package identity), a trusted bootstrap of the expected server
> identity before the first payload, and hostile same-SID negative tests.

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

## Addendum W25.2 (2026-11-09): lower-integrity squatter of the same user

The trust domain is same SID **and** same integrity level. A Low-IL process of the
same user is therefore outside it, but a client that only compares the pipe owner
with its own SID would accept a pipe created by such a process. The owner of a
pipe created by a Low-IL process of the user is that user's SID.

Decision: both clients (`windows/udx_sid_client.cpp`, `udx_ref.windows_pipe.client_ping`)
also require, before the first byte is written, exactly one explicit mandatory
label of at least Medium on the pipe object:

- the C++ client exits `7`;
- the Python client returns `PIPE_LABEL_TOO_LOW` or `PIPE_LABEL_FAILED`.

Every server of this project sets `S:(ML;;NWNR;;;ME)` explicitly. A process cannot
label an object above its own integrity level, so a Low-IL squatter cannot meet the
rule, whatever the default labelling of the objects it creates. An AppContainer
cannot create the global name at all: AppContainer pipe names are confined to
`\\.\pipe\LOCAL\`, which is redirected into the AppContainer's own namespace.

Evidence: `tools/w25_principal_matrix.py`, cases `squat_low_il_default` and
`squat_low_il_medium_label`; CI run 42609005161, both parent modes `PRINCIPAL_MATRIX_OK`.

- A Low-IL process **can** create the global production name, and the kernel labels
  the pipe Low (0x1000) by itself.
- For a standard account the pipe owner is the user, so the owner check alone would
  have passed. Both clients refuse on the label (exit 7 / `PIPE_LABEL_TOO_LOW`), and
  the squatter receives 0 bytes.
- An explicit Medium label in the squatter's descriptor fails with 1314
  (`ERROR_PRIVILEGE_NOT_HELD`).
- Side effect: because the token policy `NO_WRITE_UP` forbids a Low-IL writer on any
  Medium-labelled pipe, the server's `INTEGRITY_TOO_LOW` check is unreachable for
  non-AppContainer Low clients (defense in depth).

Details: `docs/W25_PRINCIPAL_MATRIX.md`. A same-SID squatter at the **same** level stays out
of scope: it can set the Medium label itself.

## Addendum W25.2 Aegis review (2026-11-09): equal integrity, effective label, restricted squatter

### P2: the server requires the client's integrity level to EQUAL its own

Section 1 defines the trust domain as same SID **and** same integrity level. Both
servers still only required the client's level to be at least Medium. So a Medium
client of the same user got `PEER_OK` from an elevated (High) server, and an elevated
client was accepted by a Medium server. Both cases cross the trust domain.

Decision: both servers read their own integrity RID from their process token and
require `client RID == own RID`. The `>= Medium` floor stays in front of it.

- Python: `OneShotPipeServer` reads `own_integrity_rid()` once at construction. A
  token that cannot be read raises `OSError`, so the server does not start (fail-closed).
  A client below Medium keeps the reason `INTEGRITY_TOO_LOW`; any other difference
  gives the new reason `INTEGRITY_MISMATCH`.
- C++ (`udx_sid_probe.cpp`): `server_rid` is read together with the session; it exits
  with `11` if that fails. `authorized` adds `rid == server_rid`; the denial line keeps
  its format.
- Tests: `test_w25_2_integrity.py` `test_higher_integrity_token_denied`
  (client RID = own RID + 0x100, real pipe) and
  `test_server_without_own_integrity_refuses_to_start`; portable pins in
  `SquatterW252` and mutations DK21/DK24 (`evidence/w25_dk_spec.json`) and N1/N2
  (`evidence/w25_2_native_dk_spec.json`).
- Not evidenced: no host in this repo has run a real High client against a Medium
  server, or a real Medium client against a High server. The CI parents run the server
  and the clients at one level, so on each parent the change is exercised only as
  "equal passes" and "Low is refused".

Still open and **not** built: the reverse direction on the client side. An elevated
client accepts a pipe with a Medium label owned by the user, which a Medium process
of the same user can create. Closing it would need each server to label its pipe with
its own level and each client to require `label == own level`. That changes the
production SDDL for elevated servers, which only the CI elevated parent can measure.
The decision is left to the owner.

### Label check: effective and No-Write-Up

The W25.2 rule accepted any single label ACE whose RID was at least Medium. Two
cases met that rule without enforcing anything on the pipe object:

- An ACE with `INHERIT_ONLY_ACE` does not apply to the object itself.
- An ACE whose policy mask lacks `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` does not stop
  a lower-level writer.

Both clients now refuse both cases before the first byte:

- Python: `PIPE_LABEL_INHERIT_ONLY` and `PIPE_LABEL_NO_WRITE_UP_MISSING`.
- C++: exit 7. The stderr line `UDX_CLIENT_PIPE_LABEL` now also prints `flags` and `mask`.

Measured on the development host (Windows 11 Home 10.0.26200, medium IL, own run
2026-11-09):

- A bare `S:(ML;IO;NWNR;;;ME)` is dropped by the kernel: no label ACE reads back.
- `S:(ML;OICIIO;NW;;;ME)` is kept with flags `0xb`.
- `S:(ML;;NR;;;ME)` reads back with mask `0x2`.
- A thread impersonating a Low-IL copy of the user's token cannot create the pipe:
  - with `OICIIO` Medium: error 1299;
  - with an explicit Medium label, with or without NW: error 1314.
- With a bare `IO` Medium label that thread does create it, and the pipe reads back as Low (`0x1000`).

No bypass by a Low-IL creator was found, so the new check is defense in depth.

Tests: `test_w25_pipe_label.py` `test_inherit_only_label_is_refused`,
`test_label_without_no_write_up_is_refused` and
`test_production_label_is_effective_and_no_write_up`; mutations DK22, DK23, DK25,
DK26 and N3 to N5.

### P3: restricted-token squatter (residual boundary, NOT covered)

**Threat.** A process of the same user runs at the same integrity level under a
restricted token, for example a sandbox that restricts SIDs but does not lower the
integrity level. It creates `\\.\pipe\UDX_W4_SID_PROBE` before the real server starts.

**Measured on the development host** (own run 2026-11-09, thread impersonation of a
restricted copy of the user's Medium token, not a separate restricted process):

| restricting set | creates the name with `O:<user>` + `S:(ML;;NWNR;;;ME)` | Python client | `OpenProcess(VM_WRITE\|CREATE_THREAD)` on a process of the user |
|---|---|---|---|
| user SID only | no, error 5 | (no pipe) | yes |
| `RESTRICTED` (S-1-5-12) | **yes**, owner = user, label `0x2000` / mask `0x3` | **accepts** (`SILENT_HOLD`) | no, error 5 |
| `Everyone` (S-1-1-0) | **yes** | **accepts** | no, error 5 |
| `RESTRICTED` + `Everyone` | **yes** | **accepts** | no, error 5 |
| `RESTRICTED`, `WRITE_RESTRICTED` | **yes** | **accepts** | no, error 5 |

**Why it is not covered.** Section 1 puts a process out of scope only because it
can already inject into the server and the client. A restricted token that cannot
open the user's processes for writing does not have that power. It is therefore
**outside** the trust domain, yet it passes both client checks:

- the owner check, because the default owner is the user;
- the label check, because a process may set a label equal to its own level.

The server-side `RESTRICTED_TOKEN` check protects only the server's view of its
**clients**. It says nothing about who created the pipe. The statement "restricted
token" under Consequences therefore covers restricted clients only.

**Impact if exploited.** The client sends one byte with SQOS Identification and
`EFFECTIVE_ONLY`. The squatter learns the client's identity, but it cannot act as the
client, and it can answer with a forged `PEER_OK`. The probe carries no data and
grants no OS action, so the damage is a false peer verdict, not a privilege gain.

**Residual boundary.**

- Owner and label are the only facts a client can read from the pipe object, and
  neither tells this squatter apart from the real server.
- The only reachable signal would be the server's process token via
  `GetNamedPipeServerProcessId`. That PID is deliberately not a security input
  (Forshaw 2019, see W13).
- Covering the threat needs the design in section 2: a server identity the user
  cannot assume, checked as the pipe owner.
- Pinned as a boundary, not as a guarantee: `test_w25_pipe_label.py`
  `test_restricted_token_squatter_is_a_documented_boundary` turns red if Windows
  changes any of the three facts (create allowed, client accepts, process access denied).

Not evidenced:

- A separate restricted **process** as the squatter. The principal matrix has
  none; its `restricted` principal restricts to the user and every enabled group,
  and so it stays inside the trust domain.
- Restricting sets with the logon SID.
- Any host other than the development host.

## Addendum UT6-02 (2026-11-11): the client binds the same identity as the server

Cross-family re-audit A7-R2 confirmed a design asymmetry. Since the W25.2 Aegis
review the server required the client's integrity level to EQUAL its own (P2), but
the client only required the pipe's mandatory label to be `>= Medium`, and every
server labelled its pipe Medium whatever its own level. A Medium client therefore
accepted the pipe of an elevated server of the same user and wrote to it, although
section 1 makes only same SID AND same level one trust domain.

Decision (both directions now symmetric):

- **Server label = own level.** `build_sddl(sid, rid)` takes the server token's own
  level; `OneShotPipeServer` passes it. Medium -> `S:(ML;;NWNR;;;ME)`, High ->
  `S:(ML;;NWNR;;;HI)`. Any other own level (Low, Medium Plus, System, Protected)
  refuses to start (`ValueError('UNSUPPORTED_INTEGRITY_LEVEL')`; C++ probe exit 16)
  before anything is allocated. The one-argument `build_sddl(sid)` keeps the
  reviewed Medium string.
- **Client label = own level.** The client reads its own effective level before the
  open (Python: the thread's impersonation token if present, else the process
  token; any other `OpenThreadToken` error is a failure, not a fallback; C++: the
  process token, the C++ client never impersonates). Unreadable ->
  `OWN_INTEGRITY_FAILED` / C++ exit 8, nothing opened. A single effective
  No-Write-Up label that is not EXACTLY that level -> `PIPE_LABEL_MISMATCH` / C++
  exit 7, no byte sent. Below Medium stays `PIPE_LABEL_TOO_LOW`.

Consequence for the principal matrix: an AppContainer child (Low) can no longer
reach the server's `INTEGRITY_TOO_LOW` check. Under a Medium parent the lowbox
token still opens the AC-ACE pipe (measured W25.1) and the C++ client refuses the
label (exit 7). Under the elevated parent the label is High; the expected outcome
(open refused with 5) is a PREDICTION until the first CI run measures it. The server
check stays as defense in depth and keeps its fault-injection tests.

Evidence on the development host (Windows 11, standard user, Medium): real token
and real kernel label on one side of every case, the other side injected
(`tests/test_ut6_02_label_parity.py`). Not evidenced here: a real High label against
a real Medium client, the elevated runner, and the compiled C++ (no compiler on the
host; CI jobs `cpp-candidate`, `windows-principal-matrix`, `windows-native-evidence`).
