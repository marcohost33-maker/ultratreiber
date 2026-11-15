# ADR-UDX-007 (W26) — IPC integrity policy: one endpoint per (user SID, integrity level)

Status: **Proposed** — Claude session for the owner, 2026-11-15. The repository owner
decides; until then the code keeps the UT6-02 rule unchanged (this ADR adds tests and
evidence, no behaviour change). Scope: the Windows named-pipe probe
(`udx_ref/windows_pipe.py`, `windows/udx_sid_client.cpp`, `windows/udx_sid_probe.cpp`).
Research only; not a production security acceptance and not a release approval.

Trigger: the A7 round of 2026-11-11 (order `AUFTRAG_007acc2_A7_Sammel-5PR_…`, head
`a736ca8`) asked UT-A7-01 ("label equal to own level: is a legitimate Medium client
wrongly refused by a High server, and the reverse?") and UT-A7-03 ("do AppContainer /
LPAC clients carry a label that breaks the equality rule?"). The reviews disagree:

| Review (Drive `007acc2/02_ANTWORTEN`, 2026-11-12) | Verdict | Proposal |
|---|---|---|
| Gemini, A7 Sammel-5PR (two documents) | UT-A7-01 **BESTAETIGT** (type-2 errors), UT-A7-03 **BESTAETIGT** (E1) | server: `client_il >= min_required_il`; client: `pipe_label_il >= client_il`, owner = expected SID, label NO_WRITE_UP |
| GPT-6, cross-family reaudit / R10.1 | NICHT_PRUEFBAR on Windows (E0) | "keine blinde >= Medium-Umstellung"; decide only from an explicit IPC/role model; `pipe_il >= client_il` "ist kein genereller Ersatz für ACL/Owner/Token-/Capability-Prüfungen" |

None of the reviewers ran anything on Windows for this repository (all E0/E1). This ADR
writes down the role model GPT-6 asks for, shows that Gemini's client rule and the
current rule decide identically on every input the kernel lets through, and adds
native cases (W26) that measure the two cross-level directions.

## Decision

### 1. Role model

A UDX endpoint serves exactly one principal: **the user SID at the server's own
integrity level** (ADR-UDX-006 §1: same SID and same level is one trust domain). A
client talks only to an endpoint of its own (SID, level). Concretely:

- the server labels its pipe with its own level (`build_sddl(sid, rid)`, UT6-02) and
  refuses a client of a different level (`INTEGRITY_MISMATCH`);
- the client requires exactly one effective No-Write-Up label equal to its own
  effective level (`PIPE_LABEL_MISMATCH`, C++ exit 7), after the owner check.

Cross-level traffic (Medium <-> High of the same user) and sandboxed clients
(AppContainer, LPAC) are **not supported** by the research probe. That is a scope
decision, not an oversight: each needs its own endpoint design (§4).

### 2. Medium client -> elevated (High) server: refused by the kernel, not by UDX

The pipe carries `S:(ML;;NWNR;;;HI)`. The Medium client's token has the default
mandatory policy `TOKEN_MANDATORY_POLICY_NO_WRITE_UP`: "a process associated with the
token cannot write to objects that have a greater mandatory integrity level"
([MS-DTYP 2.4.8](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/de8373ec-206f-4dc8-b3fe-c638fed7b282)).
The client opens with `FILE_GENERIC_READ | FILE_WRITE_DATA` (W18), so `CreateFileW`
fails with `ERROR_ACCESS_DENIED` before a single line of the UT6-02 client rule runs.
W25.2 measured the same mechanism for Low against Medium (CI runs 42606332563,
42608409744: neither label mask 0x0 nor NX-only admits the writer).

Consequence: the "false rejection" of UT-A7-01 (first half) is the operating-system
boundary. No client-side relaxation can admit this client; only weakening the
**server's** label (dropping NW, or labelling Medium) could, and that would let every
Medium process of the user write into the elevated broker. W26 measures this case
natively (`py_medium_il`, `cpp_medium_il`, elevated parent only).

### 3. Elevated (High) client -> Medium endpoint: refused by the UT6-02 client rule

A Medium process of the same user can create the production name with **exactly** the
descriptor this project's own Medium server sets — `build_sddl(sid, MEDIUM)`: owner =
the user, the same DACL, label `ME` with NW|NR (it may label at its own level, only
not above it; W25.2 measured 1314 for Low -> Medium). To the elevated client such a
squatter is byte-for-byte indistinguishable from a legitimate Medium UDX server: the
owner check passes, and only the level separates them. W26 adds this squatter
(`squat_medium_il_production`) and requires: C++ exit 7 with the label line
`rid=8192 … own=12288`, Python `PIPE_LABEL_MISMATCH` with the owner check passed,
squatter received **0 bytes**. Under the pre-UT6-02 rule (`label >= Medium`) the
elevated client would have written to it — the A7-R4 open gate "elevated client vs
medium squatter".

So the second half of UT-A7-01 is not a type-2 error either: refusing is the only
decision that does not hand elevated data to any Medium process of the user. A
legitimate Medium server and a Medium squatter cannot be told apart without a server
identity that a Medium process cannot forge (§4).

### 4. Gemini's asymmetric rule decides identically on every reachable input

Let `c` be the client's level, `s` the server's level; the server labels the pipe
`s` with NO_WRITE_UP (both rules require NO_WRITE_UP).

| Case | Kernel at open | Current client rule (`label == c`) | Gemini client rule (`label >= c`) | Old W25.2 rule (`label >= Medium`) |
|---|---|---|---|---|
| `c == s` (Medium/Medium, High/High) | admitted | accept | accept | accept |
| `c < s` (Medium client, High pipe) | **refused, 5** (token NO_WRITE_UP) | not reached | not reached | not reached |
| `c > s` (High client, Medium pipe or squatter) | admitted | **refuse** (exit 7) | **refuse** (`ME >= HI` is false) | **accept -> writes** (UT6-02 hole) |
| `c` Low / AppContainer, pipe Medium or High | refused at open (Low) or by the DACL / label (AppContainer, W25/W25.1) | refuse if reached | refuse if reached | refuse if reached |

The two rules differ only where the label is above the client's level and carries
NO_WRITE_UP, and there the kernel already refuses the open. Gemini's server-side rule
(`client_il >= min`) would admit a High client at a Medium server; that pairing is
refused one step earlier by both client rules. **Decision: keep equality.** It is the
tightest rule, it mirrors the server's `INTEGRITY_MISMATCH`, and it is observationally
equal to the proposed alternative wherever the kernel lets a client through. A change
would cost a code diff in two languages for no change in any reachable outcome.

### 5. AppContainer and LPAC: not supported, by design

An AppContainer token is always Low IL (measured W25); LPAC tokens are AppContainers
without the `ALL APPLICATION PACKAGES` (`AC`, S-1-15-2-1) membership and are granted
access only through `ALL RESTRICTED APPLICATION PACKAGES` (S-1-15-2-2) or their package
SID ([Raymond Chen, 2022-05-02](https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550)).
The production DACL has neither ACE, so both are refused at open (measured for
AppContainer, W25; LPAC **not** measured). UT-A7-03 is therefore confirmed as a
**property**, not a defect: sandboxed clients are outside the role model. Supporting
them would need a separate, opt-in endpoint (package-SID ACE, Low label, its own
queue and its own server-side checks), never a widening of the Medium/High pipe.

### 6. Where Microsoft draws the line

Microsoft's servicing criteria treat administrator-to-kernel as not a boundary and
handle UAC as a defense-in-depth feature rather than a serviced security boundary
([MSRC Windows security servicing criteria](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria);
the classification was disputed for CVE-2024-6769,
[Dark Reading](https://www.darkreading.com/vulnerabilities-threats/exploit-chain-windows-uac-bypass)).
This ADR does not rely on Windows servicing a Medium -> High bypass. It keeps the
research probe from **adding** a cross-level channel of its own, which is the
conservative reading of ADR-UDX-006 §1. (The exact MSRC list entry for UAC was not
re-read in this session; the claim rests on the cited summaries.)

## Consequences

- No behaviour change. `tools/w25_principal_matrix.py` gains the principal `medium_il`
  (the parent's token lowered to `S-1-16-8192`), two client cases and one squatter
  case for the elevated parent; `evaluate()` stays fail-closed; 12 portable
  discriminating mutations (`evidence/w26_dk_spec.json`).
- Answers: UT-A7-01 -> **design decision, both directions refused on purpose**;
  measured natively in CI run 43767612816 (head `7f1735a`): `py_medium_il` /
  `cpp_medium_il` exit 1 with error 5; `squat_medium_il_production` C++ exit 7 with
  `rid=8192 … own=12288`, Python `PIPE_LABEL_MISMATCH`, 0 bytes to the squatter
  (see `docs/W26_CROSS_IL_POLICY.md`).
  UT-A7-03 -> **confirmed as out of scope**; LPAC not measured. UT-A7-02 (C++/Python
  parity) -> the squatter case checks both clients against the same real Medium pipe.
- Still open and unchanged: G2-App (OS application identity / server bootstrap), a
  cross-level or sandboxed endpoint design if the owner wants one, second interactive
  session, UIAccess and virtualized tokens, Windows 11 instead of the hosted Windows
  Server runner, independent attestation.
