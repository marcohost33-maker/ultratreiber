# UDX W14 – independent follow-up / gates / handoff (2026-10-13)

**Evidence head (unchanged):** `26309e997fea1ac90edba8a51e457fd494cac978`

**Artifact class:** LOCAL CANDIDATE DIFF, not merged, not Windows-tested, not a
release; use `git apply --check` on a clean W14 checkout before review.

## Critical self-correction to previous report

A successful Linux discovery run (`239` total, `67` skipped) does not confirm
`5/5` Windows mutation differentiation, because the Windows tests are excluded.
The concrete `GRGW` access mask `0x0012019f` contains the **instance creation
bit** `0x4`, while not explicitly containing `WRITE_DAC`, `WRITE_OWNER`, or
`DELETE`. This is narrower than `GA` but cannot be described as client-least-
privilege. First-instance single-instance semantics constrain *concurrent*
instances, not prestart name squatting. Owner SIDs are not server authenticity.

## Reproducible negative-first checks

```sh
PYTHONPATH=. python -m unittest discover -s tests -q
PYTHONPATH=. python tools/w14_acl_static_gate.py --json /tmp/w14_portable.json
python -m json.tool /tmp/w14_portable.json
sha256sum -c SHA256SUMS_W12
```

The `tests/test_w14_acl_static_gate.py` covers: original SDDL, GA rollback
mutation, missing FIRST_PIPE_INSTANCE mutation, protected DACL and NWNR mandatory SACL, explicit
mask aliasing, wrong SHA, and refusal to certify a release. These portable
probes are **not** Win32 kernel access checks. The executable script is
advisory; never wire its successful exit to a GitHub **required release check**
without a trusted external evidence producer and a separate OS validator.

## Windows test matrix (owner-executed, cross-family witnessed)

| Lane | Positive control | Discriminating negative | Evidence | Release |
|---|---|---|---|---|
| Same interactive account, medium IL | `PEER_OK` | alternate process squats pre-start; proper denial or documented availability limit | test + PID, token SID/IL, DACL/SACL snapshot | blocked |
| Second ordinary user | same-user control | secondary user cannot open/send | two independent Windows accounts | blocked |
| Low IL / AppContainer | medium positive | client denied at OPEN and no occupied server slot | actual token + GetSecurityInfo/Win32 error | blocked |
| UAC elevated / non-elevated | owner SID readback | verify elevated Administrators owner fail-closed | actual owner SID + effective rights | blocked |
| Services / SYSTEM | matched user control | service account denial / session denial | SCM token info + OS build | blocked |
| OW ACE option | original DACL control | ACCESS_CHECK WRITE_DAC denied for object-owner without breaking server | changed SDDL + recorded rollback | blocked |
| Native C++ | Python ctypes baseline | stall, CancelIoEx, peer death, SDDL mismatch, heap lifetime | native compiled executable and toolchain | blocked |
| Remote / SMB | local success | `PIPE_REJECT_REMOTE_CLIENTS` from remote peer | second host and network path | blocked |

## Invariants / ownership decisions

* Same-SID processes trusted? Current design assumes yes. If not, a redesign is
  needed, not an informal `OW` edit.
* Server startup: `FILE_FLAG_FIRST_PIPE_INSTANCE` + one live instance is an
  availability gate, not authenticated application identity.
* OwnerRights SDDL: the effective owner may be Administrators rather than user;
  `READ_CONTROL` persists through another ACE even when implicit owner rights
  are suppressed; OS `AccessCheck` must be tested.
* Research handshake (`PEER_OK`) grants **no operational UDX capabilities**.
* C++ client/server have unbounded blocking I/O; no production authorization.
* Any future trusted gate must bind `reviewer, source head SHA, base SHA,
  test binary SHA, host OS, command, exit code, timestamps, independent reviewer`
  and fail closed on absent, stale, conflicting or untrusted evidence.

## Required disposition

**NO-GO for merge/release/claim of Windows G2.**
Portable reference tests can run as a maintenance gate, but must never become
proof of native rights. No GitHub mutations or production deploys by this patch.
