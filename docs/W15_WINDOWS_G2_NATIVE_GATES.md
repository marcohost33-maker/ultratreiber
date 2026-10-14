# UDX W15 – Windows G2 local evidence lane (13 October 2026)

Author: Coworker Research. **Scope: isolated research test, NOT production deployment.**
Pin: W14 source HEAD `26309e997fea1ac90edba8a51e457fd494cac978`, with W14 independent patch **then** W15 increment. Do not claim a new approved remote SHA when running uncommitted patches.

## Why W15 is needed

W14 validated portable structure, not the kernel. W12/W13 captured one-account Win32 observations. Review of test code revealed **two distinct Windows-only `unittest.TestCase` classes**:
- `WindowsPipeRuntime`: 23 tests;
- `WindowsPipeFaultInjection`: 24 tests.

A prototype collector that selected only the first class silently dropped all 24 fault-injection tests. W15 now pins **47 cases** and checks class coverage, individual `PASS`, unique test identifiers, source SHA-256, and baseline Git head. Incomplete classes, subprocess failure, timeout, skipped cases, source mutation, or a false release flag must fail closed.

## How to collect a new primary Win32 result

Use a **disposable Windows 11 test VM** with two independent ordinary test accounts. Work in an unprivileged shell in an isolated folder; never against a production pipe/name. Verify the original Git bundle hash and W14/W15 patches separately before applying; both are research candidates and never pushed by this package.

In a Python 3.13+ terminal at the root of a clean W14+W15 checkout:

```powershell
python tools/w14_acl_static_gate.py --json w14_static.json
python tools/w15_windows_evidence.py --collect --repo . --timeout 300 --output w15_native.json
python tools/w15_windows_evidence.py --verify w15_native.json --repo .
python -m unittest discover -s tests -v
```

`--collect` runs precisely the 47 existing native Windows tests in an isolated child process; the child process has a deadline. It records the observed operating-system build and Python version, SHA-256 of the Python executable and source files, exit code, individual case outcomes, and an explicit list of **unexecuted manual gates**. No process elevation, second-user token, SCM change, registry write, or remote connection is initiated by the W15 collector. A green `--verify` means **schema and local-source consistency only**; it is not third-party authentication.

On Linux/macOS, `--collect` is required to return exit 2 and `NATIVE_WINDOWS_REQUIRED`. This is a **desired negative result**. If a Windows run skips even one native case, it does not pass this lane. Existing historical 239/245/257 suite numbers are Linux runs and must not be mixed with Windows counts.

## Seven independent gates left open after local collector success

| Gate | Positive control | Negative or adversarial requirement | Separate witness |
|---|---|---|---|
| SECOND_ORDINARY_ACCOUNT_DENIAL | original account positive handshake | other ordinary account attempts same exact random pipe; denial at client open or server token, no `PEER_OK` | independently recorded account SIDs (redacted), process logs |
| REAL_APP_CONTAINER_AND_LOW_IL | medium IL client works | real AppContainer or Low-IL token attempt, verify no usable positive response or slot occupancy | token-level/IL OS readback |
| ELEVATED_OWNER_AND_EFFECTIVE_ACL | ordinary account owner readback | elevated account owner and DACL/OW effective rights, incl. `WRITE_DAC` | GetSecurityInfo/AccessCheck results |
| SERVICE_ACCOUNT_SESSION | ordinary client works | service and alternate-session token denied | isolated service VM, SCM evidence |
| REMOTE_SECOND_HOST | local loopback works | actual remote SMB transport rejected | network second machine, OS logs |
| CPP_NATIVE_BINARY_AND_TIMEOUT_PARITY | Python baseline works | MSVC x64 compile, isolated process timeout, peer-death/blocked-read/failed-RevertToSelf cases; C++ blocking semantics are unresolved | build logs, binary digest, native test |
| INDEPENDENT_SECURITY_REVIEW | exact W14/W15 source and logs pinned | review finds source/evidence mismatch, rejects stale SHA or unreviewed security exception | trusted reviewer separate from patch author |

**Manual cross-account protocol** (no credential collection): One ordinary account launches the existing `udx_ref.windows_pipe` server using a unique ephemeral pipe name in the test VM and records its `listening` JSON. A second *already provisioned* ordinary account separately runs the existing client CLI against that name. Capture the client's exit code and server verdict; compare against a same-account positive control on a new unique pipe. Because the server is one-shot, every case needs its own instance. Do not create privileged accounts or impersonate users from the testing script. Name collisions and machine-wide namespace squatting are addressed by random names, not solved as authentication.

The C++ research candidate uses synchronous/blocking Win32 I/O and is **not deadline-equivalent** to the Python overlapped implementation. Never interpret successful compilation as cancellation or heap-lifetime safety.

## Source-of-truth and trust

- Patch is an unmerged local artifact. The W14 original Git HEAD stays unchanged until a separately approved code operation.
- `source_sha256` is an observation, not a signature. The report can be edited by a local actor. Independent capture/review, separate signer, trusted check provider, and a correctly configured GitHub ruleset are required for any release workflow.
- `manual_gates` must remain `NOT_EXECUTED` in this tool; external reviewed results belong in another signed/approved attestation artifact. The collector is **incapable** of authorizing a merge or deployment.
- Avoid putting real user SIDs, usernames, machine names, access tokens, full paths, or customer documents into shared evidence. Limit logs to minimal redacted facts and hashes; secure retention and consent by the project owner.
- W14 portable gate is unchanged; W15 is additive. No SDDL DACL/SACL mutation without Win32 AccessCheck. Same-SID process ≠ application identity.

## Primary references

- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches

## Gate disposition

`W15_PORTABLE_QUALITY = eligible for independent replay`;
`W15_NATIVE_WINDOWS_TEST = NOT_EXECUTED in this Linux environment`;
`W15_WINDOWS_G2 = BLOCKED`;
`W15_RELEASE = BLOCKED`.
