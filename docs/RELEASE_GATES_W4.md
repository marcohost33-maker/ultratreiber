# UDX v0.4 gate status — measured, not inferred

| Gate | Item | Result | Strict conclusion |
|---|---|---|---|
| G0 | Source tree, SHA256SUMS, fresh extraction | see independent evidence | LOCAL reproducibility only |
| G1a | Python JSON Schema Draft 2020-12 structural validation | automated unittest lane | LOCAL PASS |
| G1b | Cross-runtime strict wire parsing | Node 22 / CPython 3.13; 19 fixed vectors + 200 deterministic cases | LOCAL PASS for tested cases |
| G1c | Independent JS structural JSON Schema validator, schema compiler and fuzz | not implemented | OPEN |
| G2-Linux | real `SO_PEERCRED`, private AF_UNIX, absolute deadline, denied cross-UID baseline inherited | tested one Linux host / user | LOCAL PASS narrowly scoped |
| G2-Windows | current-user DACL, remote rejection, impersonation | source-only C++ probe, no Windows runtime | OPEN, NOT tested |
| G3 | verified real OS object handle/permission | no OS object adapter | OPEN |
| G4 | persistent receipt, uncertain effect, revocation and restart | in-memory only | OPEN |
| G5 | performance / platforms | one Linux AF_UNIX fixture benchmark | OPEN |
| G6 | independent security review, code signing, privacy release | none | OPEN |

## Scope of all test counts

Total test count includes parser, in-memory broker, real Linux socket tests and 2 **static Windows source guards**. These two are never security evidence for Windows itself. On Linux root, tests skip intentionally; root-only aggregate is not passing Linux G2 evidence.

## Correctness caveats

- Authenticated kernel UID is not signed app identity. Same-UID attack surface remains.
- Object-level ACL exists only in synthetic fixture; not a filesystem authorization result.
- In-memory replay cache evicts after 1024 requests and resets on restart; NOT replay protection for side effects.
- No privileged actions, remote transport, Android or iOS app support.
- No official production SLO or Windows security sign-off.
