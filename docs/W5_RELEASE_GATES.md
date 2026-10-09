# W5 Gate review — Fail closed

**RESEARCH CANDIDATE — NO PRODUCTION RELEASE.**

| Gate | Minimum evidence | Measured | Decision |
|---|---|---|---|
| G0 Package integrity | clean extraction + manifest verification + complete nonroot suite | See `SHA256SUMS`, independent extraction log | LOCAL PASS |
| G1 Python/Node wire parity | golden + byte fuzz (at least 1,200) + 2020-12 schema lane | 22 golden, 200 structured mutations, 1,200 byte mutations; JS full schema engine absent | PARTIAL |
| G2-Linux UID transport | `SO_PEERCRED`, 0700 runtime, 0600 socket, deadlines and bounded workers | Linux nonroot tests, cross-UID previous lane | NARROW LOCAL PASS |
| G2-App security | OS-enforced *application* identity for same UID | none | FAIL/OPEN |
| G2-Windows | MSVC compile, Windows real-user tests, bounded overlapped I/O, SID and remote denial | source-only files | FAIL/OPEN |
| G3 OS object authorization | real OS handles, no path substitution, per-object and per-property ACL | fixture objects only | FAIL/OPEN |
| G4 Durability | persistent receipts/ledger, restart and crash fault injection, signed policy provenance | volatile deque/cache only | FAIL/OPEN |
| G5 Latency/DoS | queue fairness, admission budget, sustained and burst benchmark, reproducible SLO | 3 paired local trials, worker saturation test | FAIL/OPEN |
| G6 Independent review | signed artifacts, security audit, SBOM, update chain, privacy assessments | not performed | FAIL/OPEN |

### Priority roadmap W6–W8

W6 P0: choose explicit threat model and principal isolation (one OS user per tenant or supervisor-controlled sandbox/app container), with app-grants bound to OS-enforced identity. Implement and fault-inject Windows overlapped timeouts in a real Windows CI runner; no Windows release claim without compile and adversarial OS tests.

W6 P1: make Linux service externally supervised (systemd user service with restricted unit/RuntimeDirectory, restart policy and no privilege), rate/connection quotas and structured nonsecret telemetry. Test race-resistant socket directory descriptor anchoring; same-UID adversaries remain out-of-model until isolation is designed.

W7: implement approved-resource `read-only` OS handle adapter, with user-mediated selection and checks at use time (TOCTOU; no arbitrary paths). Add per-property response whitelist, strict resource budgets, replay persistence only if mutating operations are introduced.

W8: persistent transactional action ledger + exactly-defined `UNCERTAIN` crash recovery model, second-language Schema 2020-12 validator, Rust portability assessment, Android/iOS user-consented companion bounds, and optional separate Digi/Nigin adapters. Independent security review before any release.

Any `FAIL/OPEN` means not deployable as a general OS broker.
