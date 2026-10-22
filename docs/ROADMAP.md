# UDX Standalone roadmap (audited W5)

## Scope

Standalone core owns contracts, identity gates, policy and platform adapters. Digi is an optional downstream client and must not affect the standalone security boundary.

## Closed for the prototype

- Bounded and stricter I-JSON request and response parser.
- Contract-level runtime checks and Python/Node independent differential cases.
- Real unprivileged Linux AF_UNIX identity at OS UID granularity.
- Bounded local-worker concurrency, absolute request deadline, bounded diagnostic memory.
- Local synthetic object metadata with read-only per-subject fixture ACL, no OS object access.

## Unclosed, ordered gates

1. P0: formal model of app-versus-user identities; OS-enforced app isolation; deny same-UID impostors before any sensitive adapter.
2. P0: real Windows host CI, compile and test native probe, evented I/O with deadlines and client impersonation failure negative controls.
3. P1: Linux descriptor-anchored runtime and systemd process supervision; fair admission and per-principal budgets.
4. P1: Cross-runtime complete JSON Schema 2020-12 conformance; preserve fail-closed wire-specific rules.
5. P1: real OS read-only adapter with approved handles and object-level/property-level checks, especially TOCTOU.
6. P1: durable receipts, crash/restart faults and quarantined `UNCERTAIN` for all mutating actions, if later authorized.
7. P2: Windows/Linux cross-platform SDK, package signing/SBOM, update/recovery and privacy review.
8. P2: Android (Binder/permission model) and iOS (App Intents/companion) within actual OS restrictions.
9. P3: Digi connector and Nigin, Vero, CodeFactory cross-project adapter (separate and optional).

**Release condition:** production requires all corresponding G0–G6 gates in `W5_RELEASE_GATES.md` passed by independent, platform-appropriate evidence.

## W8 2026-10-09 – Incremental verified update

Research-only private `SCM_RIGHTS` handoff added via `udx_ref/fd_handoff.py` and `tools/demo_w8_fd_handoff.py`; public UDX fixture transport remains unchanged. G3 native FileChooser user consent remains BLOCKED; isolated Linux app identity, Windows runtime compilation and durable write journal remain BLOCKED. Refer to `docs/W8_AUDIT_IMPLEMENTATION.md` for evidence and next gates. The Linux trusted-host FD example deliberately does not accept arbitrary file paths or untrusted `approved=true` from an IPC client.

## W9 – completed on 2026-10-09 (research only)

- Added per-message kernel-credential private handoff and positive/negative distinct-UID run, plus fail-closed **shape parser** for FileChooser results.
- W9/G2 remains blocked pending independent production isolation; W9/G3 blocked pending actual D-Bus interaction in graphical sandbox and revocation trials. See `docs/W9_CRITICAL_AUDIT.md`.
- W10: authenticated portal app identity and lifecycle; user-visible consent, revoke, cancellation; harden supervised per-app worker; Windows compile and runtime security gates; persistent ledger before any side effects.

## W10 — 2026-10-09 (research only)

- Added internal-only SQLite WAL/FULL one-use grant journal and crash-uncertainty quarantine. Actual `SCM_RIGHTS` handoff is now guarded by persisted single-use claim through the private trusted-host wrapper.
- Added FileChooser Request correlation state machine; tests with injected bus metadata only, NO authenticated user session D-Bus interaction. Same-UID app isolation and genuine portal consent remain BLOCKED.
- Added real Cross-UID Linux demo, abrupt-crash recovery demo, tests and journal microbenchmark. Evidence in `docs/W10_CRITICAL_AUDIT.md`, `evidence/W10_*`.
- W11 priorities: live D-Bus/Flatpak integration with consent/revoke; supervised app isolation; Windows compiled probe; encrypted/retained journal + recovery adversarial tests. Digi optional; no GitHub writes.

## W18 — 2026-10-22 (research only)

- Closed the W14 instance-bit finding: every pipe ACE grants `0x12008b` (`FILE_GENERIC_READ | FILE_WRITE_DATA`) instead of GRGW, and clients open with the same mask. On the hosted runner, a further `CreateNamedPipeW` instance and a legacy `GENERIC_WRITE` open are refused, each with a W17 control in the same test. See `docs/W18_LEAST_PRIVILEGE_PIPE_ACL.md`.
- First MSVC build of `windows/*.cpp` (`/W4 /WX`) plus C++/Python cross-run in CI (`cpp-candidate`).
- Still open, in order: (1) local Windows 11 standard-account collector run on the W18 bytes; (2) second-account / AppContainer / Low-IL / service matrix; (3) UDX14-08 pre-start squatting (needs a server-identity/bootstrap design, not an ACL edit); (4) C++ overlapped I/O with deadlines (UDX14-04 remainder) or an explicit scope reduction to research-only; (5) UDX14-06 FD-handoff flake: not reproduced in W18 (0/25), keep under observation.
