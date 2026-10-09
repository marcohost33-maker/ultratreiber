# ADR-UDX-005 (W7) — Trusted Observations, Strict Preview, Immutable Copy
Status: ACCEPTED FOR RESEARCH ONLY; NOT a production security acceptance.

## Decision
1. Treat all preview proposals as untrusted structured input; validate exact types before equality/comparison. In Python, `bool` and `int` MUST not be interchangeable at the security boundary.
2. Treat any positive frame tile-change as a reset of consecutive quiet observations. `STABLE_HEURISTIC` is a perception signal and never direct authorization for OS effects.
3. Use a per-instance keyed tile fingerprint, rotated on reset, to reduce passive cross-session correlation; it does not make image metadata public-safe.
4. For host-approved reads of untrusted mutable regular files, prefer a copy-on-approval; on Linux, kernel-seal a bounded anonymous `memfd` before publishing the copy. Reject unsupported platforms. Never claim source-level atomicity from paired reads and stat checks.
5. Preserve the existing v0.6 IPC surface; do not expose new capabilities to clients prior to trusted user mediation and app identity.

## Consequences
- Status vocabulary gains `LOW_CHANGE`; downstream clients must reject unknown states until an explicit versioned contract exists.
- In-process processing incurs additional type, lock and keyed-digest costs; local benchmark in W7 evidence, not an OS latency budget.
- Sealed snapshot buffers consume up to 64 KiB per live object plus existing data, and require bounded simultaneous grant count; storage is short-lived and host-only.
- No assumption that arbitrary same-UID processes are different principals.
