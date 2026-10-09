# W11 release gate ledger

- **G0 local protocol/test baseline:** W11 research test PASS 183/183 unprivileged Linux (excluding real GUI and Windows).
- **G1 cross-language:** 2026-10-09 inherited bounded fixture parity only, no complete JSON Schema 2020-12 conformance.
- **G2 application identity:** BLOCKED. OS UID != strong app isolation; Windows not compiled.
- **G3 current-user consent/revocation:** BLOCKED. PortalRequest is injected metadata simulation, no real DBus.
- **G4 persistence:** RESEARCH ONLY; SQLite WAL/FULL no cryptographic assurance, no power-cut proof.
- **G5 performance:** BLOCKED; microbench cannot substitute real GUI+IPC+OS and varied workloads.
- **G6 privacy/security and release:** BLOCKED; no signed production package, audit or legal assessment.

Prohibit public write/mouse/keyboard/capture operations until relevant gates are evidenced. Digi remains optional.
