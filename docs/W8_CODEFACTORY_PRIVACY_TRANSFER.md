# W8 Reusable Patterns and Privacy Compliance Candidates

CodeFactory **candidates only**, not directly imported to central CodeFactory assets:

- `CF-UDX-W8-EXACT-ONE-SCM-RIGHTS`: single-purpose descriptor transfer, strict ancillary parsing, `MSG_CTRUNC` fail-closed and verified descriptor closure.
- `CF-UDX-W8-PRIVATE-CAPABILITY-CHANNEL`: private `SOCK_SEQPACKET` pair; open FD is an *object capability*, **not** evidence of independent user approval.
- `CF-UDX-W8-BOUND-RESPONSE`: request-ID-binding and response schema strictness; no raw file bytes by default.
- `CF-UDX-W8-CONSTRAINED-READ`: read-only `fstat`-bounded source FD -> `SealedSnapshot`, with explicit non-atomic source warning.

Compliance **candidates**, not updates to authoritative privacy matrix:

- `UDX-DP-W8-01`: SHA-256 of small predictable files and size are potentially identifying; retention and visibility minimization.
- `UDX-DP-W8-02`: Portal-granted files may remain accessible across sessions; consent revocation is not equivalent to deleting transferred copies.
- `UDX-DP-W8-03`: trusted selector must not accept client-reported `approved=true` or forward arbitrary user-supplied path as consent proof.
- `UDX-DP-W8-04`: `memfd` seals protect write integrity, not confidentiality; peer or proc permissions need separate hardening.
- `UDX-DP-W8-05`: no UID-to-app identity equivalence; preserve trust-boundary split and smallest necessary privileges.

Learning statistics – **verifiable local deltas only**: W7 110 tests -> W8 126 tests (+16); 1 new descriptor IPC transport research module; 1 separate-process demo; no Windows/Android/iOS or FileChooser HIL validation. Evidence file checksums and benchmark stored separately.
