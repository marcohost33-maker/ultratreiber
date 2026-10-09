# W9 – Cross-UID Credentialed FD Transfer / Critical Audit

Date: 2026-10-09. Status: standalone Linux security research candidate, **NO PRODUCTION RELEASE**.

## Scope and inherited baseline

W8's private `SOCK_SEQPACKET` + `SCM_RIGHTS` transfer verified one FD but used `SO_PEERCRED`. On socketpairs created by the launcher, this can identify the creator at pair creation instead of the process that later sends a message. W8 also did not verify response *sender* via message credentials. Source authorization still depends on a trusted pre-opener; no GUI portal exists in the executable chain.

## W9 implementation

- `udx_ref/credentialed_handoff.py`: private, unaddressed `socketpair`; enables `SO_PASSCRED` on both ends; receives required `SCM_CREDENTIALS` on each packet, compares actual UID to expected host/worker role; rejects wrong/missing/multiple credentials, unexpected ancillary messages, extra/missing FDs, truncated control/data, invalid structured messages, wrong request ID and response-size/hash violations. Closes any received descriptors on every rejected packet.
- Security property: message-time credentials are kernel-checked (Linux `unix(7)`), not untrusted JSON and not merely `SO_PEERCRED`. **Root and processes retaining CAP_SETUID/CAP_SYS_ADMIN are outside this identity-assurance claim**; UID alone still cannot distinguish same-UID applications.
- `tools/demo_w9_cross_uid.py`: root-assisted *disposable lab launcher* starts **two non-root processes under distinct UIDs** (`oai` UID 1000; `nobody` UID 65534 in THIS environment). Worker has no DAC read permission on the 0600 fixture but handles the transferred FD; kernel-provided sender+responder credentials checked both ways. Negative run proves forged `uid` JSON from wrong UID is rejected. Root launcher is NOT deployable as a privileged service.
- `udx_ref/portal_boundary.py`: only parses a subset of XDG FileChooser response structure, rejects cancellation, unexpected keys, writable, multiple/non-local/unsafe URI. **No D-Bus call, no authenticated portal response, no application identity, no consent proof and no file open.** This parser MUST NEVER be callable as a grant authority by public clients.
- The **public UDX IPC still only has synthetic test data**, no user-selected file operations or device controls.

## Evidence and falsification

- Non-root (`oai`) `python -m unittest discover -s tests -v`: **142 passed, 0 skipped**, 16 newly added unit tests relative to 126 in W8. `evidence/W9_NONROOT_TESTS.log`.
- Real distinct-UID IPC positive+negative: `tools/demo_w9_cross_uid.py` invoked in isolated lab; success including DAC-denied direct path access and forged-message rejection. `evidence/W9_CROSS_UID_DEMO.json`. This exercise requires root **only as a test harness to spawn two unprivileged roles**, not for UDX operations.
- 5 alternating rounds × 250 operations for *each* of W8 and W9, 4KiB file, same nonroot user; in-process, creates sockets, transfers FD, hashes sealed content, verifies response. Baseline/results in `evidence/W9_PAIRED_BENCH.json`. Results depend on host scheduling and load; not a deployment SLO.
- Negative testing: wrong host UID, wrong worker UID, PASSCRED disabled, missing or too-many FDs, oversized messages, wrong response/request ID, forged identity field, response FD injection, repeated FD-leak check, portal canceled/unsafe URI/multiple/writable.

## Critical remaining gaps (BLOCK RELEASE)

1. **G2 not closed end-to-end**: distinct-UID demonstration proves OS DAC separation in one fixture but does not prove a production sandbox (no AppArmor/SELinux/Flatpak/bubblewrap confinement, no production supervisor lifecycle/FD-leak/PID/race attestation). The inherited private channel is a capability; its leakage is fatal. Separate UIDs on the chosen hosts still need real deployment and independent review.
2. **G3 not closed**: XDG FileChooser/Document Portal integration is NOT implemented or GUI-tested; response parser cannot authenticate a D-Bus sender or establish a user grant. FileChooser result may be a `file://` URI and persist via Documents Portal; per-app permissions and RevokePermissions semantics are separate.
3. **Revocation cannot recall data**: once a trusted host passes a descriptor or copies data into sealed memfd, a later Documents Portal revocation cannot retroactively erase existing process-memory copies. Minimize retention; design scoped lifetimes, cancellation before handoff, and explicit deletion of local copies. Any guarantee of deleting already transmitted bytes would be false.
4. **TOCTOU source**: W8/W9's double read+fstat checks reduce but cannot eliminate concurrent in-place writer races; snapshot is immutable only after the copy is sealed. Avoid promising an atomic source snapshot.
5. **Private data**: returned `sha256` and `size` can fingerprint known contents. Use authorized scopes, data minimization, and short retention; no hash logs in public channels.
6. **Windows remains source-only**: existing Named Pipe probe not compiled/run on Windows; no mobile driver capability verified. Digi integration optional and not performed.
7. **No persistent ledger**: replay/commit/recovery for actions with side effects remains G4 open. This module is read-only metadata and does not grant OS mutation.

## Next sequence (W10)

- Real desktop session/Flatpak: authenticate D-Bus portal provenance, use `FileChooser.OpenFile` + `Request.Response` and app-specific Documents Portal access, test cancel/deny/revoke & file replacement. Explicit choice of ephemeral vs persistent access.
- Production Linux sandbox: per-app identities under a supervised non-root launcher with closed file descriptor table and process credentials; restrict exec, FS, network; verify namespace/LSM behaviors on supported distros.
- Native Windows CI with MSVC security checks and cross-identity negatives; durable journal before any mutation.
- Independent audit, fuzzing, supply-chain verification, deterministic repeatable benchmarks under load.

## Official sources
- https://man7.org/linux/man-pages/man7/unix.7.html – `SO_PASSCRED`, `SCM_CREDENTIALS`, `SO_PEERCRED`, `SCM_RIGHTS`.
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html – FileChooser selection and persistence.
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html – application-scoped exports and grant/revoke.
- https://man7.org/linux/man-pages/man2/openat2.2.html – future path resolution if a real portal URI requires opening a path.

No GitHub writes. CodeFactory/Compliance transfer candidates are NOT authoritative matrix changes.
