# UDX W0-W11 Cross-Wave Technical Audit — 2026-10-09

**Scope**: Review of the UDX/UHAL dialogue and reproducible W10 source inheritance. Source-of-truth for executed W11 work is the unpacked W10 archive plus locally patched W11 revision. External vendor docs cited below. No claim of auditing the full 60+ other project lines.

## Evidence ladder and retrospective, W0–W10

- W0–W1 proposed universal agent/OS mediator; conceptual only. Correction: no universal privileged kernel driver, app-only mobile abilities; standalone broker, agent optional.
- W2 research in-memory protocol; earlier self-reported 33 tests. Not an OS-IPC or OS-security proof.
- W3 unprivileged Linux IPC via SO_PEERCRED; earlier 50 tests. Peer UID identifies account, NOT application.
- W4 JSON/Node parser parity, absolute IPC deadline; 55 tests, Windows C++ source candidate only, NOT compiled on Windows.
- W5 bounded threaded broker, client response scope and I-JSON; 68 tests. Per-request overhead rose; positive single benchmark cannot establish SLO.
- W6 consent dry-run, tile hashing, simulated frame leases and host-approved read-only FDs; 96 tests; no native interactive consent.
- W7 type-bound grant fixes, stability detection and sealed test snapshots; 110 tests; no source-file atomic-snapshot guarantee.
- W8 private SCM_RIGHTS read-only FD handoff; 126 tests; file selection not authorized by OS.
- W9 per-message SCM_CREDENTIALS cross-UID research; 142 tests; no production same-UID sandbox and portal.
- W10 SQLite WAL/FULL durable one-use grant journal, crash quarantine and simulated portal correlation; 173 tests; power loss, tamper and portal consent unproved.
- W11: reproduced `PortalRequest` invalid monotonic-clock NaN leading to acceptance; patched clock finite/monotonic checks and same-SQLite-connection reentrant transaction serialization; 10 new targeted tests, 183 total on unprivileged Linux; no skips. Security gates remain BLOCKED.

**Warning**: Test totals are CUMULATIVE across waves and do not imply fully independent test suites or coverage; exact prior history is documented from archived evidence and messages, not all prior phases independently re-run now. The W11 suite is rerun from inherited code and the fresh package.

## Falsification / patch details

**W11-01 (P1): invalid clock permits false accept**. Previous `PortalRequest.receive` performed `self._clock() > deadline`; IEEE NaN made comparison false, so an otherwise well-formed simulated portal result was accepted. Demonstrated before patch; after patch, invalid/negative/bool/nonfinite clock rejected, monotonic rollback rejected, exact deadline rejected; all failures terminal to `REJECTED` or `EXPIRED`. This tests a trusted-injected *simulation clock*, not real D-Bus consent.

**W11-02 (P1 defense): same SQLite connection across threads**. `sqlite3.connect(check_same_thread=False)` permits cross-thread use but does not provide per-business-transaction serialization. The `_tx` context now holds a per-instance RLock from BEGIN IMMEDIATE through COMMIT/ROLLBACK. `state()` and `close()` are covered by same lock. Test: 12 threads claim one grant on the SAME DurableGrantStore instance; exactly one succeeds, 11 are denied. This does not make multi-process filesystem/DB access tamper proof.

## Persistent open critical gates

1. G3 BLOCKED: live GUI XDG FileChooser+Documents Portal selection, authenticated D-Bus owner lookup, sender identity, cancellation, revocation, persistence and session restoration. Existing `portal_request.py` validates only injected metadata.
2. G2 BLOCKED: a real deployment supervisor and application identity distinct from a UID. Linux same-UID processes and malicious host remain able to interfere with privately owned journal/IPC. Kernel-backed per-app sandbox policy and negative controls must be independently run.
3. G4 BLOCKED: SQLite DB/WAL/SHM lifecycle, backup corruption, storage encryption decision, schema migration, data-retention and deletion/forensic recoverability, genuine sudden power loss. SQLite FULL does NOT provide cryptographic tamper evidence.
4. G3 BLOCKED: revocation CANNOT retroactively recall transferred FDs or data copies. `INFLIGHT` revoke only refuses an assertion of completed status. Need recipient lifecycle/cancellation design and explicit data minimization.
5. G3 BLOCKED: stable POSIX source properties are not an atomic file snapshot. Linux sealed memfd only seals the copied buffer after snapshot attempt; concurrency remains.
6. G2 Windows BLOCKED: no native compile or Win32 DACL/impersonation failure/overlapped I/O runtime tests.
7. G5 BLOCKED: no Apple/Android native integration, no GPU zero-copy proof, no production real-time performance/SLO, no independent third-party security audit. The mobile OS does not promise unbounded systemwide programmatic control.
8. G6 BLOCKED: no audited key hierarchy, update signing, supply-chain SBOM, external timestamped witness, or user-facing audit controls. No production certification.

## Controls and formulas

- **Authorization release invariant**: `EXECUTE = PEER_OS_VERIFIED ∧ APP_ISOLATED ∧ CAPABILITY_SCOPED ∧ CURRENT_USER_CONSENT ∧ VALID_GRANT ∧ NOT_REVOKED ∧ RESOURCE_FD_MATCH ∧ AUDIT_DURABLE`. A missing unknown operand is FALSE (fail-closed). In today's test environment, USER_CONSENT=not verified and APP_ISOLATED=not verified, hence EXECUTE=FALSE for sensitive production actions.
- **Temporal invariant**: `finite(t) ∧ finite(deadline) ∧ t >= previous_t ∧ t < deadline`. Never accept NaN, infinity, boolean or regressing monotonic timestamps.
- **Replay invariant**: `∀ grant g: successful_claims(g) <= 1`; use a durable unique request ID and atomic claim before FD handoff. A crash after claim yields QUARANTINED, not auto-retry.
- **Durability**: `SQLite WAL + synchronous=FULL` only within storage/VFS guarantees. Correlate fsync faults with actual machine power-cut emulation before release.
- **Latency**: `L_total = L_auth + L_journal + L_IPC + L_nativeOS + L_response` as an *event-level* decomposition. Do not add p95s and represent the sum as p95 of total; instead time each complete end-to-end event.
- **Quality metrics**: `test_pass_rate = passes / executed`; report skips separately; `failure_rate = failures / total_requests`; observed latency `p99` only for a specified hardware/software workload and confidence interval.

## PR / NR / reusable CodeFactory

PR (positive requirements): versioned bounded parser, kernel-verified IPC identity, OS-backed app isolation, per-resource grant, persisted one-use journal before handoff, deterministic state machine, trusted clock validation, negative fixtures, exact-version hash provenance.
NR (negative requirements): no caller-supplied identity or consent flags; no public file-path capability; no automatic retry after uncertain transfer; no unverifiable Windows/iOS claims; no trust escalation from JSON; no storing raw screenshot/audio/secret as diagnostic proof; no release claim from green unit tests alone.

Reusable candidates (DO NOT automatically promote): `CF-UDX-FINITE-MONOTONIC-CLOCK-11`, `CF-UDX-SERIALIZED-SQLITE-TRANSACTIONS-11`, `CF-UDX-ONEUSE-UNCERTAIN-10`, `CF-UDX-PORTAL-PROVENANCE-10`, `CF-UDX-BOUNDED-FD-READ-08`, `CF-UDX-INTEROP-IJSON-04`, each with attached negative test, OS scope and claim ceiling. Transfer patterns, not project-specific trust roots or latency claims.

## Compliance registry candidate (Swiss context requires separate legal review)

- UDX-DP-01 Identity & scope: UID/app/client metadata potential person data; purpose limitation, access controls, PII inventory, processor/roles TBC.
- UDX-DP-02 Journal: timestamps, inode/dev/UID and hashes are potentially linkable. Retention schedule, WAL, backups, access logging, access/deletion workflows TBC.
- UDX-DP-03 Consent: UX evidence, actual OS dialogue, differentiated withdrawal vs transfer already performed. Consent is not always the sole legal basis; needs legal classification.
- UDX-DP-04 Cross-device: no remote transfer today; future recipient country and encryption/key lifecycle review before activation.
- UDX-DP-05 Security: immutable independent audit witness/incident response/deletion from backups, not implemented.
- UDX-DP-06 Supply chain: signed releases, reproducibility, SBOM, dependency inventory and update rollback.
- UDX-DP-07 Research telemetry: frames/visual hints can be personal and special-sensitive data; explicit minimal capture, masking and expiry.
- UDX-DP-08 User/app isolation: same-UID attackers and physical backups excluded from approved operating context until validated.

These are **open compliance entries** not legal compliance attestations. Swiss FADP/DSG and any cantonal requirements need a case-specific assessment.

## Sources (independent external verification)

- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html
- https://www.sqlite.org/howtocorrupt.html
- https://www.sqlite.org/pragma.html
- https://github.com/OWASP/ASVS/blob/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json
- https://man7.org/linux/man-pages/man7/unix.7.html

## Next acceptance plan (ordered, not declared complete)

1. First create a local disposable Flatpak sandbox and desktop DBus test host on a real GUI runner; assert cancel/yes/no; verify sender's bus identity from library metadata and portal owner changes; revoke after FD and prove existing copy persists.
2. Linux supervised per-application process identity and no inherited extraneous FD, capped worker group and fair admission; malicious same-UID negative test.
3. Journal controlled retention + schema migrations, backup/restore with all WAL files, read-only integrity check and fault injection (`fsync`, ENOSPC, forced exit) under a standalone test harness.
4. Run Windows named-pipe candidate in an actual Windows CI machine with locked-down ACL and denied impersonation; collect signed binaries and independent results.
5. Only after G2/G3/G4 evidence: bounded real OS read-only adapter; then Android/iOS companions, as allowed by platform; Digi optional connector afterward.
