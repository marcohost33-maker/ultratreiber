# UDX W10 — Durable one-use grant and portal response correlation
Date: 2026-10-09. Research-only. G2/G3/G4 release gates OPEN.

## What has been implemented and reproduced
- `udx_ref/durable_grants.py`: internal-only SQLite WAL+FULL journal; private 0700 parent, 0600 DB, reject symlink/hardlink/world-readable path; trusted-host issuance of a single-use, UID-, inode-, metadata-, TTL-, and UUID-bound *test* grant. `BEGIN IMMEDIATE` atomic claim, unique `request_id`, wall-clock rollback refusal; explicit recovery of in-flight work to `QUARANTINED`. Source file **is** read via a read-only descriptor for bounded observation and does **not** prove atomicity against concurrent writers.
- `udx_ref/authorized_handoff.py`: private trusted-host wrapper commits the one-use claim *before* `SCM_RIGHTS` transmission and verifies kernel-credentialed response before marking COMPLETED. On a known failure/timeout the item is quarantined. It does NOT authenticate user approval.
- `udx_ref/portal_request.py`: asynchronous FileChooser Request state machine validating unique D-Bus sender ID, guessed handle token, result path, deadline, cancellation and exactly-once Response. Caller MUST obtain D-Bus sender and owner from the actual authenticated D-Bus transport; these are just strings in this research module. Return URI is not consent proof or a resource handle. Old portal installations may return a non-expected handle; W10 rejects these rather than implementing legacy handle re-subscription.
- `tools/demo_w10_cross_uid.py`: real Linux root-assisted disposable TEST launcher spawns unprivileged, distinct-UID worker and host. Host issues journal-backed grant, commits before sending a FD and verifies the reply; worker cannot open private source by path. Negative tests forgery, journal replay and reopening. Test launcher as root MUST NOT be deployed as an OS service.
- `tools/demo_w10_crash_recovery.py`: OS process exits abruptly *after claim* and before completion; journal reopens, quarantines and refuses replay. This is process crash research, not power loss simulation.
- Additional tests in `tests/test_w10_grants_portal.py` exercise types, expiry, clock rollback, atomic multi-connection claim race, changed file scope, cancellation, forged portal metadata, timeouts, duplicate response and a successful private FD roundtrip.

## Concrete red/green finding
The first W10 expiry path changed ISSUED -> EXPIRED inside SQLite then raised an exception while the transaction manager rolled the state update back. Revised to finish the transaction before raising; verified that EXPIRED remains durable. Also explicitly declared `request_id UNIQUE` and tested that two grants cannot use the same request identifier.

## Security boundaries: NOT resolved
1. A true FileChooser GUI selection, authenticated `org.freedesktop.portal.Desktop` D-Bus connection, persistent Documents Portal grant and genuine revoke/cancel remain UNTESTED. The current test machine has no reachable user session bus and no `dbus-next`/GI implementation. No claim of real OS user consent.
2. The journal can only be used by a trustworthy host in a protected execution context. Other programs with the SAME UID can still tamper with database or host IPC; a private SQLite directory alone is not same-UID isolation. Tests using distinct UIDs do not close all production sandbox deployment risks.
3. Already transferred FDs and data copies cannot be retroactively recalled after revocation. A revoke after INFLIGHT records `REVOKED_INFLIGHT` and the completion path refuses to assert success; worker-produced data might already exist.
4. SQLite WAL+FULL is durable when the underlying filesystem implements sync honestly; not a cryptographically anchored, append-only, tamper-proof ledger. The test only covers process interruption, not whole-system loss/power cutoff. SQL schema migrations and retention policies required.
5. Source owner/inode/size/mtime/ctime metadata do not guarantee an atomic file snapshot. Owner restriction is narrower than portal-mediated files owned by other UIDs. TOCTOU remains open.
6. The existing W9 private socket deadlines are short; creating a grant involves synchronous disk operations. In one W10 Cross-UID demo run the reply exceeded the inherited 2-second research timeout. The demo alone sets 12 seconds to assess security correctness; the production timeout/queue design needs independent benchmarking and budgets.
7. No Windows native compile/run; no Android/iOS driver; no Digi link; no unrestricted input or file operations.
8. File owner UID, inode, size, timestamps, receipt IDs and request IDs in the journal are metadata about user-selected resources; impose purpose limitation, retention and secure deletion (including WAL/checkpoints) before release. Neither unlinking nor a SQLite DELETE can ensure removal from all backups or media.

## Source-of-truth / best practices (verified official documentation)
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html — pre-subscribe by handle_token, handle check, Close does not yield Response.
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html — real selection and persistence across sessions.
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Documents.html — app-scoped FUSE document access, GrantPermissions and RevokePermissions with constraints.
- https://www.sqlite.org/wal.html — WAL/checkpoint constraints.
- https://sqlite.org/pragma.html — FULL synchronous and power-loss durability expectations.
- https://man7.org/linux/man-pages/man7/unix.7.html — SCM_RIGHTS, SCM_CREDENTIALS and kernel identity semantics.

## W11 gates
- G3: GUI/Flatpak under real desktop; D-Bus owner/bus provenance, request token and handle, cancellation, file selection, document export/revoke; verify rejected reinstatement and FD survival semantics.
- G2: per-application sandbox lifecycle, credential-bound worker spawn under supervisor, FD inheritance audits, containment (LSM/namespace), same-UID attacker test.
- G4: journal encryption-at-rest decision, backups and purge policy, schema migration, cross-process power-fault test, external witness for tamper evidence.
- G2 Windows: compile source under Windows MSVC, test DACL, impersonation negative, overlapped I/O and timeouts.
- G5: paired sustained realistic benchmark incl. durable fsync, GUI/session broker and app isolation, CPU/memory and tail latency; no invented SLO.

No modifications of GitHub or upstream projects. Digi remains optional.
