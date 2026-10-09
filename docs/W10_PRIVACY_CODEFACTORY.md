# W10 CodeFactory & privacy candidates — evidence-scoped (not imported to authoritative matrices)

CF-UDX-W10-01: WAL+FULL one-use grant with transactional state transitions: issue -> inflight -> completed OR quarantine/revoked. Only internal trusted host may create or consume. Tests: replay, crash, race.
CF-UDX-W10-02: independent portal-response correlation with owner unique name, request handle, nonce/token, deadline, cancellation and duplicate-response rejection; live D-Bus integration missing.
CF-UDX-W10-03: trusted-host wrapper commits before FD handoff; validates reply; any incomplete receipt -> quarantine, never retry silently.
CF-UDX-W10-04: source descriptor anchored only in trusted host; no path in untrusted IPC, bound owner/inode/size/timestamps; still NOT atomic snapshot.

Compliance candidates for review, not inserted into central matrix:
DP-UDX-W10-01: Data minimization: journal stores owner UID, worker UID, inode/device/size/times and random receipt ID; avoid storing file path/content/hash in this table.
DP-UDX-W10-02: Consent provenance: only D-Bus portal reply from trusted transport; never client-controlled Boolean, unique name string or URI alone.
DP-UDX-W10-03: Cancel/revoke: distinguish pre-transfer prevention, in-flight UNCERTAIN, post-copy impossibility of recall.
DP-UDX-W10-04: Retention: TTL of admission <=300 sec but database rows persist until controlled purge. Need retention policy, secure-at-rest, backup rules and migration.
DP-UDX-W10-05: Avoid privilege escalation: do not expose internal issuance/revoke methods to untrusted network/UDX clients; OS broker must verify actor.
