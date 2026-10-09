# ADR-UDX-002 — Linux authenticated IPC research lane (2026-10-09)

Status: **PROPOSED**, not release-accepted.

## Decision

Continue standalone-first. An independent non-root Python process exposes exactly two read-only fixture actions via AF_UNIX SOCK_STREAM. The server derives identity from `getsockopt(SO_PEERCRED)` and maps to `uid:<numeric>`. Incoming wire never contains `subject`, `role`, `actor`, `consent` or `grant`. A schema-closed envelope, capability policy, and per-object owner check are required. The server accepts only a pre-created 0700 directory with an exclusively created 0600 socket, refuses stale path replacement, uses a length-prefixed 4-byte network-order frame (up to 4096 bytes), one request per connection and one-second timeouts.

## Scope / claims

- This **demonstrates actual kernel-supplied UID attribution** between separate Linux processes; it does not implement app-level authentication, a general OS adapter or authorization to system objects.
- Read-only test objects only. All principal authorization is confined to the same UID. Real user's objects, policies and processes remain untouched.
- Windows development is separated into a future named-pipe adapter with restricted DACL, local-only flag and verified client token/impersonation behavior, not “ported” by changing the socket name.
- Android and iOS remain future limited-privilege companions.

## Known negative/control cases

- Unknown capability, fake actor, extra grant fields, invalid JSON/UTF-8, oversized declared frame, traversal object ID, duplicate keys, stale request id.
- Symlinked runtime directory, non-0700 directory, preexisting socket path, fragmented stream frames, truncated stream, clean bounded shutdown.

## Threats and non-claims

- UID equivalence is not human authentication, device attestation or app identity. A process belonging to the same Linux UID can call the service and receives the same fixture access.
- No persistence, reboot rollback, cross-uid policy management, TLS, multi-device federation or workspaces.
- Directory ownership/mode checks are not a proof against an attacker controlling all processes of the UID or the namespace.
- Runtime directory stale socket after abnormal termination => operator-driven cleanup only; never blind unlink.
- JSON Schema validation is not a replacement for raw-byte parser checks, and JSON Schema cannot model file permissions or `SO_PEERCRED`.
- Due to single-thread service and 1-second timeout, DoS against a local session is still possible. Needs accept queue/work budget gate before real use.

## Sources and justification

- man7 unix(7): `SO_PEERCRED` credentials at connection time; Linux-specific.
- JSON Schema Draft 2020-12: validation vocabulary, closed properties, conditionals.
- Microsoft named-pipe security: default security descriptor is overly broad for a privileged broker.
- NIST SP 800-218 v1.1: reproducible verification and secure development discipline; v1.2 is a draft, not a finished standard.

## Deferred ADRs

- 003: durable transaction/outcome state machine for mutating OS operations.
- 004: native Windows server ACL/impersonation, packaging/signatures and user consent.
- 005: privilege separation, app identity and plugin isolation; reject same-UID confusion.
