# UDX reusable CodeFactory patterns (candidate, no global import)

- **CF-UDX-FRAME-BOUNDS-v1**: 4-byte network-order length; byte cap before allocating or parsing body; malformed/truncated connection never executes an operation. Negative tests oversized advertised length without body, partial header, partial body, odd UTF-8.
- **CF-UDX-OS-PEER-v1**: authenticated UID via kernel SO_PEERCRED on connected AF_UNIX only; refuse missing/invalid OS credentials; sender JSON fields never grant privileges. Limit: UID != application identity.
- **CF-UDX-PRIVATE-ENDPOINT-v1**: owner-controlled 0700 runtime dir, new 0600 socket; refuse unknown existing path; no path-based socket takeover; bounded shutdown checks inode before unlink. Limit: abnormal kill leaves stale socket.
- **CF-UDX-CONTRACT-PARITY-v1**: JSON Schema 2020-12 + golden request/response vectors with negative oracle; ensure required conformance dependency is installed. JSON Schema alone cannot distinguish repeated key pairs.
- **CF-UDX-REPLAY-SCOPE-v1**: process-local bounded replay controls only a read-only proof; never use as a durable exactly-once guarantee.

- **CF-UDX-DK-RUNNER-v1** (W26.1): discriminating mutations are evidence only if reproducible: mutate a private copy, never the checkout; no bytecode cache (`-B`, `PYTHONDONTWRITEBYTECODE`; `.pyc` is validated by mtime seconds + size); byte I/O (no CRLF translation); anchor exactly once (stale = finding, not skip); baseline green and not skipped; a timeout or skip is never a kill; spec paths confined to the copy. Limit: a kill by a source-text pin proves the pin, not the runtime behaviour.
- **CF-UDX-IL-EQUALITY-v1** (W26): a local IPC client accepts an endpoint only if its mandatory label EQUALS the client's own effective integrity level (after the owner check). Rationale: a lower-level squatter can copy owner, DACL and its own label, so only the level separates it; higher labels are already refused at open by the token's NO_WRITE_UP policy. Limit: needs the default token mandatory policy; no server authentication (G2-App).

Transfer rule: copy only after matching trust boundaries and a named owner verifies independent implementation plus tests; no automatic promotion into CodeFactory runtime.
