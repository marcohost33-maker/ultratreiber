# UDX reusable CodeFactory patterns (candidate, no global import)

- **CF-UDX-FRAME-BOUNDS-v1**: 4-byte network-order length; byte cap before allocating or parsing body; malformed/truncated connection never executes an operation. Negative tests oversized advertised length without body, partial header, partial body, odd UTF-8.
- **CF-UDX-OS-PEER-v1**: authenticated UID via kernel SO_PEERCRED on connected AF_UNIX only; refuse missing/invalid OS credentials; sender JSON fields never grant privileges. Limit: UID != application identity.
- **CF-UDX-PRIVATE-ENDPOINT-v1**: owner-controlled 0700 runtime dir, new 0600 socket; refuse unknown existing path; no path-based socket takeover; bounded shutdown checks inode before unlink. Limit: abnormal kill leaves stale socket.
- **CF-UDX-CONTRACT-PARITY-v1**: JSON Schema 2020-12 + golden request/response vectors with negative oracle; ensure required conformance dependency is installed. JSON Schema alone cannot distinguish repeated key pairs.
- **CF-UDX-REPLAY-SCOPE-v1**: process-local bounded replay controls only a read-only proof; never use as a durable exactly-once guarantee.

Transfer rule: copy only after matching trust boundaries and a named owner verifies independent implementation plus tests; no automatic promotion into CodeFactory runtime.
