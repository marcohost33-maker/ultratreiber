# ADR-UDX-003 — Strict interoperable wire semantics and absolute deadlines
**Date:** 2026-10-09. **State:** accepted for W4 research candidate, not production.

## Decision

- The existing `udx/0.1` envelope stays stable; no new OS privileges or mutating capabilities.
- Wire JSON is checked for unique keys *after JSON escape decoding* (RFC 7493), canonical UTF-8, no unpaired surrogate values, integer numbers only in exact portable range [-9007199254740991, 9007199254740991]. Float syntax remains forbidden by the earlier parser contract.
- Recursive nesting is limited to 16 (including dictionary keys as scalar visits); byte budget 4096. These are wire rules beyond a structural JSON Schema 2020-12 validator.
- The Node.js implementation is independent of the Python decoder (own lexical scanner, Node JSON.parse after scanning, TextDecoder fatal UTF-8). Parser parity is checked with 19 manually fixed golden vectors and 200 seeded mutations. This is NOT full schema-engine parity.
- A Linux connection has one absolute 1-second deadline measured with `time.monotonic()`, not renewed for every new byte. The serial service remains vulnerable to queue exhaustion and same-UID denial-of-service under sustained connections. This mitigation is bounded work, not DoS resistance certification.

## Rejected alternatives

- JSON.parse alone in Node: duplicate object keys collapse silently.
- Per-recv timeout without absolute deadline: one-byte trickle resets it.
- Schema-only validation: cannot prove unique JSON member names or input byte constraints.
- Disallowing all unknown capabilities in structural parser: capability dispatch remains a separate fail-closed broker task and can support negotiation later.

## Gates

`G1-parser` locally demonstrated in two runtimes; `G1-complete` remains OPEN pending full second-language schema validation and CI across actual environments. `G2-Linux-limited` locally demonstrated; `G2-Windows` OPEN. Neither proves isolated applications of the same UID.

## Sources

- RFC 7493 I-JSON: https://www.rfc-editor.org/rfc/rfc7493
- RFC 8259 JSON: https://www.rfc-editor.org/rfc/rfc8259
- JSON Schema 2020-12: https://json-schema.org/specification
