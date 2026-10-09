# W9 transfer candidates: reuse and compliance (not approved)

## CodeFactory
- `CF-UDX-W9-CREDS-01`: per-message kernel credential authentication with `SO_PASSCRED/SCM_CREDENTIALS`, as distinct from a socketpair's `SO_PEERCRED` creation-time credentials. Test wrong UID both directions.
- `CF-UDX-W9-ANCILLARY-02`: strict `recvmsg` parser that closes all transferred handles on malformed packet and refuses any unexpected ancillary type, FD count or truncation.
- `CF-UDX-W9-PORTAL-03`: cancel-safe, bounded, one-file read-only FileChooser-result shape parser. NOT a consent evaluator; no public grant API.
- `CF-UDX-W9-NEGATIVE-04`: controlled separate UID integration with DAC denial and forged identity field rejection.

## Datenschutz/Compliance matrix **proposed**
- `UDX-W9-DP1`: Document Portal access may persist; require transparent grant retention and revoke controls.
- `UDX-W9-DP2`: revocation cannot recall FD-backed or copied data; data lifecycle and deletion limits must be explicit.
- `UDX-W9-DP3`: hash and file size are possible content fingerprints; no unbounded debug logging.
- `UDX-W9-DP4`: distinguish kernel identity, app identity and informed user consent; neither is interchangeable.
- `UDX-W9-DP5`: isolate production launcher/worker and manage leaked FDs, lifecycle, capabilities and least privilege.

## Evidence increment
- 126 -> 142 successful Linux non-root tests (+16).
- 1 positive two-principal OS separation run and 1 negative forged-UID run.
- 5 paired benchmark rounds per candidate × 250 in-process calls, separate-process throughput not measured.
- No verified user-mediated FileChooser, Windows or mobile runtime.

Do not write these candidates into authoritative matrices without matching schema, ownership, reviewer and evidence sign-off.
