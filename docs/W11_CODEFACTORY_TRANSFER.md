# W11 CodeFactory transfer candidate

Status: `RESEARCH_REUSABLE_NOT_PROMOTED`; requires exact consumer adaptation and validation.

| Pattern ID | Intended use | Negative oracle | Claim ceiling |
|---|---|---|---|
| CF-UDX-FINITE-MONOTONIC-CLOCK-11 | deadline-based async portal requests | injected `float('nan')`, `inf`, `True`, backward clock and expiry boundary | simulation state machine only, not authenticated OS consent |
| CF-UDX-SERIALIZED-SQLITE-TRANSACTIONS-11 | single shared sqlite3 connection across threads | barrier-aligned 12 concurrent one-use grant claims; exactly one accepted | does not defeat attacker with same UID or fsync/power failure |
| CF-UDX-ONEUSE-UNCERTAIN-10 | crash-aware handoff ledger | kill process after claim, recover to QUARANTINED, deny replay | not immutable; not powered-off recovery proof |
| CF-UDX-BOUNDED-FD-READ-08 | locally approved FD read | reject write fd/oversize/symlink confusion and forbidden UID | no atomic source snapshot |
| CF-UDX-PORTAL-PROVENANCE-10 | async FileChooser response shape | wrong D-Bus owner, wrong request handle, cancellation | owner must come from real authenticated bus |

Transfer workflow: source+contract+negative tests -> consumer exact version review -> isolated test -> OS-specific permission test -> independent review -> staged release. Never copy role identities or local timing claims.
