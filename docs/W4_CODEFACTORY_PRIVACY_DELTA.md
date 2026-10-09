# W4 reusable patterns and privacy/compliance candidate deltas

## CodeFactory patterns (all candidate, no promotion)

- `CF-UDX-RECV-DEADLINE-06`: absolute monotonic connection budget, must shrink on each recv; unit test slow byte trickle and next-client recovery. Failure mode: renewing timeout for every byte.
- `CF-UDX-DUAL-PARSER-07`: separately implemented strict JSON scanner for duplicate keys after unescaping; Python/Node fixture parity harness with a fixed seed.
- `CF-UDX-INTEROPERABLE-INTEGERS-08`: ensure cross-runtime exact integers and rejection of unpaired Unicode surrogates; document stricter-than-JSON subset.
- `CF-UDX-WINDOWS-SID-PIPE-09`: source only; explicit DACL and remote reject + last-message impersonation; **never reusable in production without Windows fault tests**.
- `CF-UDX-GATE-VECTOR-10`: record gates as vectors; a static source test must not satisfy OS runtime gate.

## Privacy / Swiss DSG / GDPR candidate matrix entries (not central register edits)

| ID | Personal data / risk | Mitigation candidate | Validation gap |
|---|---|---|---|
| UDX-DP-07 | UID / Windows SID processed as linkable identifier | local memory only, avoid printing identities, purpose limitation | retention and deletion policy |
| UDX-DP-08 | IP/remote identity claims during pairing | remote disabled by default; reject remote Windows Named-Pipe clients | Windows real network test |
| UDX-DP-09 | Error logs may expose request payloads | test audit only records UUID and refusal code; no raw payloads | threat review and telemetry audit |
| UDX-DP-10 | Inter-application request rights under same OS user | explicit app identity separation and scoped grants before real OS operations | same-UID negative control, revocation |
| UDX-DP-11 | OS update/supply-chain tampering | pinned deps, signed binaries, static/dynamic security scans | SBOM, signature verification, distribution |

Compliance status: open; no assertion of Swiss DSG/GDPR compliance. Need role determination, data subject rights, jurisdiction and consent/legal basis analysis prior release.
