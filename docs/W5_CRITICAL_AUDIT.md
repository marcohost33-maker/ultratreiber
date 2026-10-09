# W5 UDX — Independent Critical Audit and Hardening

Date: 2026-10-09. Scope: the four assistant development replies covering UDX 0.2, 0.3, 0.4 and their audit claims. Basis: source files physically present at `/mnt/data` and independent execution. **Scope limitation**: only Linux-host behavior was run; Windows/Android/iOS not run. This is an **internal self-audit**, not an independent external security certification.

## Method and evidence hierarchy

1. Direct source trace / version-specific comparison > prose claims.
2. Repeat baseline v0.4 as normal user; root skipping is reported distinctly.
3. Negative controls: present the same malformed input or hostile schedule to W4 and W5 using independent `cwd`/`PYTHONPATH` roots.
4. Conformance: Python runtime, Python JSON Schema and separate Node 22 runtime; fuzz 1,200 byte mutations + 200 structured cases + 22 golden cases.
5. Paired measurements W4/W5: random order in 3 paired trials, 50 warmup + 500 serial queries each, same W5 client; 3 repeated percentiles are neither independent random users nor population statistics.
6. Default-deny gates; no claims beyond tested environment.

## Critical findings and corrective actions

| ID | Severity | W4 finding | W5 work | Status |
|---|---|---|---|---|
| F-01 | P0 | `uid:<id>` permits any process with same UID: no application separation | Explicit trust-boundary restriction, do not introduce OS objects or privileged execution | OPEN, cannot fix with JSON/UID check |
| F-02 | P1 | Serial server susceptible to 1s head-of-line delay for each slow connection | Bounded 4-worker pool, 1s deadline per request, reject new connections when saturated | Improved, DoS NOT solved |
| F-03 | P1 | `Broker.audit` grows without limit | Ring buffer of last 256 events | FIXED for volatile memory bound; durable audit OPEN |
| F-04 | P1 | Broker replay/check/write would race under multithreading | Atomic lock around `handle` | FIXED in reference process only; restart/eviction OPEN |
| F-05 | P1 | IPC client parses untrusted server response via `json.loads` only | Strict response envelope + ID echo + capability-specific response data allowlist | FIXED in reference contract |
| F-06 | P1 | Wire parsers admitted Unicode noncharacters (`U+FFFE`) | Python+Node reject surrogate/noncharacters, escaped or direct | FIXED, red/green witnessed |
| F-07 | P1 | Windows probe uses blocking connect/read/flush without absolute deadline and has no actual UDX handler | Source review and explicit release block; don't claim Windows integration | OPEN |
| F-08 | P1 | Replay cache evicts last 1024 and vanishes at restart | Explicitly prohibited for future side effects; no writes added | OPEN |
| F-09 | P1 | Prior paired comparison harness might load W5 for both server versions due to cwd/module precedence | Fixed subprocess `cwd=root`, `PYTHONPATH=root`; discarded contaminated preliminary measurements | FIXED measurement methodology |
| F-10 | P2 | Real object-access and per-property authorization untested | Strict metadata response shape, no real file bridge | OPEN real OS authorization |
| F-11 | P2 | W4 55 green includes 2 static Windows textual checks | Separately label Windows checks; no Windows PASS | OPEN Windows gate |
| F-12 | P2 | `Schema` does not model raw byte/duplicate-key semantics or request↔response correlation | Wire parser plus runtime check + fixtures; full independent JS Schema validator absent | PARTIAL |

**Red-green counterexamples (one run each, not a statistically established performance improvement)**:

- v0.4 parser: escaped `U+FFFE` string accepted; v0.5 parser: `MALFORMED_JSON`.
- v0.4 serial broker: legitimate follow-up behind a 1-byte stalled client took **0.888714 s**; v0.5 four-worker broker took **0.013916 s** under same test structure.
- Invalid requests repeatedly appended audit entries in v0.4; v0.5 caps the local buffer at 256. New test checks 968 malformed requests without reading fixtures.
- 100 concurrent identical request IDs yield exactly one `OK` and 99 `REPLAY_REJECTED` in the single-process reference. This is not crash recovery.

## Performance trade-off, non-production

Three independently started servers per revision; 500 timed local read-only fixture requests plus 50 warmups per server, same v0.5 client for both; Python 3.13.5, Linux one shared host. From `evidence/W5_PAIRED_BENCHMARK.json`:

| Statistic (median of 3 trial-level percentiles) | W4 v0.4 | W5 v0.5 |
|---|---:|---:|
| p50 | 0.145893 ms | 0.326053 ms |
| p95 | 1.088624 ms | 1.666768 ms |
| p99 | 2.428688 ms | 2.553051 ms |

**Interpretation:** W5 is slower for ordinary sequential requests. Source of additional overhead: thread pool scheduling, synchronization and stricter response validation. Faster under one slow client is *a separate adversarial condition*, not an overall speedup. Three trials are insufficient for a service-level guarantee. Results depend on host activity. No real OS reads or writes were benchmarked.

## What is unsafe to conclude

- `SO_PEERCRED` proves a Linux UID at connect time, not a signed app, intent, trusted parent, or authorization to each object. Same-user malicious process remains in-scope for high-risk deployments.
- Unix socket `0700` directory and `0600` socket protect against **other users** on this Linux implementation. They do not separate same-UID processes; do not extrapolate to BSD/macOS.
- A bounded thread pool still allows hostile same-UID clients to occupy all workers or repeatedly connect. Max-workers is not fairness, a per-app budget, or a production DoS solution.
- A bounded in-memory replay cache/volatile audit is not evidence, durability, or tamper resistance.
- Runtime response validation does not authenticate which same-UID process is serving the socket; a same-UID malicious service can impersonate a valid response. Pair with securely provisioned app credentials/OS sandbox identities before privileged action.
- Windows C++ source probe has not been compiled or run; it blocks and may grant a whole Windows user SID access; a real Windows host/security test is required.
- JSON Schema's structural checks do not replace byte parsing, semantic policy, identity and ID binding. The Node parser is not a full Draft 2020-12 schema implementation.
- Synthetic metadata size 42 is test data, not a filesystem read or production KPI.

## Standards and design links (checked via web 2026-10-09)

- Linux `unix(7)` credentials and socket permissions: https://man7.org/linux/man-pages/man7/unix.7.html
- Microsoft `ImpersonateNamedPipeClient`, failure behavior: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- Named Pipe ACL: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Windows overlapped I/O and remote-client flag: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
- I-JSON Unicode restrictions: https://www.rfc-editor.org/rfc/rfc7493
- Object authorization and response minimization: https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/ and https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/
- Bounded worker lifecycle: https://docs.python.org/3.13/library/concurrent.futures.html
