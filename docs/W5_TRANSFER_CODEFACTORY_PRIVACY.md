# W5 reusable patterns and privacy/compliance deltas

This is a **candidate knowledge-transfer record**, not an authoritative registry update or legal sign-off.

## CodeFactory candidate patterns

- `CF-UDX-BOUNDED-AUDIT-06`: volatile diagnostic `deque(maxlen=N)` avoids unbounded RAM. MUST label lossiness; never substitute for audit evidence.
- `CF-UDX-IPC-ADMISSION-07`: hard bounded concurrency and fail-closed rejection upon saturation. Notes: untrusted clients can still saturate capacity; add per-principal limits once principals are OS-isolated.
- `CF-UDX-REPLAY-ATOMIC-08`: atomic replay test+admission+operation+audit in one broker; does not guarantee cross-restart replay prevention.
- `CF-UDX-RESPONSE-BIND-09`: strict UTF8/json parsing, exact allowed fields, request-ID echo, object-ID match, per-capability property whitelists.
- `CF-UDX-IJSON-NONCHAR-10`: identical Python/JS rejection of Unicode noncharacters and invalid surrogate strings; independent byte differential test.
- `CF-UDX-PROVENANCE-BENCH-11`: paired benchmark must isolate executable, working directory and import path; detect invalid contamination before reporting.

## Privacy and compliance candidates

- `UDX-DP-07`: audit event metadata (`request_id`, refusal code), purpose limitation, retention, non-durable sampling and access control; prevent unintended logging of content.
- `UDX-DP-08`: separate process/app principal from user principal; same-UID service is not granular consent.
- `UDX-DP-09`: response property-level data minimization and strict schema, including IDs and sizes.
- `UDX-DP-10`: user-consent flows must be separate from discovery and operator-grant mutation; consent revocation checked before each actual OS action.
- `UDX-DP-11`: offline local device integration still processes personal data; assess logs, device ownership, lifecycle, user-facing disclosure.

## Statistics candidate, evidence-bounded

- Prior v0.4 suite: 55 tests under unprivileged Linux, including 2 source-only Windows pattern checks.
- Current v0.5: 68 tests under unprivileged Linux with no skips/errors; includes 2 source-only Windows pattern checks, so no Windows gate passed.
- Parser cross-runtime differential: 22 fixed golden test cases, 200 structured mutations, 1,200 mutated wire-byte cases. This proves agreement for tested vectors only, not universal language equivalence.
- Improvements verified by red/green tests: Unicode noncharacters and head-of-line blocking; bounded in-memory audit.
- Performance regression admitted: p50 of ordinary sequential local IPC higher in v0.5; protected against single slow-client serialized request.
- No measured OS action, Windows runtime, durable ledger, or production reliability.

Destination candidates: `007acc2/06_WISSEN`, CodeFactory transfer queue, privacy/compliance matrix and learning statistics **pending independent adjudication**. Do not auto-promote this research candidate.
