# W4 status and priority next steps

- Verified locally: parser parity (Python/Node limited set), Linux absolute request deadline, real AF_UNIX UID credential fixture, 55 passing nonroot tests, fresh package manifest checks pending final packaging.
- Windows source-only transport handshake exists, **not compiled or runtime-verified**.

## W5 P0

1. Real Windows test host with MSVC + ordinary accounts: compile/fix Win32 SID source, DACL inspection, remote refusal, impersonation fault injection, timeout/overlapped I/O. No Windows PASS until all.
2. Linux app-isolation design: same-UID clients can connect; mitigate with OS process isolation, per-app privileges, capability grants (never claimed by payload); fail-closed object handle binding before actual operations.
3. Complete cross-language schema contract: independent Node JSON Schema Draft2020-12 validator or a correctly pinned standard library, negative pattern parity, and CI with precise dependencies.
4. Linux queue/backpressure, connection concurrency and sustained load; 1-second per-client deadline is not DoS resistance.

## W5 P1

5. Durable ledger/idempotency and injected crash/restart before ANY OS writes.
6. Native read-only OS handle adapter via owner-approved file chooser; no arbitrary untrusted path.
7. Independent security review, reproducible packaging and supply-chain signatures.
8. Android/iOS companion planning and optionally Digi connector (no change to standalone core).
