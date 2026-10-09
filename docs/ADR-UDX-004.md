# ADR-UDX-004 — Windows security transport: native SID-bound probe
**Date:** 2026-10-09. **Status:** unverified Windows source candidate.

## Scope and explicit non-claims

The `windows/` C++ code demonstrates the intended native primitives on paper: protected DACL exact user SID + SYSTEM, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, the client explicitly offering impersonation, last-message read, server token query under impersonation, `EqualSid`, mandatory revert before any positive response. The only successful behavior is the ASCII `PEER_OK` handshake, **not** a UDX message or OS capability. This source could not be compiled or executed on Linux: neither Windows compiler nor Windows runtime is installed. Static assertion tests are not platform-security tests.

## Known blockers

1. Blocking I/O: malicious same-SID client can park the server indefinitely. Implement `FILE_FLAG_OVERLAPPED` with handle-specific cancellation/deadlines and bounded concurrency.
2. Require negative tests on real Windows: alternate user, integrity level, AppContainer, impersonation failure, remote SMB, process and UAC context, service identity; use native Windows resource ACLs separately.
3. `OpenThreadToken` identity identifies user SID, **not individual software/process identity**. Same-user hostile code may be inside the trust boundary. Require process isolation / signed deployment / constrained capabilities and explicit consent.
4. If privileged service is introduced, isolate policy and all OS operations; never execute actions on failure to impersonate or revert. Strongly prefer per-user unprivileged broker.
5. Research handshake has no UDX framing or parser. Before integration require byte-bounded frame, schema validation, request id, replay policy, deny reason, trace, timeout/recovery, client and server protocol tests.

## Required verification

Build with `cl /W4 /EHsc /std:c++17`; run under ordinary Windows account; check pipe DACL with OS APIs; demonstrate refusal to a different account and remote client; fault-inject errors of each impersonation operation; verify thread identity always reverts. Recheck Microsoft docs and actual Windows SDK version; no release until ALL mandatory tests pass. Source reviewed only from Linux, not compiled.

## Sources

- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew
- https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
