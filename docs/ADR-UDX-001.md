# ADR-UDX-001 — Standalone-first OS integration fabric

**Datum:** 2026-10-09  
**Status:** PROPOSED for review, not approved, no deployment  
**Owner:** decision reserved to project owner  
**Subject:** independently versioned Universal Driver & eXchange (UDX)  
**Claim ceiling:** read-only, in-process contract reference; four-platform design, no native implementation

## Problem and correction

An "ultra driver" physically running inside all four kernels is not a coherent deployable artifact. Windows kernel drivers, Linux kernel modules, Android services and sandboxed iOS apps have incompatible privileges, ABI and distribution rules. A privileged universal driver is a high-risk confused-deputy design. The correct abstraction is one stable *logical capability contract* plus narrowly scoped platform-specific executors.

**UDX is an independent product. Digi, Nigin, Vero, other AI agents, command-line tools and apps are optional clients. Neither the UDX core nor platform adapters import Digi packages or any model runtime.**

## Layered architecture

```
Clients: CLI / user app / service / Digi / Nigin / agents
       |
Client SDK + optional MCP/A2A bridges (no forwarded authority)
       |
Authenticated local transport boundary [OS-created peer identity]
       |
UDX protocol ingress: bounded parser, schema/version, per-request identity binding
       |
Capability discovery -- independent authorization -- request state machine
       |                                  |
       +-------- Policy decision ----------+
                     |       |
              Consent service (if applicable)
                     |
    Short-lived resource handles / scoped operations
                     |
         OS-specific executor (least privilege)
                     |
Windows / Linux / Android / iOS permitted native APIs
                     |
 Evidence/recovery (outside the critical execution chain when safely possible)
```

The primary runtime must never rely on a language-model-generated verdict for authorization. One OS may return `UNSUPPORTED` for an operation that exists elsewhere; this is not a failure of portability. Capability identity and semantics must be stable even when support differs.

## Five distinct contracts (not one overloaded object)

1. **Discovery:** `capability`, semantic contract version, platform support, requirements, limits. This does not authorize anything.
2. **Request:** strict versioned envelope with unique request ID, action and typed parameters. No self-asserted identity or consent.
3. **Authorization:** OS-attested actor, principal/device scope, policy head, capability, resource ID or previously issued handle, required consent and expiry; authoritative evaluation just before any action.
4. **Execution:** exact checked action, bounded resources and deterministic outcome taxonomy; policy result cannot silently morph into execution authority.
5. **Receipt:** evidence of decision, attempt, effect, and observed completion. `UNKNOWN/UNCERTAIN` is mandatory when the outcome cannot be proven.

## Proposed outcome states

`UNSUPPORTED`, `INVALID`, `UNAUTHENTICATED`, `DENIED`, `READY`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `UNCERTAIN`, `QUARANTINED`.
These are **proposed future wire states**; the executable reference deliberately supports only `{status: OK|DENIED}` and explicit reason codes. Never claim full lifecycle implementation from the reference.

## Trust boundaries, threats, invariants

- **TB1:** untrusted wire -> bounded parser: reject unknown fields, duplicate keys, invalid encoding and oversized frames before buffering further.
- **TB2:** OS-authenticated peer -> scoped principal: never take actor/role/capability grants/consent from request JSON.
- **TB3:** principal -> object: object-level ACL/authorization at point of use; no path traversal, symlink-follow assumptions or unchecked object IDs.
- **TB4:** policy -> OS executor: no ambient administrator privilege; checked action equals executed operation, no shell string building.
- **TB5:** OS result -> receipt: separate planned, attempted and observed outcomes; record `UNCERTAIN` on ambiguous side effects.
- **TB6:** client adapters -> core: external protocols are untrusted adaptation edges, not a grant issuer.
- **TB7:** policy/consent revisions: reject stale grants and revocation races; bind approval to exact action, object, actor and expiry.
- **TB8:** cancellation/timeouts: cancelled request does not imply OS side effect was rolled back.
- **TB9:** multitenancy and concurrency: a cached decision for user A must never authenticate B; quotas and backpressure are per authenticated principal.
- **TB10:** distribution: signed updates, SBOM, dependency pinning, rollback and release provenance; never download/execute code because an LLM suggested it.

## Architecture rule for write actions

For mutating operations, an operation-specific recovery state machine is required:

```
PROPOSED -> AUTHORIZED -> PREPARED -> DISPATCHED -> VERIFIED -> COMMITTED
                                 |             |
                                 v             v
                              ABORTED       UNCERTAIN -> RECONCILED | QUARANTINED
```

No universal `exactly once` guarantee is claimed. A durable idempotency key plus request digest and user/target binding is necessary but insufficient for non-transactional OS side effects. Recovery requires read-back or operation-specific compensation and proof; on conflict, refuse retries. Never treat an action receipt as evidence of an OS effect unless verified.

## Language and runtime

- Prototype: Python standard library, zero OS side effects, for reasoning and golden vectors only.
- Potential native desktop broker: Rust, subject to toolchain, security review and portability benchmarks; not yet selected.
- Android adapter: Kotlin, Binder/AIDL with caller UID/permission validation; account for lifecycle and explicit Android background service policies.
- iOS adapter: Swift App Intents and user-scoped app capabilities; optional authenticated companion connection to desktop; no general always-on OS service.
- WIT/WASM and MCP: optional boundaries, not hard dependencies. A2A: separate external agent bridge, not a kernel/OS bus.

## Deviation from prior Digi-first draft

Old: `OS -> UDX -> Digi -> projects`.  
New: `OS -> independent UDX -> any authorized client (Digi optional)`.  
No Digi authority or evidence is inherited automatically by UDX. If a client is Digi, its own authority gate remains an additional prerequisite for executing Digi-originated actions.

## Open design decisions

- UDX stable ID, name/domain and ownership/trademark/licensing.
- Native broker language and distribution packaging.
- Local IPC identity and consent binding on each OS; transport matrix.
- Resource capability handles, lease expiry, revocation and revalidation semantics.
- State-changing operation journal design with power-loss tests.
- Event taxonomy, quotas, interruption handling and bounded subscription replay.
- Privacy threat model, retention, export and deletion policy for audit data.
- Signed plugin ecosystem and sandboxed extension model.
- Remote pairing and multi-device federation (deferred).

**Decision boundary:** This document proposes the architecture; approval is not implied by passing reference tests.
