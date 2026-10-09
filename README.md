# UDX Standalone W11 v0.11 — isolated read-only broker research

**Status: WORKING RESEARCH DEMONSTRATOR, NOT PRODUCTION READY.** The platform-independent UDX and Linux IPC path remain standalone. No Digi/Nigin dependency. No GUI portal authorization, unrestricted device access or Windows runtime proof.

## W11 source audit / corrections

- Corrected `PortalRequest` invalid/non-finite/regressing clock handling including exact-deadline rejection. A pre-patch NaN-clock case accepted a simulated result; now denied.
- Serialized transactions for one shared SQLite connection via a per-instance reentrant lock; 12 concurrent same-grant claims yield exactly one winner in negative test.
- W11 evidence: `docs/W11_INDEPENDENT_CROSS_WAVE_AUDIT.md`, `docs/W11_CODEFACTORY_TRANSFER.md`, `docs/W11_ROADMAP_GATES.md` and `tests/test_w11_audit_hardening.py`.
- **RESEARCH ONLY**: no real authenticated portal consent, same-UID app isolation, Windows run, or production release.

## W10 additions

- `udx_ref/durable_grants.py` — local trusted-host journal: SQLite WAL+FULL, single-use grants bound to resource FD and actor roles, TTL, revoke, quarantine on uncertain recovery. This is NOT a user-consent issuer or immutable audit ledger.
- `udx_ref/authorized_handoff.py` — private, durable-claim-before-send SCM_RIGHTS wrapper.
- `udx_ref/portal_request.py` — fail-closed FileChooser correlation state machine. **Simulated input only**; authenticated D-Bus provenance is NOT implemented.
- `tools/demo_w10_cross_uid.py` and `tools/demo_w10_crash_recovery.py` — controlled Linux POSIX kernel credential and process-crash demonstrations.
- `tests/test_w10_grants_portal.py` — expiry, replay, UID binding, resource replacement, database permissions, concurrent claim, cross-device not claimed, forged portal reply rejection and terminal states.

## Reproduce

Run without root (tests require Python 3.13; inherited Node interoperability tests require Node):

```sh
PYTHONPATH=. python -m unittest discover -s tests -v
PYTHONPATH=. python tools/demo_w10_crash_recovery.py
PYTHONPATH=. python tools/bench_w10_journal.py
```

In **disposable controlled Linux environment only**, the root-assisted test launcher spawns *two unprivileged users* and drops privileges before UDX operations:

```sh
PYTHONPATH=. python tools/demo_w10_cross_uid.py
```

This launcher is **not** a deployable privileged daemon. See `docs/W10_CRITICAL_AUDIT.md` and `docs/W10_PRIVACY_CODEFACTORY.md`.

## Release gates still blocked

Native FileChooser/Document Portal and authentic user consent; per-app production sandbox including same-UID threat; Windows compilation and runtime attack tests; robust startup/crash/power-loss durability review; independent benchmark and security audit.
