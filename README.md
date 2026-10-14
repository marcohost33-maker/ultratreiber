# Ultratreiber (UDX)

[![CI](https://github.com/marcohost33-maker/ultratreiber/actions/workflows/ci.yml/badge.svg)](https://github.com/marcohost33-maker/ultratreiber/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: research demonstrator](https://img.shields.io/badge/status-research%20demonstrator-orange.svg)

Ultratreiber (UDX, *Universal Driver & eXchange*) is a research demonstrator of an isolated, read-only access broker: a fail-closed request parser, OS-credential-bound peer identity and evidence-gated Linux (AF_UNIX) and Windows (named pipe) transport lanes, with no dependency on any client or model runtime.

> **Status: RESEARCH DEMONSTRATOR — NOT PRODUCTION READY.** Current wave: W16 (version 0.16.0). No release, no security approval.
>
> **Evidenced (local, not independently attested):**
> - Portable + Linux test suite, run without root (`python -m unittest discover -s tests`); per-wave logs in `evidence/*_NONROOT_TESTS.log`.
> - Native Windows 11 lane: the 47 pinned named-pipe tests of `tests/test_w12_windows_pipe.py` (23 runtime + 24 fault-injection) passed 47/47 on 2026-10-14 (Windows 11 Home 10.0.26200, Python 3.14.4, one standard account, not elevated): [`evidence/W16_NATIVE_WINDOWS_REPORT_FINAL.json`](evidence/W16_NATIVE_WINDOWS_REPORT_FINAL.json), summary in [`evidence/W16_WINDOWS_LANE_SUMMARY.json`](evidence/W16_WINDOWS_LANE_SUMMARY.json). The collector verdict `UNTRUSTED_REPORT_SCHEMA_VALID` is a syntax and local-hash check, not an attestation. Re-run on the same host at the public-prep commit `4b87f3b` (first run at a committed head; Python 3.14.4): 47/47, [`evidence/PUBLIC_PREP_NATIVE_WINDOWS_REPORT.json`](evidence/PUBLIC_PREP_NATIVE_WINDOWS_REPORT.json).
>
> **NOT evidenced:** denial against a real second Windows account; real AppContainer / Low-IL tokens; service-account sessions; elevated owner / AccessCheck matrix; a second (remote) host; a compiled C++ binary (`windows/*.cpp` has never been built); independent security review or attestation; authentic portal consent; Android/iOS.

## Quick start

Requires Python 3.13 or newer (CI: 3.13 and 3.14). The runtime (`udx_ref/`) uses the standard library only; the tests additionally use `jsonschema` (`requirements-test.txt`; without it the contract-conformance tests skip as "NOT green") and Node.js 22 or newer for the cross-runtime interop tests (they skip when `node` is absent).

Linux shell (run as a normal user, not root):

```sh
git clone https://github.com/marcohost33-maker/ultratreiber.git && cd ultratreiber
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-test.txt
PYTHONPATH=. python -m unittest discover -s tests -v
sha256sum -c SHA256SUMS_W12
```

Windows (PowerShell, standard user):

```powershell
git clone https://github.com/marcohost33-maker/ultratreiber.git; cd ultratreiber
py -3 -m pip install -r requirements-test.txt
$env:PYTHONPATH = '.'
py -3 -m unittest discover -s tests -v
py -3 tools/w15_windows_evidence.py --collect --repo . --timeout 300 --output "$env:TEMP\udx_native.json"
py -3 tools/w15_windows_evidence.py --verify "$env:TEMP\udx_native.json" --repo .
```

`SHA256SUMS_W12` is the current manifest (all tracked files except the two manifests); `SHA256SUMS` is the historical W11 import manifest, kept unchanged as a record and intentionally no longer current. The collector needs a full clone (it checks that the audited W14 baseline `26309e9` is an ancestor of `HEAD`) and byte-exact sources (`.gitattributes` disables line-ending conversion). Exit code 0 with verdict `UNTRUSTED_REPORT_SCHEMA_VALID` means the 47 pinned tests passed on that machine — nothing more. On Windows use a base interpreter, not a virtual environment: a venv's `python.exe` is a redirector that starts the real interpreter as a child process, so `test_same_user_cross_process_peer_ok` sees a different client PID and fails (observed with Python 3.13.13). Wave-by-wave design notes, audits and gates are in [`docs/`](docs/) (start with `W12_WINDOWS_LANE.md`, `W16_FAIL_CLOSED_EVIDENCE_HARDENING.md`, `ROADMAP.md`).

## Citation, license, provenance

- Cite via [`CITATION.cff`](CITATION.cff) (GitHub: "Cite this repository").
- Licensed under the [Apache License 2.0](LICENSE); see [`NOTICE`](NOTICE). Copyright 2026 Marco Hostettler / Coworker Research (Coworkerz).
- Developed with the DI (digital intelligence) Coworker system — Coworker Research. Names such as Digi, Nigin, Vero, CodeFactory or `007acc2` in `docs/` refer to private Coworker Research projects and workspaces that are not publicly accessible.
- Security reports: [`SECURITY.md`](SECURITY.md). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## UDX Standalone W11 v0.11 — isolated read-only broker research (historical wave notes)

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
