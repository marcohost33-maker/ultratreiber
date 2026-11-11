# Ultratreiber (UDX)

[![CI](https://github.com/marcohost33-maker/ultratreiber/actions/workflows/ci.yml/badge.svg)](https://github.com/marcohost33-maker/ultratreiber/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: research demonstrator](https://img.shields.io/badge/status-research%20demonstrator-orange.svg)

Ultratreiber (UDX, *Universal Driver & eXchange*) is a research demonstrator of an isolated, read-only access broker: a fail-closed request parser, OS-credential-bound peer identity and evidence-gated Linux (AF_UNIX) and Windows (named pipe) transport lanes, with no dependency on any client or model runtime.

> **Status: RESEARCH DEMONSTRATOR — NOT PRODUCTION READY.** Current wave: W25 (version 0.25.0). No release, no security approval.
>
> **Evidenced (local, not independently attested):**
> - Portable + Linux test suite, run without root (`python -m unittest discover -s tests`); per-wave logs in `evidence/*_NONROOT_TESTS.log`.
> - Native Windows 11 lane: the 47 pinned named-pipe tests of `tests/test_w12_windows_pipe.py` (23 runtime + 24 fault-injection) passed 47/47 on 2026-10-14 (Windows 11 Home 10.0.26200, Python 3.14.4, one standard account, not elevated): [`evidence/W16_NATIVE_WINDOWS_REPORT_FINAL.json`](evidence/W16_NATIVE_WINDOWS_REPORT_FINAL.json), summary in [`evidence/W16_WINDOWS_LANE_SUMMARY.json`](evidence/W16_WINDOWS_LANE_SUMMARY.json). The collector verdict `UNTRUSTED_REPORT_SCHEMA_VALID` is a syntax and local-hash check, not an attestation. Re-run on the same host at the public-prep commit `4b87f3b` (first run at a committed head; Python 3.14.4): 47/47, [`evidence/PUBLIC_PREP_NATIVE_WINDOWS_REPORT.json`](evidence/PUBLIC_PREP_NATIVE_WINDOWS_REPORT.json).
>
> - W17 (issue #2): the pipe owner is now set explicitly to the server user (`O:<SID>` in the SDDL). Before, an elevated administrator's pipe was owned by `BUILTIN\Administrators`, so the client's owner check refused it; Git Bash hid this because MSYS2/Cygwin rewrites the token's default owner. An OWNER RIGHTS ACE (`OW`) removes the owner's implicit `WRITE_DAC` (W14 finding UDX14-01). CI now runs the Windows suite under bash and pwsh, and the hosted-runner collector job is required (Windows Server, elevated Administrator — not standard-user evidence). The local Windows 11 reports above were taken on the pre-W17 source bytes; a fresh local collector run on W17 is pending. Details: [`docs/W17_PIPE_OWNER.md`](docs/W17_PIPE_OWNER.md).
>
> - W18: no ACE of the pipe grants `FILE_CREATE_PIPE_INSTANCE` any more. GRGW (`0x12019f`) contains `FILE_APPEND_DATA`, which for named pipes is the instance-creation bit. Every ACE now grants `FILE_GENERIC_READ | FILE_WRITE_DATA` (`0x12008b`), and clients open with exactly that mask, so a `GENERIC_WRITE` open is refused. Discriminating Windows tests run against the W17 descriptor as a control (second instance and legacy open are admitted there, refused under W18). The C++ candidates are compiled for the first time (MSVC `cl /W4 /WX`, CI job `cpp-candidate`) and cross-run against the Python lane in both directions. Details: [`docs/W18_LEAST_PRIVILEGE_PIPE_ACL.md`](docs/W18_LEAST_PRIVILEGE_PIPE_ACL.md).
>
> - W19: same user SID at the same integrity level is one trust domain ([`docs/ADR-UDX-006.md`](docs/ADR-UDX-006.md)); a pre-existing pipe name is reported as `PIPE_NAME_OCCUPIED` (CLI exit 21). Local Windows 11 run on the W18 bytes, Medium IL, UAC-filtered administrator token: 47/47 ([`docs/W18_LOCAL_WIN11_RUN.md`](docs/W18_LOCAL_WIN11_RUN.md)).
>
> - W20: **standard-account and second-account lane** in CI (`windows-account-matrix`). Two throwaway local accounts with no Administrators membership run as scheduled tasks. The second account and the elevated administrator are refused at open (`ERROR_ACCESS_DENIED`). The same-account control completes `PEER_OK` and the server identifies account A. The 47 pinned native tests pass as account A (47/47, `--verify` OK). The C++ probe now exits 21 for an occupied name, like the Python CLI. Details: [`docs/W20_STANDARD_ACCOUNT_LANE.md`](docs/W20_STANDARD_ACCOUNT_LANE.md).
>
> - W24: **bounded C++ pipe I/O** (UDX14-04 / UDX-W21-01 / UDX22-01; integrates the external reviews W21–W23). Server and client run every pipe operation overlapped under one absolute deadline (`windows/udx_bounded_pipe_io.hpp`: `GetOverlappedResultEx`, `CancelIoEx`, bounded settle, exit 31 if a cancelled I/O does not settle); `FlushFileBuffers` is replaced by a bounded wait for peer close. New exit codes 22 (deadline), 23 (`PEER_OK` written, peer did not close), 24 (bad arguments). The MSVC job runs six new negative-first native cases (connect / read / drain stall, silent server against the C++ client, bad arguments, small-budget positive control); a stall passes only with the typed exit code well before the stalling party lets go. Stale status claims in `SECURITY.md` fixed; W4/W5 gate files marked as historical snapshots; ADR-UDX-006 links the open G2-App gate. Details: [`docs/W24_BOUNDED_CPP_IO.md`](docs/W24_BOUNDED_CPP_IO.md).
>
> - W25: **real Low-IL, AppContainer and restricted-token principals** as separate processes (CI job `windows-principal-matrix`). The compiled C++ client is started suspended under each token; its token facts are read before it runs. Against the production security descriptor, Low IL and AppContainer are refused at open with `ERROR_ACCESS_DENIED` by both the Python and the C++ server, and the server sees no client. A restricted token passes the DACL and is refused by the server's token check (`RESTRICTED_TOKEN` / C++ exit 20). With a harness-only weakened descriptor, the server itself refuses the real Low-IL and AppContainer tokens (`INTEGRITY_TOO_LOW`; an AppContainer token is always Low IL, so `APPCONTAINER_CLIENT` is defense in depth). W25.1 (self-review) adds a handle allow-list for every child, typed C++ denial facts, a factorial attribution of the refusals and the same matrix under a throwaway **standard-account parent**: 16/16 in both modes. It also falsified one of our own hypotheses: a Medium label does not stop an AppContainer once the DACL grants `AC`, so for AppContainer clients the DACL is the only OS barrier. W25.2 (security fix): a Low-IL process of the same user can create the global pipe name and owns it with the user's SID, so an owner check alone accepted it. Both clients now also require an explicit mandatory label >= Medium before writing (C++ exit 7, Python `PIPE_LABEL_TOO_LOW`). A real Low-IL squatter received 0 bytes, and its attempt to set a Medium label failed with 1314. Details: [`docs/W25_PRINCIPAL_MATRIX.md`](docs/W25_PRINCIPAL_MATRIX.md).
>
> **NOT evidenced:** a second account in a different interactive session (W20 covers a second account via batch logon on the hosted Windows Server runner); AppContainers with capabilities an AppContainer or restricted-token principal as pipe squatter (Low IL is covered since W25.2) (W25 covers Low-IL / AppContainer / restricted clients with an elevated and a standard-account parent on the hosted Windows Server runner); service-account sessions; elevated owner / AccessCheck matrix; a second (remote) host; the C++ cancel-race path (exit 31) under kernel fault injection, repeated race runs and handle/memory profiles (W24 shows the deadline and cancellation on the normal path only, elevated hosted runner); delivery acknowledgement (peer close is not processing); exit-code parity of the Python CLI with the new C++ codes 22/23; independent security review or attestation; authentic portal consent; Android/iOS.

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

`SHA256SUMS_W12` is the current manifest (all tracked files except the two manifests); `SHA256SUMS` is the historical W11 import manifest, kept unchanged as a record and intentionally no longer current. The collector needs a full clone (it checks that the audited W14 baseline `26309e9` is an ancestor of `HEAD`) and byte-exact sources (`.gitattributes` disables line-ending conversion). Exit code 0 with verdict `UNTRUSTED_REPORT_SCHEMA_VALID` means the 47 pinned tests passed on that machine — nothing more. On Windows use a base interpreter, not a virtual environment: a venv's `python.exe` is a redirector that starts the real interpreter as a child process, so `test_same_user_cross_process_peer_ok` sees a different client PID and fails (observed with Python 3.13.13). Wave-by-wave design notes, audits and gates are in [`docs/`](docs/) (start with `W12_WINDOWS_LANE.md`, `W16_FAIL_CLOSED_EVIDENCE_HARDENING.md`, `W17_PIPE_OWNER.md`, `W18_LEAST_PRIVILEGE_PIPE_ACL.md`, `ROADMAP.md`).

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
