# Security Policy

Ultratreiber (UDX) is a **research demonstrator, not production software**. It has
no security approval, no independent audit and no supported release. Do not deploy
it to protect real data or systems.

## Supported versions

| Version | Supported |
|---|---|
| `main` (current wave W24, 0.24.0) | Best effort: reports are read and triaged |
| older waves / commits | No |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub's
private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** and fill in the advisory form.

Please do **not** open a public issue for an undisclosed vulnerability.
There is no e-mail reporting channel.

Helpful content: affected file and commit, platform and Python version, a minimal
reproduction, and what you expected versus what happened. Do not include real
account names, SIDs, tokens or paths from your machine in shared logs; the
evidence collector redacts raw test output for that reason.

## What to expect

This is a small research project without a staffed security team. Reports are
acknowledged on a best-effort basis; there is no guaranteed response time and no
bug bounty. Fixes land on `main` and are described in the advisory.

## Scope notes

In scope: the request parser and contracts (`udx_ref/`, `contracts/`), the Linux
AF_UNIX and Windows named-pipe peer-identity checks, the durable grant journal,
and the evidence tooling in `tools/` (for example a report that the verifier
accepts although it should be `BLOCKED`).

Known, documented limits are not new vulnerabilities by themselves - see the
"NOT evidenced" list in `README.md` and the audit documents in `docs/`.
Current state (W24): the C++ candidates in `windows/` are compiled with MSVC
`/W4 /WX` and cross-run on a hosted Windows runner (since W18); since W24 their
pipe I/O is overlapped under one absolute deadline, with native stall tests in CI.
W20 supplies second-standard-account evidence under batch logon (Session 0) on that
runner. None of this establishes: a second interactive Windows 11 session, real
AppContainer / Low-IL / service principals, remote-host coverage, the C++ cancel-race
path (exit 31) under fault injection, delivery acknowledgement, independent
attestation, or product approval (gate G2-App remains FAIL/OPEN). Same user SID is
not the same application identity (`docs/ADR-UDX-006.md`).
