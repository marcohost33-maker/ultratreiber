# UDX W8 – Independent Security Gate / Kernel FD Handoff

**Date:** 2026-10-09  
**Scope:** Standalone first; independent local implementation, no modifications to source GitHub repositories.  
**Evidence class:** Linux user-space research prototype, no production authorization assertion.

## Prior state and problems

W7 `ApprovedFdReader` and `SealedSnapshot` existed, but both were usable **only in-process**. The public Linux UDX broker still implements only synthetic object lookup and correctly exposes no file path or FD API. A real trusted host-to-worker handoff was missing. W7 grant/approval Boolean is a harness fixture and MUST NEVER be used to claim system consent.

## W8 implementation

- `udx_ref/fd_handoff.py`: single-purpose `AF_UNIX SOCK_SEQPACKET` **private socketpair**; EXACTLY ONE FD over `SCM_RIGHTS`. The request carries protocol ID, `inspect.readonly` operation, canonical UUID, and nothing about paths, arbitrary capabilities or client-supplied identities.
- Kernel-assisted receiver uses `SO_PEERCRED` UID and tests against a trusted host-configured UID. This UID does not identify one application; on pre-created socketpairs the PID may refer to socketpair creation rather than the eventual spawned child. **Do not treat this as per-app authentication.**
- Bounded `recvmsg` and ancillary buffers; reject `MSG_TRUNC` and `MSG_CTRUNC`; reject missing, multiple, malformed, and non-CLOEXEC descriptors; **close every received descriptor** on error.
- `SealedSnapshot` copies a single host-provided *read-only regular FD*, limited to 64 KiB, performs two source reads and kernel-seals the copy. Output only `{id,status,size,sha256}`, with strict response validation, no raw data bytes.
- Demonstration `tools/demo_w8_fd_handoff.py` launches a separate, nonprivileged Python worker using `subprocess.Popen(... pass_fds ...)` against internally created synthetic fixture. No public socket; no raw path input on the worker transport.
- `tools/bench_w8_handoff.py`: measures the local paired call; clearly excludes process launch, GUI consent, security isolation and hardware.

## Authoritative external sources and crucial refinements

- Linux `unix(7)`: https://man7.org/linux/man-pages/man7/unix.7.html (`SCM_RIGHTS` passes an open file description; `SO_PEERCRED` is not app identity).
- Linux `recvmsg(2)`: https://man7.org/linux/man-pages/man2/recvmsg.2.html (both `MSG_TRUNC` and `MSG_CTRUNC`).
- XDG portal FileChooser: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html. This presents a file selection dialog, returns `file://` URI(s), which may be mediated by Documents Portal. This **does not inherently** return an open read-only FD; privileged host integration is an additional step. A selected document may remain accessible over multiple sessions – revocation requires separate design.
- systemd service credentials: https://systemd.io/CREDENTIALS/ – a candidate for deployment-time credential mediation, not proof of per-app UID separation.

## Threats and scope boundaries

1. **No actual FileChooser/consent:** Developer-controlled fixture FD. This is a *mechanism*, NOT an end-to-end user authorization flow.
2. **No same-UID isolation:** A private unadvertised socketpair reduces unintended connectivity but does not defend against compromised trusted launcher, inherited-FD leakage, ptrace-equivalent access or malicious code with equivalent OS authority. App authentication is STILL G2 BLOCKED.
3. **Source atomicity:** `SealedSnapshot` is immutable AFTER the copy only. Two consistent reads plus `fstat` cannot prove a serialized snapshot while a separate writer changes the source.
4. **Privacy:** Hash and file size can fingerprint predictable content, and metadata must not be treated as anonymized. No raw payload is returned, but the worker necessarily reads it.
5. **Owner check:** Current policy requires source file owner equal expected UID; intentionally rejects some legitimate read-only documents (e.g. system-owned) until an explicit per-resource policy is designed.
6. **No privilege escalation:** Neither worker nor launcher is elevated or uses arbitrary OS input/screen control. Existing public UDX broker stays unchanged.
7. **Not an application identity framework:** The trusted process must be genuinely authenticated and supervised in a future OS-specific deployment; do not promote an inherited FD alone to universal attestation.
8. **Memory/trace:** `memfd` may be visible in /proc for permitted same-UID processes and data remains in memory while snapshot is open; kernel sealing is integrity, NOT secrecy.

## Executable tests and evidence

- 110 inherited W7 regression tests + 16 W8 tests = **126 Linux non-root tests**, zero skipped.
- Multi-process program verifies the actual transfer of an opened FD across an `exec` boundary and result binding.
- Negative cases: wrong UID, file owner mismatch, writeable FD, directory FD, size overflow, too few/too many FDs, truncated packets/control, malformed and duplicate-key JSON, wrong response UUID, illegal response fields/size, FD injection in response, repeated malformed packets without descriptor leaks.
- Benchmark: five rounds x 300 in-process transfers on a 4 KiB fixture; see `evidence/W8_BENCHMARK.json` for measured results and explicit exclusions.
- These tests do not cover Flatpak sandboxing, AppArmor/SELinux, real desktop dialog, Windows native host, or sustained load. No production approval.

## Next release gates

- **G2:** Separate application principals through OS-enforced process isolation (e.g. distinct UIDs or trusted supervisor), secure runtime dir and peer identity at trust boundary, path/FD inheritance controls. Cross-UID and compromised client adversarial tests.
- **G3:** Real `org.freedesktop.portal.FileChooser` D-Bus integration in actual graphical session, authenticated portal response provenance, cancel/revoke testing, application-visible file access semantics, no transfer of attacker-supplied path, post-selection open and handoff within same authorized principal.
- **G3+Read:** Audit TOCTOU and source mutation; supported filesystem snapshot APIs or explicit best-effort semantics; keyed metadata if privacy context warrants.
- **G4:** Durable effect journal (`PREPARED`, `APPLIED`, `UNCERTAIN`) and fault injection BEFORE any mutating adapter is exposed.
- **G2-Win:** Native Windows compile and runtime security tests remain blocked.
- **G5-G6:** Independent reviewer, packaging/attestation, CI with Linux and Windows hosts, long-running load, sandbox and accessibility policy reviews.

**No release beyond research prototype.** Digi only optional future client.
