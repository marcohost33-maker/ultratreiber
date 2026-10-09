# UDX v0.3 local test evidence — 2026-10-09

- OS: Linux 6.18.44 x86_64, glibc2.41; Python 3.13.5.
- Test command: `/opt/pyvenv/bin/python -m unittest discover -s tests -q` executed as **UID 1000 (`oai`)**, not root; result **50 tests, 0 failures, 0 skips**.
- Separate root-run command: 50 tests, 14 security/IPC tests skipped (correct platform gating), **not a passing Linux-lane result**.
- Linux kernel test uses AF_UNIX stream, SO_PEERCRED, socket-directory 0700 and socket 0600; separate Python server process.
- Controlled cross-UID negative control (orchestrated inside test container): `nobody` denied at private runtime path; owning user `oai` succeeds. This does not prove resistance to elevated root or same-UID attacks.
- End-to-end IPC fixture benchmark: 300 successful requests; p50=0.06406 ms, p95=0.25031 ms, p99=0.32390 ms, mean=0.08814 ms, max=0.42676 ms. No true OS file operations.
- Version `udx/0.1` unchanged from v0.2; schema structural and wire parser independent checks.
- Open gates: Rust/TypeScript parity; native Windows identity tests; per-app isolation, durable state, OS operations, cross-device and platform support.

**Evidence ceiling:** research-only, local reproducibility; not a security certification or production readiness.
