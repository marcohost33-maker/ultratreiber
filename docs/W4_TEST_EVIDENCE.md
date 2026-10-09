# W4 local evidence (2026-10-09)

- Source basis: W3 `UDX_Standalone_v0.3_2026-10-09.zip`, source folder copied and modified locally. No GitHub writes.
- Host: Linux 6.18.44 x86_64 glibc 2.41, Python 3.13.5, Node 22.16.0; user `oai` (nonroot) for ALL test lanes.
- Full suite `python -m unittest discover -s tests -v`: **55 tests / 0 failed / 0 skipped** under nonroot (see `evidence/TESTS_NONROOT.log`).
- Python versus Node independent strict wire parser: 19 fixed golden vectors + 200 seeded mutation cases; agreement, not exhaustive proof. `test_node_interop.py` uses a separate Node process.
- Slowloris negative control: one byte received; no further bytes for 1.23 sec; new legitimate request succeeds after absolute 1-sec deadline. Guard caps duration of an individual message on the single-thread server. Rate/queue exhaustion remains open.
- Windows candidate: two static source guards PASS; **zero Windows compile/runtime tests**. No Windows claims beyond uncompiled candidate.
- 300 local IPC fixture requests: measured values in `evidence/IPC_BENCHMARK.json`. No OS object read or network; noisy host results, not paired/controlled regression versus W3.
- Dependency test: JSON Schema 2020-12 through Python package `jsonschema`; runtime CPython stdlib; independent Node.js `node:util` and `node:fs` builtins. The Windows code requires Windows SDK.

Audit questions for next wave: Does a same-UID hostile process bypass any planned fine-grained app policy? How to bound the Windows blocking read? Is runtime JSON Schema using the same patterns and constrained dialect as Python? Are directory/socket path checks race safe? Test per-platform authorization before any OS action.
