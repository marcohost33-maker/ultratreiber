# Contributing

Thanks for your interest. Ultratreiber (UDX) is a research demonstrator; the
bar for changes is evidence, not volume.

## Before you start

- For anything beyond a typo, open an issue first and describe the problem or
  the claim you want to test.
- Security issues: do **not** open an issue - follow [`SECURITY.md`](SECURITY.md).
- By contributing you agree that your contribution is licensed under the
  [Apache License 2.0](LICENSE) (section 5 of the license).
- Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

Python 3.13 or newer, no third-party packages; Node.js 22+ for the interop tests.

```sh
PYTHONPATH=. python -m unittest discover -s tests -v   # Linux: run as a normal user, not root
sha256sum -c SHA256SUMS_W12
```

On Windows additionally run the native evidence collector (see `README.md`).

## Pull request checklist

- [ ] Every new guard or check has a **negative test** that fails when the guard
      is removed (fail-closed first, happy path second).
- [ ] The full suite passes on the platforms you touched; state platform, Python
      version and the exact `Ran N ... OK` line in the PR.
- [ ] `SHA256SUMS_W12` is regenerated over all tracked files except itself
      (`git ls-files | grep -vx SHA256SUMS_W12 | xargs sha256sum -b > SHA256SUMS_W12`
      in a checkout without line-ending conversion).
- [ ] Changes to pinned sources (`udx_ref/windows_pipe.py`, `windows/*.cpp`,
      `tests/test_w12_windows_pipe.py`) update the pins in
      `tools/w15_windows_evidence.py` deliberately and say why.
- [ ] No claim stronger than the evidence: "passed locally" is not "verified",
      a schema-valid report is not an attestation.
- [ ] No local paths, account names, SIDs or secrets in code, docs or evidence.

## Style

Standard library only, small explicit functions, typed denial codes instead of
generic exceptions, deterministic tests (fixed seeds, bounded timeouts).
