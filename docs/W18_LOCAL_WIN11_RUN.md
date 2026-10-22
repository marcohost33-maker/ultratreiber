# W18 — local Windows 11 collector run, non-elevated token (2026-10-23)

ROADMAP W18 item (1): run the native evidence collector on the W18 bytes on a
real Windows 11 machine without elevation. Only facts observed in this run;
nothing here is a release approval.

## Machine and token

| fact | value | how observed |
| --- | --- | --- |
| OS | Windows 11 Home, `EditionID` Core, `DisplayVersion` 25H2, build 26200.9711 | registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (its `ProductName` string still reads "Windows 10 Home"); collector: `platform_release` 11, `platform_version` 10.0.26200 |
| integrity level | **Medium** (`S-1-16-8192`) | `whoami /groups` |
| Administrators | `BUILTIN\Administrators` (`S-1-5-32-544`) and `S-1-5-114` present as **deny-only** | `whoami /groups` |
| Python | 3.14.4, base interpreter (`sys.prefix == sys.base_prefix`), executable SHA-256 `7ca24f26d6e3f463419ee4f537ddd3acd312c38fe45e678cce08572f26a8bd1a` | collector report, `python -c` |

**Not a standard account.** The interactive user is a member of the local
Administrators group; the shell runs with the UAC-filtered (non-elevated)
token, so Administrators is deny-only and the integrity level is Medium. That
is the token a standard user would also get for these checks, but the account
itself is not a standard (non-admin) account. Whether this satisfies the
"standard-account" wording of the roadmap item is an owner decision.

## W18 bytes

- Fresh local clone, `core.autocrlf=false`, checkout
  `682ac68e6790bb6c748f83fcb0cd5b05e3a5d8ab` (head of PR #4 at W18).
- `sha256sum -c --strict SHA256SUMS_W12`: exit 0.
- Pinned sources in the report: `udx_ref/windows_pipe.py`
  `6a9791dbfbb1f095094ad19a44f1f9f0f5dfed316a1fac8ef808a41538ec37a3`,
  `tests/test_w12_windows_pipe.py`
  `5858e116582235487888807ef5ac07f42f3408715b0a2366759bd725301116e7`,
  `windows/udx_sid_probe.cpp` `789eb785…fcef9`, `windows/udx_sid_client.cpp`
  `e97dc3b5…5091e` (full values in the report).

## Result

```
python tools/w15_windows_evidence.py --collect --repo . --timeout 300 --output <report>
python tools/w15_windows_evidence.py --verify <report> --repo .
```

| | value |
| --- | --- |
| collected (UTC) | 2026-10-22T22:25:36Z (local 2026-10-23 00:25) |
| `--collect` exit code | 0 |
| `diagnostic_code` | `OK` |
| cases | 47 run, 47 `PASS`, 47 unique ids: 23 `WindowsPipeRuntime` + 24 `WindowsPipeFaultInjection` |
| wall time | 13.234 s |
| `--verify` exit code | 0, verdict `UNTRUSTED_REPORT_SCHEMA_VALID`, `release_authorized: false` |
| `manual_gates` | all 7 `NOT_EXECUTED` |
| report | `evidence/W18_LOCAL_WIN11_NATIVE_REPORT.json`, SHA-256 `d4040d5e8ac29a6378dcfbb6370ab4e9fa6b58a99a409b46fe207a6dd768ef24` (no user name, SID or host name in it) |

`--verify` of this report against the W19 checkout fails by design (W19 changed
`udx_ref/windows_pipe.py`): observed exit 2, verdict `BLOCKED`, issues
`PINNED_SOURCE_DRIFT:udx_ref/windows_pipe.py` plus `SOURCE_CHANGED` for
`windows_pipe.py` and both tools. Verify it against `682ac68`.

Second run, same machine and token, on the W19 head
`59017a0a891ea515637347d62df8edf3dbc4d389` (`udx_ref/windows_pipe.py`
`08e3b35a3260646b2626f394e43a3c6955dbcea2f666b656dd2b29677acb1d3b`): collect exit
0, `diagnostic_code` `OK`, 47/47 `PASS`, 12.515 s, verify exit 0
(`UNTRUSTED_REPORT_SCHEMA_VALID`). Report not committed.

## What this run is not

- Not a standard (non-admin) account, see above.
- Not the G2 matrix: no second account, no real AppContainer or Low-IL process
  as a separate principal, no service account, no remote host, no elevated
  (High-IL) run. The seven manual gates stay open.
- Not an independent attestation: the report is produced and checked on the
  same machine by the same operator.
