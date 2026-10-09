# UDX cross-project reuse and sources

## Reuse evidence / claim ceiling

| Source | Existing element | UDX concept | Evidence limit |
|---|---|---|---|
| `marcohost33-maker/digi` `docs/adr/ADR-0002-zones-as-ports-and-adapters.md` | core-owned ports, per-platform guarantees | independent adapter contract | design reuse only, no code linked |
| Digi `digi/stage3/registry.py` | typed capability manifests, strict verdict mapping | capability discovery and default-deny | synthetic ecosystem manifest ≠ OS rights |
| Digi `digi/stage3/guard.py` | fixed action/flag checks | validate checked operation before action | never directly execute checked CLI argv |
| Digi `digi/authority.py`, `docs/architecture/ARCHITECTURE.md` | probabilistic proposer / deterministic admission | optional Digi client with extra gate | no Digi runtime import or authority inheritance |
| `marcohost33-maker/nigin-engine/contracts` | WIT, capability-grant schemas, compatibility matrix | external engine/plugin adapter inspiration | Nigin G1 DRAFT, no full host/adapter |
| `marcohost33-maker/browser-nigin` `src/mcp/mcp-contract-validator.mjs` | strict JSON schema subset fail-closed | contract conformance test pattern | only pinned scheme supported |
| `marcohost33-maker/veromode` `src/veromode/policy.py` and ledger | actor policy, append-only chain, postdecision receipts | future policy/receipt model | not ported, concurrency/anchoring caveats |
| `007acc2/06_WISSEN` CodeFactory typed validation, bounded reader, exact-head evidence | reusable tests and patterns | prototype guard patterns | independently written, no license or execution import |
| `007acc2` README | approved workspace layout | final knowledge-transfer location | no write to root; digest dedup if uploaded |

## Reviewed external engineering references (URLs)

- Microsoft named pipe security: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- Microsoft named pipe impersonation: https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
- Windows LPAC: https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- Linux Landlock: https://docs.kernel.org/userspace-api/landlock.html
- D-Bus specification and authentication: https://dbus.freedesktop.org/doc/dbus-specification.html
- Android persistent work: https://developer.android.com/develop/background-work/background-tasks/persistent
- Apple App Intents: https://developer.apple.com/documentation/appintents
- Apple BackgroundTasks: https://developer.apple.com/documentation/backgroundtasks
- Apple App Groups: https://developer.apple.com/documentation/xcode/configuring-app-groups
- MCP latest 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28
- A2A latest released 1.0.0: https://a2a-protocol.org/v1.0.0/specification
- OWASP API Security Top 10: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- NIST SSDF SP 800-218: https://csrc.nist.gov/pubs/sp/800/218/final

These sources inform a design; citations are not proof that this prototype implements their security guarantees.

## Transfer to CodeFactory after independent gate

1. `CF-UDX-BOUNDED-ENVELOPE-01`: reject oversized bytes before UTF-8/JSON and unknown fields.
2. `CF-UDX-AUTH-PEER-02`: bind peer identity to OS credential, never to request JSON.
3. `CF-UDX-OBJECT-ACL-03`: re-authorize target resource at use point, independent of capability discovery.
4. `CF-UDX-EXACT-OP-04`: bind consent/grant and execution to exact checked action/resource/policy revision.
5. `CF-UDX-UNCERTAIN-05`: effect outcome unknown = quarantine until reconciled.

**Reuse status: proposed pattern candidates, not validated production components.**

## Compliance items for later matrix integration

`UDX-DP-01` principal and device identifiers; lawful basis, purpose and retention.  
`UDX-DP-02` minimum-data audit receipts and no raw payload logging.  
`UDX-DP-03` OS permission revocation, consent records and accessible user control.  
`UDX-DP-04` cross-device pairing, cross-border transfers, encryption and deletion.  
`UDX-DP-05` process telemetry/security events; roles, threat model, incident response.  
`UDX-DP-06` plugin supply chain, vulnerability policy and signed updates.

These are proposed review entries; no claim of legal compliance or existing insertion into a connected spreadsheet.
