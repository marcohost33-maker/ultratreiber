# UDX privacy/compliance matrix – candidate entries (not authoritative matrix updates)

| ID | Risk / data | Control to build | Status |
|---|---|---|---|
| UDX-DP-01 | Linux UID and process metadata may be personal data in combination with access records | purpose limitation; minimal retention; access policy; no raw payload logs | design |
| UDX-DP-02 | Consent captured by false client claims | OS-authenticated grant service and purpose-bound consent receipts; revocation | missing |
| UDX-DP-03 | Audit trail may leak filenames, identities or content | pseudonymous/hashed correlation with threat-aware reversibility, retention and encryption | missing |
| UDX-DP-04 | Multi-device transfers/remote control | no remote transport by default, explicit pairing, separate trust model | not implemented |
| UDX-DP-05 | Plugin update/supply chain | signed packages, SBOM, dependency review, rollback | missing |
| UDX-DP-06 | OS safety/permission accessibility | native permission prompt, graceful denial, accessibility-tested UI | missing |

**Current prototype:** synthetic fixture; test UID appears only in process-local policy. No telemetry, cloud, user file reads, personal document store or persistent audit. Swiss FADP/DSG and EU GDPR scope depends on deployment/users/data flow; legal review remains a release gate.
