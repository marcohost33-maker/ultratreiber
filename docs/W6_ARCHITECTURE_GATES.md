# UDX W6 — Standalone Architektur, Übergänge, Gates

## Trust boundaries und Authority

```text
 OS / Nutzer-Consent (externe Instanz; nicht durch UDX nachbildbar)
       v
 Plattform-native Session / Handle / App-Isolation [NICHT in W6 vorhanden]
       v
 Authentifizierter IPC-Broker [W5: Linux-UID nur, keine App-Isolation]
       v
 Versionierter Request / Capability Registry / Policy [W5, nur Fixtures]
       v
 PreviewGate(W6: In-Process-Human-Harness-Test; Dry-Run)
       |                               \
       |                                Bounded Read-Only FD Reader [W6, host-only]
       v
 FrameChangeTracker [W6; Metadaten] / GPU FrameLease-Modell [W6; mock]
       v
 Optional Connector: Digi, Nigin, anderes System [NICHT in W6]
```

***Keine* Identitätsfelder vom Client authentifizieren ihn.** `PeerIdentity` auf Python-Ebene ist ein Testsymbol, keine OS-Autorität. Ein gültiges Consent-Feld oder ein `human_approved=True` aus Client-Eingabe wäre eine kritische Sicherheitslücke. `issue` bleibt deshalb ausschließlich eine lokale Test-Harness-API und wird nicht über UDX-IPC exportiert.

## Action acceptance for eventual real OS operations

\[Allow = AuthenticatedOSPrincipal \land OSAuthorizedScope \land UserConsent \land CapabilityGrant \land Session \land Resource \land FreshFrameEpoch \land WithinBudget \land AllowedPlatform\]

W6 implementiert *nur* die Anteile Capability/Session/Resource/FrameEpoch/TTL/OneShot in einem **dry-run** In-Process-Modell. Alle realen OS-Operationen weiterhin geschlossen.

## Zu testende State Machine für eine zukünftige Aktion

- `PROPOSED` → `CONSENT_PENDING` → `AUTHORIZED` → `PREPARED` → `APPLIED` → `VERIFIED`
- Bei Denial: `DENIED`. Bei Crash nach möglicher Side-Effect: `UNCERTAIN`, nicht blind erneut ausführen.
- Ein Consent-Token ist an Display/Resource, Nutzer, App, Session, OS-Rechte, Ablaufzeit und Widerruf gebunden. Keine Erneuerung durch untrusted Clients.
- Kill-Switch und Anwesenheit: OS-sichtbare unabhängige Nutzersteuerung, jede Änderung vor Übergabe an Native-API prüfen.

## W6 Gate-Status

| Gate | Status | Evidence |
|---|---|---|
| G0: v0.5 Regression + W6 local tests | LOCAL PASS (Linux nonroot) | `evidence/W6_NONROOT_TESTS.log` |
| G1: separater Node-Parser für existierendes `udx/0.1` | LOCAL PARTIAL (W5), nicht neue Action API | test suite |
| G2: OS identity per app | FAIL/OPEN | Linux SO_PEERCRED only UID, same-UID app separation absent |
| G3: user-approved read-only host FD | PARTIAL | preopened FD, no arbitrary path, size bound; trusted picker not built |
| G3: consent for real input | FAIL/OPEN | dry-run only |
| G4: transaction ledger / rollback | FAIL/OPEN | no durable records, no side effects implemented |
| G5: real GPU / media performance | FAIL/OPEN | fixture tile microbench only |
| G6: platform attestation & review | FAIL/OPEN | Windows/iOS/Android not executed |

## W7–W9 Proposed

1. W7 Linux portal consent implementation in confined unprivileged sandbox, verified user-choice; adapter obtains file descriptors only after OS-granted selection. Prepare cross-session revocation and cancel.
2. W7 Windows gated real run: C++/WinRT or Rust windows-rs, named pipe SID DACL, overlapped timeouts, `SendInput` only after independent authorization, UIPI tests, no UIAccess as default.
3. W8 Android user-facing companion: narrow functionality with appropriate `MediaProjection` session consent, not autonomous accessibility unless verified exempt accessibility use case.
4. W8 iOS user-facing App Intents/Shortcuts/ReplayKit scopes, no background XCUITest automation.
5. W8–W9 optional Digi client adapter after all upstream security gates and independent evaluation.

## Data protection & CodeFactory handoff (not yet promoted)

- `CF-UDX-W6-01` One-shot time/epoch/resource-scoped dry-run proposal gate (in-memory simulator; **NOT a security verifier**)
- `CF-UDX-W6-02` Tile-hash changed-region signal; explicit epistemic status `STABLE_HEURISTIC`, never promises UI correctness
- `CF-UDX-W6-03` FrameLease `try/finally` closure pattern for API-owned GPU frames; mock only
- `CF-UDX-W6-04` Pre-approved read-only FD with strict byte budget, regular-file and ownership checks; host-only
- `UDX-DP-W6-A` Screen/image metadata sensitivity; user-selectable display, scoped processing, no raw frame retention by default
- `UDX-DP-W6-B` Input automation, user visibility, revocation, app-store policy and access control
- `UDX-DP-W6-C` Re-identification: frame hashes themselves may leak coarse patterns; retention/audit minimization
- `UDX-DP-W6-D` Multi-principal isolation and SOC/security controls before service deployment

Data processing compliance depends on intended country, use case, processor roles and actual implementation; no legal approval claimed.
