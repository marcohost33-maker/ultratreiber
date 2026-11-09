# W25 – Echte Low-IL-, AppContainer- und Restricted-Token-Principals (nativ)

Stand 2026-11-09 · Forschung, **kein Release, keine Sicherheitsfreigabe** · Basis: W24 (PR #5)

## Ausgangslage

Offener Roadmap-Punkt W24 (1): „echte AppContainer- / Low-IL-Principals als eigene
Prozesse“. Die serverseitigen Ablehnungen `INTEGRITY_TOO_LOW`, `APPCONTAINER_CLIENT`
und `RESTRICTED_TOKEN` waren bis W24 nur mit **injizierten** Token-Fakten belegt
(Fault-Injection-Hälfte der 47 gepinnten Fälle in `tests/test_w12_windows_pipe.py`).
W20 hat ein zweites *Konto* geprüft, aber keine abgeschotteten Principals desselben
Benutzers.

## Umsetzung

`tools/w25_principal_matrix.py` startet den kompilierten C++-Client
(`windows/udx_sid_client.cpp`, MSVC `/W4 /WX`, gebaut mit derselben Funktion wie der
W18-Kreuzlauf) als **echten, eigenen Prozess** unter vier Principals:

| Principal | Erzeugung |
|---|---|
| `same_token` | `CreateProcessAsUserW` mit unverändertem Duplikat des eigenen Tokens (Positivkontrolle für den Launcher-Pfad) |
| `low_il` | dasselbe Duplikat, Integritätslabel auf Low (`S-1-16-4096`) gesetzt |
| `appcontainer` | `CreateProcessW` mit `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` für ein Wegwerf-Profil ohne Capabilities (danach gelöscht) |
| `restricted` | `CreateRestrictedToken` mit Benutzer + allen aktivierten Gruppen als einschränkende SIDs. Das ist die kleinste Änderung, die der Kernel als restricted meldet (`IsTokenRestricted`). Sie prüft die Server-Kontrolle; sie ist **keine Sandbox**. |

**Kein Fehlgrün durch den Launcher:** Jedes Kind wird `CREATE_SUSPENDED` erzeugt.
Seine Token-Fakten (Benutzer-SID, Integritäts-RID, AppContainer-Flag und -SID,
restricted) werden aus dem Kindprozess gelesen, **bevor** es läuft. Ein Launcher, der
die Einschränkung still nicht anwendet, ergibt `CHILD_INTEGRITY_WRONG` usw.

**Ablehnung beim Öffnen ist unterscheidbar:** Der C++-Client schreibt vor Exit 1 genau
eine stderr-Zeile `UDX_CLIENT_OPEN_ERROR <n>`. Exit 1 allein bedeutete auch „Pipe bis
zur Frist nicht vorhanden“. Die Exit-Codes sind unverändert. Der Pin des Clients ist in
W14-Gate und W15-Collector nachgeführt, `SHA256SUMS_W12` neu erzeugt.

### Zwei Schichten, 11 Fälle

- **Schicht 1, Produktions-SD** (`build_sddl`; das C++-Probe nutzt dieselbe SDDL):
  - Low IL und AppContainer müssen **beim Öffnen** mit `ERROR_ACCESS_DENIED` scheitern.
    Gründe: Mandatory Label `NW|NR` auf Medium, und die DACL hat keine AppContainer-ACE.
    Der Server darf keinen Client sehen.
  - Der Restricted-Token passiert die DACL, weil seine einschränkende Menge den Benutzer
    enthält. Die Token-Prüfung des Servers muss ihn ablehnen, nachdem sie den Benutzer
    identifiziert hat.
- **Schicht 2, Kontroll-SD** (nur im Harness, absichtlich geschwächt: `+(A;;0x12008b;;;AC)`
  und Label `LW` statt `ME`):
  - Das Öffnen gelingt. Jetzt muss der **Server selbst** das echte Token ablehnen.
  - Eine `same_token`-Kontrolle zeigt, dass die Kontroll-SD weiterhin bedient.

`evaluate()` entscheidet allein aus dem Bericht und ist fail-closed. Geprüft werden:

- exakte Fallmenge und Fallform
- Kind-Fakten je Principal
- Client-Exit und Open-Fehler
- begrenzte Kindlaufzeit (≤ 15 s)
- Server-Entscheid, identifizierter Benutzer und gesendet/nicht gesendet
- SDDL, unabhängig nachgerechnet (nicht aus dem Modul unter Test)
- Profil gelöscht
- kein Release-Anspruch

Abgesichert ist das durch 32 portable Tests (`tests/test_w25_principal_matrix.py`) und
8/8 diskriminierende Mutationen (`evidence/w25_dk_spec.json`, jede macht ihren Test rot;
lokal mit `python -B` geprüft).

## Nativer Beleg

CI-Lauf [42587069609](https://github.com/marcohost33-maker/ultratreiber/actions/runs/42587069609),
PR #6, Kopf `d180f6c`. **8/8 Jobs grün**: Suiten Ubuntu/Windows × 3.13/3.14, nativer
Collector 47/47 + `--verify`, C++-Kreuzlauf 11/11, Konto-Matrix W20 und die neue
`windows-principal-matrix`. Verdikt `PRINCIPAL_MATRIX_OK`, `issues: []`, Bericht-SHA-256
`d4b94c22bfdb7a82d01d2c6877c366fef76aca28b91c0a2df1bbf55361cee243`, Artefakt
`udx-w25-principal-matrix-68801ef…` (30 Tage). Der erste Lauf auf `f3d4346` (Lauf
42586824276) war ebenfalls grün, Verdikt `PRINCIPAL_MATRIX_OK`.

| Fall | Kind: RID / AC / restricted | Client-Exit | Open-Fehler | Server |
|---|---|---|---|---|
| `py_same_token` | 0x3000 / – / – | 0 | – | `PEER_OK` |
| `py_low_il` | 0x1000 / – / – | 1 | 5 | `DENIED/CONNECT_TIMEOUT` (kein Client) |
| `py_appcontainer` | 0x1000 / ja / – | 1 | 5 | `DENIED/CONNECT_TIMEOUT` (kein Client) |
| `py_restricted` | 0x3000 / – / ja | 3 | – | `DENIED/RESTRICTED_TOKEN` |
| `ctl_same_token` | 0x3000 / – / – | 0 | – | `PEER_OK` |
| `ctl_low_il` | 0x1000 / – / – | 3 | – | `DENIED/INTEGRITY_TOO_LOW` |
| `ctl_appcontainer` | 0x1000 / ja / – | 3 | – | `DENIED/INTEGRITY_TOO_LOW` |
| `cpp_same_token` | 0x3000 / – / – | 0 | – | Exit 0 |
| `cpp_low_il` | 0x1000 / – / – | 1 | 5 | Exit 22 (Frist, kein Client) |
| `cpp_appcontainer` | 0x1000 / ja / – | 1 | 5 | Exit 22 (Frist, kein Client) |
| `cpp_restricted` | 0x3000 / – / ja | 3 | – | Exit 20 |

Die Client-Laufzeit lag in allen Fällen bei 14–20 ms: Abweisung oder Antwort kamen
sofort, nichts lief in eine Frist. `same_token` ist High (0x3000), weil der Runner ein
erhöhter eingebauter Administrator ist.

## Befunde

1. **Die Produktions-SD weist Low IL und AppContainer bereits beim Öffnen ab**, gegen
   beide Server-Implementierungen (Python und C++). Der Server sieht keinen Client und
   wendet keine Ressourcen über die eigene Frist hinaus auf. Das ist die erste
   Verteidigungslinie.
2. **Die Token-Prüfungen der Server greifen mit echten Kernel-Tokens.** Mit geschwächter
   SD lehnt der Python-Server Low IL und AppContainer mit `INTEGRITY_TOO_LOW` ab, und
   zwar erst *nachdem* er den Benutzer korrekt identifiziert hat. Den Restricted-Token
   lehnen Python (`RESTRICTED_TOKEN`) und C++ (Exit 20) mit der Produktions-SD ab.
3. **Designfakt:** Ein Standard-AppContainer-Token ist immer Low IL. Weil der Server die
   Integrität zuerst prüft, erreicht ein solcher Client die `APPCONTAINER_CLIENT`-Prüfung
   nie. Sie ist Defense in Depth und bleibt nur durch Fault Injection belegt.
   Konsequenz: Ein künftiger Broker für AppContainer-Clients müsste die Integritätsregel
   *bewusst* ändern. Er bräuchte dann eine eigene Package-SID-Regel; „AppContainer
   zulassen“ allein wäre falsch.
4. Der Restricted-Token wird von der DACL **nicht** abgewiesen, wenn seine einschränkende
   Menge den Benutzer enthält. Die Server-Prüfung ist hier die einzige Schicht. Sie ist
   damit nativ belegt.

## Grenzen (nicht belegt)

- Gehosteter Runner: Windows Server, erhöhter eingebauter Administrator. Nicht Windows 11,
  kein Standardkonto als Elternprozess (W20 deckt das Standardkonto für die Python-Lane ab).
- Zweite **interaktive** Sitzung, Dienstkonto, entfernter Host.
- AppContainer mit Capabilities. Medium-IL-AppContainer-Tokens lassen sich mit den
  Standard-APIs nicht erzeugen.
- Restricted-Token mit *engerer* einschränkender Menge (ohne Benutzer): Er würde schon an
  der DACL scheitern. Nicht als eigener Fall gemessen.
- Eine Low-IL-, AppContainer- oder Restricted-Variante als **Server** (Squatting-Szenario
  aus einer Sandbox heraus) ist nicht geprüft.
- Unabhängige Attestierung; G2-App (OS-App-Identität) bleibt FAIL/OPEN.

## Quellen (Microsoft Learn, abgerufen 2026-11-09)

- Mandatory Integrity Control: https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
- AppContainer isolation: https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
- Launch an AppContainer (SECURITY_CAPABILITIES): https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- CreateRestrictedToken: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
- CreateProcessAsUserW: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw
