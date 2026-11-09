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
3. **Designfakt:** Ein Standard-AppContainer-Token ist immer Low IL (Microsoft Learn,
   CreateProcessInSandbox: bei AppContainer ist die Integrität immer Low). Weil der Server die
   Integrität zuerst prüft, erreicht ein solcher Client die `APPCONTAINER_CLIENT`-Prüfung
   nie. Sie ist Defense in Depth und bleibt nur durch Fault Injection belegt.
   Konsequenz: Ein künftiger Broker für AppContainer-Clients müsste die Integritätsregel
   *bewusst* ändern. Er bräuchte dann eine eigene Package-SID-Regel; „AppContainer
   zulassen“ allein wäre falsch.
4. Der Restricted-Token wird von der DACL **nicht** abgewiesen, wenn seine einschränkende
   Menge den Benutzer enthält. Die Server-Prüfung ist hier die einzige Schicht. Sie ist
   damit nativ belegt.

## W25.1 – kritische Nachprüfung und Härtung (2026-11-09)

Eine Selbstprüfung der W25-Lieferung fand fünf Lücken. Alle sind geschlossen und nativ
belegt.

| # | Lücke in W25 | Härtung W25.1 | Prüfung |
|---|---|---|---|
| 1 | Kinder erbten jedes vererbbare Handle des Harness (`bInheritHandles=TRUE` ohne Allow-List): ein Sandbox-Test mit potenziell fremden Handles ist methodisch unsauber. | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` mit genau der stdout/stderr-Pipe, für alle Principals (`STARTUPINFOEX` auch für `CreateProcessAsUserW`). | `inherit == handle_list:1` je Fall |
| 2 | C++-Exit 20 war unspezifisch: `cpp_restricted` zeigte nicht, welche Prüfung griff. | Der Probe schreibt bei Ablehnung eine stderr-Zeile `UDX_PROBE_DENIED level= rid= appc= restricted= session_ok= sid_ok=`. Die Entscheidungslogik ist unverändert. | `restricted=1` muss der **einzige** fehlschlagende Fakt sein |
| 3 | Die Ursache der Abweisung beim Öffnen war nicht zugeordnet (Label oder DACL?). | Zwei weitere Harness-SDs (`label_only`, `acace_only`) und vier Fälle. | Server-SD je Fall gleich der deklarierten Variante |
| 4 | Der Elternprozess war immer der erhöhte Admin (größter Vorbehalt). | `--mode standard_account`: Die ganze Matrix läuft als Wegwerfkonto nur in `Users` (W20-Task-Mechanik). | Elternfakten passen zum Modus (gefiltertes Admin-Token ≠ Standardkonto); Konto, Recht und Arbeitsordner gelöscht |
| 5 | Das Arbeitsverzeichnis mit der AppContainer-ACE blieb liegen; die Binaries waren nicht an den Build gebunden. | Verzeichnis wird gelöscht; `used`-Hash muss gleich dem `built`-Hash sein. | `cleanup.workdir == deleted`, `BINARY_NOT_THE_BUILT_ONE` |

### Falsifikation (Messung widerlegt eine eigene Hypothese)

W25.1 hatte erwartet: Bei vorhandener AC-ACE und beibehaltenem **Medium**-Label weist das
Label allein den AppContainer ab (`ace_appcontainer` → Open-Fehler 5). CI-Lauf
[42593419596](https://github.com/marcohost33-maker/ultratreiber/actions/runs/42593419596)
zeigte das Gegenteil: Der AppContainer **öffnet** die Pipe trotz `S:(ML;;NWNR;;;ME)`, und
erst die Integritätsprüfung des Servers lehnt ab (`INTEGRITY_TOO_LOW`). Das entspricht der
Lowbox-Zugriffsprüfung des Kernels: Ist das Objektlabel ≤ Medium, gilt die
Integritätsprüfung als bestanden, und die AppContainer-DACL-Prüfung entscheidet (Forshaw,
*Windows Security Internals*, Kapitel Access Checking / Lowbox). Die Erwartung wurde auf den
Messwert gesetzt und begründet.

**Konsequenz für den Entwurf:** Für AppContainer-Clients ist die DACL die **einzige**
OS-Barriere. Eine `AC`- oder Package-SID-ACE in der Pipe-DACL öffnet die Pipe für jeden
AppContainer, auch bei Medium-Label. Danach bleibt nur die Server-Prüfung. Für Low IL ohne
AppContainer ist umgekehrt das Label die einzige Barriere (`lbl_low_il` öffnet).

### Nativer Beleg W25.1

CI-Lauf [42593714723](https://github.com/marcohost33-maker/ultratreiber/actions/runs/42593714723),
Kopf `af1f79a`: **8/8 Jobs grün**.

- Elternprozess erhöhter Admin (`…-500`, High, Admin): 16/16, `PRINCIPAL_MATRIX_OK`,
  Bericht-SHA-256 `3309a32cc97b941d6fa50829617c5c77dcb45cb396d39a4187e00efe6a8c5af6`.
- Elternprozess Standardkonto (`…-1003`, Medium, `administrators_member: false`): 16/16,
  `PRINCIPAL_MATRIX_OK`, Bericht-SHA-256
  `092fda1dab88aabc7b48bfdd2fe934252478fb176092985ce3282550bbb46c48`. Konto, Batch-Logon-Recht
  und `C:\udx_w25` danach entfernt.

| Fall (SD) | Principal | Client-Exit / Open-Fehler | Server | Aussage |
|---|---|---|---|---|
| `lbl_low_il` (label_only) | Low IL | 3 / – | `INTEGRITY_TOO_LOW` | Das Label war die einzige OS-Barriere für Low IL |
| `lbl_appcontainer` (label_only) | AppContainer | 1 / 5 | `CONNECT_TIMEOUT` | Die DACL allein weist AppContainer ab |
| `ace_appcontainer` (acace_only) | AppContainer | 3 / – | `INTEGRITY_TOO_LOW` | Das Medium-Label weist AppContainer **nicht** ab (falsifiziert) |
| `ace_same_token` (acace_only) | Elterntoken | 0 | `PEER_OK` | Die Kontroll-SD bedient |
| `cpp_restricted` (production) | restricted | 3 | Exit 20, `restricted=1 appc=0 session_ok=1 sid_ok=1 level=1 rid=Eltern` | Nur das Restricted-Flag lehnte ab |

Die übrigen 11 Fälle verhalten sich in beiden Modi wie in W25. `same_token` und
`restricted` laufen unter dem Standardkonto mit Medium (0x2000). Jedes Kind lief mit
`handle_list:1`. Die Client-Laufzeiten lagen bei 8–13 ms.

Absicherung: 46 portable Tests, darunter ein Test, der jeden DK-Anker auf genau ein
Vorkommen prüft (ein veralteter Anker fiel beim Nachlauf auf). Dazu 14/14 diskriminierende
Mutationen (`evidence/w25_dk_spec.json`).

## Grenzen (nicht belegt)

- Gehosteter Runner: Windows Server, nicht Windows 11. Das Standardkonto läuft per
  Batch-Logon in Session 0, nicht interaktiv.
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
