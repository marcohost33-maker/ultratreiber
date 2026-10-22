# UDX W20 – Standardkonto- und Zweitkonto-Lane, C++-Parität PIPE_NAME_OCCUPIED

Datum: 2026-10-23 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED**

## Ausgangslage und Entscheid

Offen nach W19 (ROADMAP W19, Punkte 1–3):
1. Ein Lauf unter einem echten Standardkonto (ohne Administratorrechte), „falls der Owner es verlangt“.
2. Die Zweitkonto-Matrix.
3. Die C++-Parität für `PIPE_NAME_OCCUPIED`; blockiert, weil lokal kein MSVC vorhanden war.

**Entscheid zu Punkt 1:** Der lokale W18-Lauf (`docs/W18_LOCAL_WIN11_RUN.md`) zählt **nicht** als Standardkonto. Das Konto ist Mitglied von `BUILTIN\Administrators`; im gefilterten Token steht die Gruppe nur als deny-only, und ein UAC-Prompt reicht für das volle Admin-Token. Microsoft ordnet Standardbenutzern Medium und erhöhten Benutzern High zu (Mandatory Integrity Control). Ein gefiltertes Admin-Token hat damit dieselbe Integritätsstufe, ist aber nicht dieselbe Identität. Statt die Frage offen zu lassen, liefert W20 den Beleg mit echten Konten ohne Administratormitgliedschaft.

## Umsetzung

`tools/w20_account_matrix.py` läuft im CI-Job `windows-account-matrix` als erhöhter Administrator auf dem wegwerfbaren gehosteten Runner:

- **Zwei lokale Konten A und B**, angelegt mit `NetUserAdd` (`USER_PRIV_USER`), also ohne Mitgliedschaft in Administrators. `net user` scheiterte im ersten CI-Lauf: Bei Passwörtern über 14 Zeichen fragt es interaktiv (Y/N), und die Kommandozeile hätte das Passwort enthalten. Die Passwörter sind zufällig und landen weder im Bericht noch im Log.
- **Jeder Schritt läuft als geplanter Task unter dem jeweiligen Konto** (Batch-Logon, Recht `SeBatchLogonRight` über `LsaAddAccountRights`, am Ende wieder entfernt). `CreateProcessWithLogonW` aus einem Dienstkontext scheitert an den Rechten auf Window Station und Desktop. Microsoft dazu: „The application must add permission for the specified user account to the specified window station and desktop“. Der Aufgabenplaner richtet die Logon-Sitzung selbst ein.
- **Getrennte, geschützte Ausgabeordner** (`icacls /inheritance:r`): Jedes Konto darf nur in den eigenen Ordner schreiben, B kann also die Belege von A nicht verändern. Das Repository ist ein frischer Klon mit voller Historie und für die Konten nur lesbar.
- **Matrix:**

| Fall | erwartet |
|---|---|
| Token-Fakten A, B | `administrators_member: false`, `TokenElevationType` = Default (1), Integrität Medium (0x2000), verschiedene SIDs |
| Elevated Admin öffnet die Pipe von A | `ERROR_ACCESS_DENIED` (5) |
| Konto B: `client_ping` auf die Pipe von A | `OPEN_FAILED`, `open_error` 5, nichts gesendet |
| Konto A: `client_ping` auf die eigene Pipe (Kontrolle, **nach** den abgewiesenen Versuchen) | `OK`; Server `PEER_OK` mit `client_sid` = A |
| Collector als A | 47/47 PASS, `--collect` und `--verify` mit Exit 0, `UNTRUSTED_REPORT_SCHEMA_VALID` |

- **Das Verdikt fällt `evaluate()` allein aus dem Bericht.** Es ist fail-closed: jede fehlende, zusätzliche oder widersprüchliche Angabe ergibt `BLOCKED`. 10 portable Tests (`tests/test_w20_account_matrix.py`) prüfen das. Ein Testfall bildet genau den W18-Lauf ab (Administrators deny-only, Medium) und muss `NOT_STANDARD_ACCOUNT` liefern.

**C++-Parität (W19 Punkt 3):** `udx_sid_probe.cpp` sichert den Fehler von `CreateNamedPipeW` **vor** `LocalFree`, das ihn sonst überschreiben kann. Exit 21 gibt es nur bei `ERROR_ACCESS_DENIED`/`ERROR_PIPE_BUSY` **und** wenn die Namensliste den Namen exakt enthält (`FindFirstFileW`, Vergleich ohne Groß-/Kleinschreibung, wie in Python `pipe_name_present`); sonst bleibt es bei 14. Im Kreuzlauf hält der Python-Server den Namen, der C++-Probe muss mit 21 enden, und die gehaltene Instanz bedient danach noch einen Client.

## Belege (CI-Lauf 39870332609, Branch-Kopf `98413ca`, PR-Merge-Ref `b61d3ac`)

7/7 Jobs grün. Bericht `windows-account-matrix` (Artefakt `udx-w20-account-matrix-b61d3ac…`):

- A = `…-1003`, B = `…-1004`: `administrators_member: false`, `elevation_type` 1, `integrity_rid` 8192 (Medium), Session 0 (Batch-Logon).
- Runner-Admin = `…-500` (eingebauter Administrator, kein Split-Token, deshalb ebenfalls `elevation_type` 1), High (12288), Session 2.
- `admin_open`: `opened: false`, WinError 5. `second_account`: `OPEN_FAILED`, 5, `sent: false`. `same_account`: `OK`, Antwort `PEER_OK`. `server`: `PEER_OK`, `client_sid` = A.
- Collector als A: 47 Fälle, 47 PASS, `diagnostic_code` `OK`, `--collect`/`--verify` mit Exit 0, Verdikt `UNTRUSTED_REPORT_SCHEMA_VALID`, Bericht-SHA-256 `ad081076…b0a4f6`.
- Verdikt `STANDARD_ACCOUNT_LANE_OK`, `issues: []`; Aufräumen: A und B gelöscht.

C++-Kreuzlauf im selben Lauf: `cpp_server_name_occupied` → `probe_exit` 21, Halter `PEER_OK`; die übrigen vier Fälle wie in W18; MSVC 19.51.36260, `/W4 /WX`.

## Grenzen

- Die Konten laufen per Batch-Logon in **Session 0**, nicht interaktiv. Der Sitzungsvergleich des Servers wurde damit nur für „gleiche Session“ geprüft; ein Zweitkonto in einer **anderen interaktiven** Sitzung (RDP, Fast User Switching) ist nicht abgedeckt.
- Das Zweitkonto wird bereits am DACL abgewiesen, die Owner- und Token-Prüfung danach wird dabei nicht erreicht. Das ist die beabsichtigte erste Verteidigungslinie, belegt aber nichts über die späteren Prüfungen bei fremden Konten.
- Weiter offen: echte AppContainer- und Low-IL-Principals als eigene Prozesse, Dienstkonto, entfernter Host, C++-Deadlines (UDX14-04, Rest), unabhängige Attestierung. Es gibt kein Release und keine Sicherheitsfreigabe.
- Der Lauf findet auf Windows Server (gehosteter Runner) statt, nicht auf Windows 11. Für Windows 11 bleibt `docs/W18_LOCAL_WIN11_RUN.md` (gefiltertes Admin-Token) der Beleg.
