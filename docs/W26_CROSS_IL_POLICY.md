# UDX W26 – Cross-IL-Politik: Medium ↔ High desselben Benutzers (UT-A7-01/-03)

Datum: 2026-11-15 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED**
Basis: PR #6, Kopf `a736ca8` (W25.2 + UT6-02). Keine Verhaltensänderung an Server oder Clients.

## Ausgangslage

Die A7-Runde vom 2026-11-11 stellte zu `a736ca8` drei Fragen (Auftrag
`007acc2/01_AUFTRAEGE/AUFTRAG_007acc2_A7_Sammel-5PR_…_2026-11-11.md`):

- **UT-A7-01:** Weist die Regel „Label gleich eigener Stufe“ einen legitimen Client fälschlich ab
  (Medium-Client gegen erhöhten High-Server und umgekehrt)?
- **UT-A7-02:** Stimmt die C++-Logik mit der Python-Referenz überein?
- **UT-A7-03:** Brechen AppContainer-/LPAC-Clients die Gleichheitsregel?

Die Antworten vom 2026-11-12 widersprechen sich: Gemini bestätigt UT-A7-01 und UT-A7-03 (E1) und
schlägt `pipe_label >= client_il` vor; GPT-6 stuft sie als nicht prüfbar ein (E0) und verlangt ein
explizites IPC-/Rollenmodell statt einer „blinden >= Medium-Umstellung“. **Kein Prüfer hat für
dieses Repository etwas unter Windows ausgeführt.** Die Messungen dazu fehlten: Weder ein echter
Medium-Client gegen eine echte High-Pipe noch ein erhöhter Client gegen einen Medium-Squatter war
je gelaufen.

## Entscheid (ADR-UDX-007, vorgeschlagen)

Ein UDX-Endpunkt bedient genau ein Prinzipal: **Benutzer-SID auf der eigenen Integritätsstufe des
Servers**. Medium ↔ High und Sandbox-Clients (AppContainer, LPAC) werden bewusst abgewiesen.

| Richtung | Wer weist ab | Warum das kein Fehler 2. Art ist |
|---|---|---|
| Medium-Client → High-Pipe | **Kernel** beim Öffnen (Fehler 5): Token-Policy `NO_WRITE_UP` gegen Label `HI` mit NW | keine Client-Regel kann diesen Client zulassen; nur ein geschwächtes Server-Label, das jeden Medium-Prozess des Benutzers schreiben liesse |
| High-Client → Medium-Pipe | **UT6-02-Client-Regel** (C++ Exit 7, Python `PIPE_LABEL_MISMATCH`) | ein Medium-Squatter mit der projekteigenen Medium-SD ist von einem legitimen Medium-Server nicht unterscheidbar |
| Low / AppContainer / LPAC | Kernel oder DACL beim Öffnen | ausserhalb des Rollenmodells; Unterstützung bräuchte einen eigenen Opt-in-Endpunkt |

Geminis Client-Regel `label >= c` und die geltende Regel `label == c` unterscheiden sich nur bei
einem Label **über** der Stufe des Clients mit NO_WRITE_UP. Genau dort verweigert der Kernel das
Öffnen bereits. Auf jeder Eingabe, die der Kernel durchlässt, entscheiden beide gleich (Tabelle
in ADR-UDX-007 §4). Deshalb bleibt die Gleichheit.

## Umsetzung (nur Prüfstand)

`tools/w25_principal_matrix.py`, Modus `elevated_admin`:

- **Prinzipal `medium_il`:** Duplikat des Eltern-Tokens, Integritätslabel auf `S-1-16-8192`
  abgesenkt (wie `low_il`, nur Medium). Token-Fakten werden vor dem Start gelesen; `evaluate()`
  verlangt Medium, gleiche SID, kein AppContainer, nicht restricted.
- **`py_medium_il`, `cpp_medium_il`:** C++-Client als `medium_il` gegen den Python- bzw.
  C++-Server mit Produktions-SD (Label `HI`). Erwartet: Exit 1, `UDX_CLIENT_OPEN_ERROR 5`, Server
  sieht keinen Client (`DENIED/CONNECT_TIMEOUT` bzw. Exit 22).
- **`squat_medium_il_production`:** Ein `medium_il`-Prozess legt den Produktionsnamen zuerst an,
  mit `build_sddl(sid, eigene Stufe)` – derselben Zeichenkette, die ein Medium-Server dieses
  Projekts setzt (Owner = Benutzer, gleiche DACL, Label `ME` mit NW|NR). Danach verbinden der
  C++-Client (erhöht, Kindprozess) und der Python-Client (erhöht, Elternprozess). Verlangt, alles
  fail-closed:
  - Squatter-SD exakt `production_sddl(sid, 0x2000)`, Label 0x2000, Owner = Benutzer.
  - C++ Exit 7 **und** genau eine Zeile `UDX_CLIENT_PIPE_LABEL count=1 rid=8192 … own=12288`
    (Exit 7 allein ist unspezifisch; nur `rid` gegen `own` zeigt, dass die Gleichheitsregel
    gegriffen hat und nicht Anzahl, Flags, Maske oder die Medium-Untergrenze).
  - Python `PIPE_LABEL_MISMATCH`, `sent=False`, `pipe_label=0x2000` **und** `pipe_owner` =
    Benutzer: Die Owner-Prüfung muss bestanden sein, sonst wäre nicht das Label der Trenner.
  - Squatter hat **0 Bytes** empfangen.
  Unter der alten W25.2-Regel (`label >= Medium`) hätten beide erhöhten Clients geschrieben.
- Der Standardkonto-Modus bleibt unverändert (dort ist `medium_il` gleich `same_token`).

UT-A7-02: Die C++-Bedingung (`labels != 1 || label_rid < MEDIUM || !label_effective ||
label_rid != self_rid`) und `_verify_pipe_label` entscheiden dieselben Fälle; die Reihenfolge der
Python-Gründe ist feiner. Der Squat-Fall prüft beide Clients gegen dieselbe echte Medium-Pipe.

## Absicherung

- 12 neue portable Tests (`CrossIntegrityW26` in `tests/test_w25_principal_matrix.py`); Suite lokal
  (Linux, Python 3.13.18): **459 OK, 111 übersprungen** (Windows-only).
- `evidence/w26_dk_spec.json`: **12/12** diskriminierende Mutationen töten ihren Test (lokal, mit
  `-B`). Die W25-Spezifikation bleibt bei **39/39**. Ein erster Lauf meldete DK28 als überlebend;
  Ursache war der Bytecode-Cache des Mutationsläufers (Mutation `HI`→`ME` gleicher Länge in
  derselben Sekunde, `.pyc` per mtime+Grösse als gültig gewertet), nicht der Code.
- Nachgetragen aus CI-Lauf 42939565127 (Kopf `a736ca8`), Modus `elevated_admin`:
  `ctl_appcontainer` und `ace_appcontainer` Exit 1, Fehler 5, Server `DENIED/CONNECT_TIMEOUT`.
  Die UT6-02-Vorhersage ist damit gemessen.

## Nativer Beleg

**Ausstehend** bis zum ersten grünen CI-Lauf dieses Stands (Job `windows-principal-matrix`).
Bis dahin sind die drei neuen Fälle **Vorhersagen**, keine Belege.

## Grenzen

- Gehosteter Runner: Windows Server, eingebauter Administrator (RID 500, kein Split-Token). Ein
  UAC-gefiltertes Token eines Admin-Kontos auf Windows 11 ist nicht dasselbe; dort bleibt der
  W18-Lauf (`docs/W18_LOCAL_WIN11_RUN.md`) der einzige Beleg.
- Das `medium_il`-Token ist ein abgesenktes Duplikat, nicht das gefilterte Token einer echten
  UAC-Anmeldung (andere Gruppen, andere Privilegien). Für die Integritätsprüfung zählt nur die Stufe.
- LPAC, UIAccess, virtualisierte Tokens, zweite interaktive Sitzung: nicht gemessen.
- Keine Server-Authentisierung: ADR-UDX-006 und G2-App gelten unverändert. Kein Release, keine
  Sicherheitsfreigabe.

## Quellen (abgerufen 2026-11-15)

- MS-DTYP 2.4.8 TOKEN_MANDATORY_POLICY: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/de8373ec-206f-4dc8-b3fe-c638fed7b282
- Mandatory Integrity Control: https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
- Raymond Chen, LPAC (2022-05-02): https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550
- MSRC Windows Security Servicing Criteria: https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria
