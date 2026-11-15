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

- 12 neue portable Tests (`CrossIntegrityW26` in `tests/test_w25_principal_matrix.py`; W26.1: +4 in `TokenPremisesW26`, +9 in `tests/test_w26_dk_runner.py`); Suite lokal
  (Linux, Python 3.13.18): **459 OK, 111 übersprungen** (Windows-only).
- `evidence/w26_dk_spec.json`: **12/12** diskriminierende Mutationen töten ihren Test (lokal, mit
  `-B`). Die W25-Spezifikation bleibt bei **39/39**. Ein erster Lauf meldete DK28 als überlebend;
  Ursache war der Bytecode-Cache des Mutationsläufers (Mutation `HI`→`ME` gleicher Länge in
  derselben Sekunde, `.pyc` per mtime+Grösse als gültig gewertet), nicht der Code.
- Nachgetragen aus CI-Lauf 42939565127 (Kopf `a736ca8`), Modus `elevated_admin`:
  `ctl_appcontainer` und `ace_appcontainer` Exit 1, Fehler 5, Server `DENIED/CONNECT_TIMEOUT`.
  Die UT6-02-Vorhersage ist damit gemessen.

## Nativer Beleg (CI-Lauf [43767612816](https://github.com/marcohost33-maker/ultratreiber/actions/runs/43767612816), Kopf `7f1735a`, PR #7, 8/8 Jobs grün)

Windows Server (gehosteter Runner), Python 3.13.17, MSVC-Build aus demselben Lauf.

| Fall (Modus `elevated_admin`, Eltern = eingebauter Administrator, IL 0x3000) | Gemessen |
|---|---|
| `py_medium_il` | Kind IL 0x2000, gleiche SID; `client_exit=1`, `open_error=5`; Server `DENIED/CONNECT_TIMEOUT` |
| `cpp_medium_il` | Kind IL 0x2000; `client_exit=1`, `open_error=5`; C++-Server Exit 22 (kein Client) |
| `squat_medium_il_production` | Squatter IL 0x2000, `created=True`, Owner = Benutzer, Label 0x2000; C++ Exit 7 mit `UDX_CLIENT_PIPE_LABEL count=1 rid=8192 flags=0 mask=3 own=12288`; Python `PIPE_LABEL_MISMATCH`; **Squatter empfing 0 Bytes** |

- Verdikt `PRINCIPAL_MATRIX_OK`, `issues: []`, Bericht-SHA-256
  `8890ceabe3f56f3ee6ee3a50a638aec00abde503f9f2215a9ae76ba816a9a26c` (erhöhter Admin) und
  `c18f1b79a1d8d957a18c537f6e400705bc30a996e7fd328586eb2ba20a9caed9` (Standardkonto, ohne die neuen
  Fälle, alle W25-Fälle unverändert). Artefakt `udx-w25-principal-matrix-e00369aa…` (PR-Merge-Ref).
- Alle übrigen Fälle beider Modi wie in Lauf 42939565127; Collector, Kontomatrix, C++-Kreuzlauf
  und die Suiten (Ubuntu/Windows, Python 3.13/3.14) grün.
- Die Maske `mask=3` (NW|NR) und `flags=0` (nicht INHERIT_ONLY) zeigen: Das Label des Squatters war
  wirksam und vollständig; abgewiesen hat allein `rid != own`.

Damit sind beide Richtungen von UT-A7-01 nativ gemessen: Medium → High verweigert der Kernel beim
Öffnen, High → Medium verweigert die UT6-02-Regel gegen einen Squatter, der Owner, DACL und Label
eines echten Medium-Servers trägt.

## W26.1 – Selbstreview: Befunde und Härtung (2026-11-15)

Kritische Nachprüfung der eigenen W26-Lieferung und der Evidenzkette des Repos. Befunde
getrennt nach „am Ziel-Repo“ und „an unserem Prüfwerkzeug“ (Vermerk 007acc2 vom 15.11.).

| ID | Art | Befund | Behebung |
|---|---|---|---|
| W26-SR-01 | Repo, Evidenzkette | Die DK-Spezifikationen („n/n getötet“) liefen nur mit einem externen, privaten Runner; nicht reproduzierbar (A7 UT6-04). | `tools/dk_runner.py`: Arbeitskopie statt Baum-Mutation, `-B` + `PYTHONDONTWRITEBYTECODE`, Byte-I/O, Anker genau einmal, Skip/Timeout zählen nie als Kill, Pfade bleiben in der Kopie. 9 eigene Tests (`tests/test_w26_dk_runner.py`). CI führt die Specs aus. |
| W26-SR-02 | Repo, Evidenzkette | Replay aller 12 Specs am Kopf: **14 veraltete Anker** (W12 4, W13 2, W14 5, W18 1, W24 1): Der Code hat sich seit der jeweiligen Welle geändert, die Mutation trifft nichts mehr. 49 Fälle sind Windows-only und liefen nie reproduzierbar. | Historische Specs bleiben unverändert (Beleg ihrer Welle). Die noch relevanten Schutzmechanismen sind neu verankert: `w26_carryover_dk_spec.json` (7 portabel) und `w26_carryover_native_dk_spec.json` (5 nativ). Native Specs W19, W25.2, W26-Carry-over laufen im Windows-Suite-Job. |
| W26-SR-03 | Werkzeug | Bytecode-Falle: `.pyc` gilt bei gleicher mtime-Sekunde und Grösse als gültig (PEP 552, Standard `TIMESTAMP`); eine gleich lange Mutation oder ihre Wiederherstellung kann maskiert werden (falsches „DK28 überlebt“). | Runner ohne Bytecode-Cache; Regression im Runner-Test gepinnt. |
| W26-SR-04 | Werkzeug (Windows) | Text-Modus-Schreiben übersetzt unter Windows LF→CRLF; Mutation **und** Wiederherstellung hätten jede Datei auf CRLF gestellt und Hash-Pins gebrochen (falsche Kills). | Nur Byte-I/O; Test mit CRLF-Inhalt prüft byte-genaue Wiederherstellung. |
| W26-SR-05 | Werkzeug | `datei` aus einer Spec wurde ungeprüft an den Arbeitspfad gehängt (`../` hätte ausserhalb geschrieben). | `_inside()`: nur Dateien innerhalb der Arbeitskopie; Test mit `../` und absolutem Pfad. |
| W26-SR-06 | Repo, Log | Die SQUAT-Logzeile druckte `owner_is_user=True`, wenn **irgendein** Owner existierte (Admin-Squatter: tatsächlich `BUILTIN\Administrators`). Das Verdikt war korrekt (`evaluate()` prüft separat), die Logzeile irreführend. | `owner=user|administrators|other|none`; Test + DK15. |
| W26-SR-07 | Repo, Prämisse | „Abweisung beim Öffnen durch NO_WRITE_UP“ (W25.2, ADR-007 §2) war erschlossen, nie als Token-Fakt gemessen. ADR-007 §4 („identisch auf jeder Eingabe, die der Kernel durchlässt“) gilt nur bei dieser Policy. | Matrix liest `TokenMandatoryPolicy` (27), `TokenUIAccess` (26), `TokenVirtualizationEnabled` (24); abgesenkte Kinder müssen NO_WRITE_UP tragen, kein Kind UIAccess/Virtualisierung. ADR §4 präzisiert (`TOKEN_MANDATORY_POLICY_OFF` braucht `SeTcbPrivilege`). DK13/DK14. |
| W26-SR-08 | Doku | ADR §3 sagte „byte-for-byte indistinguishable“; gleich ist die **Sicherheitsbeschreibung**, nicht die Pipe-Modus-Flags. | Präzisiert. |
| W26-SR-09 | Doku, Quelle | ADR §6 stützte die UAC-Einordnung auf Sekundärquellen. | MSRC-Seite gelesen: UAC = Defense-in-depth, „Intent is to service? No“; AppContainer-Sandbox = gewartete Grenze. learn.microsoft.com war aus der Sitzung nicht erreichbar (DNS), MS-DTYP-Zitat stammt aus dem Suchergebnis. |

Lokaler Stand nach W26.1: Suite grün; DK-Replay aller **aktiven** portablen Specs **84/84**
(public_prep 13, W16 5, W20 5, W25 39, W26 15, Carry-over 7). Native Specs: Ergebnis im
CI-Artefakt `udx-dk-windows-latest-<sha>`.

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
