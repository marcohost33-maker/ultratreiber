# UDX W17 – Expliziter Pipe-Owner (Issue #2)

Datum: 2026-10-15 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED**

## Befund (Issue #2)

Auf dem gehosteten Runner `windows-latest` (Windows Server, eingebauter Administrator, erhöhtes Token) scheiterte der native Collector mit `WORKER_EXIT_NONZERO`; das allein laufende Pipe-Modul lieferte für fast alle Fälle `('DENIED', 'READ_FAILED')`. Die Suite-Jobs mit denselben 47 Fällen waren grün, ebenso Windows 11 lokal (Standardkonto).

## Ursache (belegt, nicht vermutet)

1. `build_sddl` setzte nur DACL und Label, **keinen Owner**. Der Kernel übernimmt dann den Standard-Owner des Tokens (`TokenOwner`).
2. Bei einem erhöhten Administrator ist `TokenOwner` die Gruppe `BUILTIN\Administrators` (S-1-5-32-544), nicht der Benutzer (Microsoft, "How Owners Are Assigned and Changed"; V2).
3. `client_ping` prüft vor dem ersten Byte, ob der Pipe-Owner gleich der Server-SID ist (W13, Forshaw 2019). Owner = Administratorgruppe ⇒ `PIPE_OWNER_MISMATCH`, der Client schliesst ohne zu schreiben, der Server liest `ERROR_BROKEN_PIPE` ⇒ `READ_FAILED`.
4. Warum die Suite grün war: Die Suite-Jobs laufen unter Git Bash (MSYS2, ein Cygwin-Fork). Cygwin setzt in `cygheap_user::init` `TokenOwner` auf den Benutzer (`/* Set token owner to the same value as token user */`, `winsup/cygwin/uinfo.cc`), und Kindprozesse erben diese Token-Kopie. Der Collector-Job läuft unter `pwsh` und sah das echte erhöhte Token. **Klasse: grün aus falschem Grund (Shell-Artefakt).**

Damit sind die drei Kandidaten aus Issue #2 entschieden: (1) Reihenfolge – nein; (2) geerbte Standard-Handles – nein; (3) erhöhtes Administrator-Token – **ja**, über den Standard-Owner.

## Änderung

- `udx_ref/windows_pipe.py` `build_sddl`: `O:<user SID>D:P(A;;GRGW;;;SY)(A;;GRGW;;;<user SID>)S:(ML;;NWNR;;;ME)`. Der Token-Benutzer ist immer als Owner zuweisbar, kein `ERROR_INVALID_OWNER` möglich. Owner-Rechte (implizit READ_CONTROL/WRITE_DAC) bleiben beim selben Benutzer wie bisher im Standardkonto – keine Rechteausweitung gegenüber der W14-Messung.
- **OWNER-RIGHTS-ACE** `(A;;GRGW;;;OW)` (S-1-3-4), gleiche Welle. Selbstkritik am ersten W17-Kopf: Mit explizitem Owner = Benutzer wäre bei einem **erhöhten** Server ein nicht erhöhter Prozess desselben Benutzers Owner geworden und hätte über die impliziten Owner-Rechte `WRITE_DAC` erhalten (vorher war dort die Administratorgruppe Owner, die im gefilterten Token nur deny-only ist). Zugleich ist das der seit W14 gemessene Befund UDX14-01 (`AccessCheck(MAXIMUM_ALLOWED)` = 0x16019f). Liegt ein OW-ACE vor, erhält der Owner genau dessen Rechte statt READ_CONTROL|WRITE_DAC (Microsoft, "Security Identifiers New for Windows Vista"; V2). GRGW enthält READ_CONTROL, die Owner-Prüfung des Clients bleibt also möglich. Der eigene Handle des Servers behält die beim Anlegen gewährten Rechte.
- Test dazu mit echten Win32-Handles, wie die W14-Auflage in `docs/W12_WINDOWS_LANE.md` verlangt: Kontrolle (Owner = Benutzer, ohne OW) ⇒ `CreateFileW(WRITE_DAC)` gelingt; W17 ⇒ `ERROR_ACCESS_DENIED`; Positivkontrolle `READ_CONTROL` gelingt. DACL-Readback-Test (gepinnt) erwartet jetzt drei ACEs.
- `windows/udx_sid_probe.cpp`: gleiche Owner- und OW-Parität (weiterhin **nie kompiliert**).
- `tests/test_w12_windows_pipe.py`: der portable SDDL-Paritätstest und die Fixture von `test_squatter_sees_only_identification` angepasst; die 47 gepinnten IDs sind unverändert. Die Squatter-Fixture legte ihre Pipe mit dem Standard-Deskriptor an; unter dem erhöhten Token gehörte sie damit der Administratorgruppe, der Client lehnte (korrekt) vor dem Schreiben ab und der eigentliche Fall (ein Squatter mit Owner = Benutzer erfährt höchstens Identification) lief nie. Die Fixture setzt jetzt `O:<user SID>` explizit, wie es ein Angreifer mit derselben SID tun kann. Erster CI-Lauf: 46/47 unter pwsh, genau dieser Fall rot.
- `tests/test_w17_pipe_owner.py` (neu): portable Owner-Prüfung, Live-Owner = Server-Benutzer, und ein **diskriminierender Kindprozess-Test**: Owner-fähige Gruppe als `TokenOwner` setzen, per Readback belegen, Kontrolle mit altem SDDL (erwartet: `PIPE_OWNER_MISMATCH` / `READ_FAILED` wie Issue #2), dann W17 (erwartet: Owner = Benutzer, `PEER_OK`). Ohne owner-fähige Gruppe (Standardkonto) **SKIP**, nicht grün.
- Pins (`PINNED_SOURCE_SHA256`, `PINNED_NATIVE_TEST_SHA256`) in beiden Werkzeugen und `SHA256SUMS_W12` neu. Historische Evidenzberichte behalten absichtlich die alten Hashes.
- CI: Windows-Suite zusätzlich unter `pwsh` (echter Standard-Owner); der Collector-Job ist nicht mehr `continue-on-error`.

## Belege (CI, gehosteter Runner = Windows Server, erhöhter Administrator)

| Kopf | Lauf | Ergebnis |
|---|---|---|
| `621dcc9` (Owner-Fix) | 38662557930 | Collector 46/47; rot nur `test_squatter_sees_only_identification` (Fixture, siehe oben); bash-Suite grün |
| `1f12bd8` (+ Fixture) | 38662836905 | Collector 47/47 + `--verify` OK; Suite 294 Tests OK (82 skip) unter bash **und** pwsh, Python 3.13 und 3.14; Kindprozess-Test lief (nicht übersprungen) |

Der OW-Kopf wird im selben PR erneut gefahren; ab dann liegt der Collector-Bericht je Commit als Artefakt `udx-native-evidence-<sha>` vor (30 Tage).

## Negativ-Resultate / Grenzen

- Offen bleibt UDX14-02: GW enthält `FILE_APPEND_DATA` = `FILE_CREATE_PIPE_INSTANCE` (0x4). Das OW-ACE ändert daran nichts; die Trennung von Instanz- und Datenrechten braucht weiterhin ein eigenes Bootstrap-Design.
- Ein erhöhter Administrator mit aktivierter `SeTakeOwnershipPrivilege` kann den Owner weiterhin übernehmen (Privileg, nicht DACL); ausserhalb des Same-User-Modells.
- Das Label bleibt Medium (`ME`), auch wenn der Server erhöht läuft: nicht erhöhte Prozesse desselben Benutzers dürfen sich verbinden (Same-User-vertraut, wie bisher).

- Die lokale Windows-11-Evidenz (47/47) gilt für die **vorherigen** Quellbytes; für den W17-Stand ist ein neuer lokaler Collector-Lauf nötig.
- Der gehostete Runner ist Windows Server mit erhöhtem Administrator – kein Ersatz für Standardkonto, zweites Konto, AppContainer/Low-IL-Token oder unabhängigen Review.
- Der Kindprozess-Test kann auf einem Standardkonto nicht laufen (keine Gruppe mit `SE_GROUP_OWNER`); dort belegt nur der Live-Owner-Test den Normalfall.
