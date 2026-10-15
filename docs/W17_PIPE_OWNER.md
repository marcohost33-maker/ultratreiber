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
- `windows/udx_sid_probe.cpp`: gleiche Owner-Präfix-Parität (weiterhin **nie kompiliert**).
- `tests/test_w12_windows_pipe.py`: nur der portable SDDL-Paritätstest angepasst; die 47 gepinnten IDs sind unverändert.
- `tests/test_w17_pipe_owner.py` (neu): portable Owner-Prüfung, Live-Owner = Server-Benutzer, und ein **diskriminierender Kindprozess-Test**: Owner-fähige Gruppe als `TokenOwner` setzen, per Readback belegen, Kontrolle mit altem SDDL (erwartet: `PIPE_OWNER_MISMATCH` / `READ_FAILED` wie Issue #2), dann W17 (erwartet: Owner = Benutzer, `PEER_OK`). Ohne owner-fähige Gruppe (Standardkonto) **SKIP**, nicht grün.
- Pins (`PINNED_SOURCE_SHA256`, `PINNED_NATIVE_TEST_SHA256`) in beiden Werkzeugen und `SHA256SUMS_W12` neu. Historische Evidenzberichte behalten absichtlich die alten Hashes.
- CI: Windows-Suite zusätzlich unter `pwsh` (echter Standard-Owner); der Collector-Job ist nicht mehr `continue-on-error`.

## Negativ-Resultate / Grenzen

- Die lokale Windows-11-Evidenz (47/47) gilt für die **vorherigen** Quellbytes; für den W17-Stand ist ein neuer lokaler Collector-Lauf nötig.
- Der gehostete Runner ist Windows Server mit erhöhtem Administrator – kein Ersatz für Standardkonto, zweites Konto, AppContainer/Low-IL-Token oder unabhängigen Review.
- Der Kindprozess-Test kann auf einem Standardkonto nicht laufen (keine Gruppe mit `SE_GROUP_OWNER`); dort belegt nur der Live-Owner-Test den Normalfall.
