# UDX W30 – C++-Cancel-Pfad auf echtem Kernel (Exit 31, Completion im Rennen), 100-fache Grenzläufe

Datum: 2026-11-22 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED / KEIN RELEASE**

## Ausgangslage

W24 begrenzte jede C++-Pipe-Operation (`windows/udx_bounded_pipe_io.hpp`). Zwei Zweige von
`udx::cancel_and_settle` waren aber nur durch Quellwächter und Mutationen gedeckt, nie auf
einem echten Kernel erreicht (Roadmap W24 Punkt 2, W26 Punkt 3, W28 Punkt 4):

1. **Exit 31**: Die abgebrochene I/O ist nach der Gnadenfrist (1 s) nicht abgeschlossen. Der
   Einmalprozess beendet sich, statt einen Stack-Frame mit lebendem `OVERLAPPED` zu verlassen.
2. **Completion im Rennen**: Die I/O schließt nach der Frist, aber vor `CancelIoEx` ab.
   Microsoft Learn: Ein abgebrochener Vorgang kann trotzdem normal abschließen, weil die
   Abbruchanforderung zu spät kam. Das Ergebnis muss ein Timeout bleiben, nicht ein Erfolg.

Beide lassen sich ohne Eingriff nicht deterministisch auslösen. Ein Usermode-Prozess kann
`CancelIoEx` für eine ausstehende Named-Pipe-Leseoperation nicht scheitern lassen, und das
Rennfenster zwischen Fristablauf und Abbruch ist Mikrosekunden breit.

## Methode: Fault Injection nur im Testbuild

Der Header bekommt zwei **test-only** Haken hinter `#if UDX_FI_*`:

| Define | Wirkung | Zweck |
|---|---|---|
| `UDX_FI_SKIP_CANCEL` | `CancelIoEx` wird nicht angefordert | die blockierte I/O bleibt wirklich anhängig → Exit-31-Pfad mit echtem Kernelzustand |
| `UDX_FI_PRE_CANCEL_SLEEP_MS=1500` | 1,5 s Schlaf vor `CancelIoEx` | eine Gegenseite kann die I/O nach der Frist, aber vor dem Abbruch abschließen |

Schutz gegen Verwechslung und Drift:

- **Der Produktionscode ist unverändert.** Ohne die FI-Blöcke ist der Tokenstrom des
  Headers gleich dem W24-Header (sha256 `5be8c38b…`, gepinnt in
  `tests/test_w30_cancel_race.py`). Ein Kontrolltest zeigt, dass der Vergleich nicht leer
  ist: Mit den FI-Blöcken weicht der Strom ab.
- Die `.cpp`-Dateien, die Produktions-CL-Flags (`w18_cpp_crossrun.CL_FLAGS`) und die CI
  definieren kein `UDX_FI_*` (getestet; DK3 setzt ein `/D` in die Flags und wird getötet).
- Ein FI-Binary meldet sich vor `main` auf stderr (`UDX_FAULT_INJECTION_BUILD`) und gibt pro
  erreichtem Zweig eine Markerzeile aus. Produktionsbinaries geben keinen Marker aus
  (Fall `fi_banner`). In den Kampagnen gilt jeder Lauf mit Banner als Fehlschlag.

## Fälle (`tools/w30_cpp_cancel_race.py`, CI-Job `cpp-candidate`)

Gebaut mit MSVC `/W4 /WX` in drei Varianten: production, fi_skip, fi_sleep.

| Fall | Aufbau | PASS nur wenn |
|---|---|---|
| `fi_banner` | alle 6 Binaries mit `--bogus` | Exit 24; Banner genau bei den FI-Binaries |
| `fi_skip_server_exit31` | FI-Probe (Budget 0,8 s), stummer Client hält 8 s | Exit 31 nach ≥ Budget + 0,8 × Gnadenfrist und ≤ 5 s; Marker `CANCEL_SKIPPED` + `DIE_CANCEL_UNCERTAIN`; Pipe-Name danach frei |
| `fi_skip_client_exit31` | FI-Client (0,8 s), stummer Server hält 8 s | dito für den Client; der Server sah den Connect |
| `fi_sleep_server_race` | FI-Probe (1,0 s, Abbruch bei ≈ 2,5 s); Ping bei 1,75 s | Exit 22, Marker `COMPLETED_IN_RACE bytes>0`, kein Die-Marker; der Client bekommt 0 Bytes |
| `fi_sleep_client_race` | FI-Client (1,0 s); Fake-Server antwortet `PEER_OK` bei 1,75 s | Client Exit 22 (nicht 0), Marker `bytes>0`; der Server hat geschrieben |
| `fi_controls` | beide FI-Varianten, normaler Austausch | 0/0, nur der Banner, kein Zweigmarker |
| `race_server_campaign` | 100 Läufe Produktions-Probe, Budget 0,4 s, Ping-Offset seeded gleichverteilt 0–0,8 s | siehe Orakel |
| `race_client_campaign` | 100 Läufe Produktions-Client, Budget 0,4 s, Antwort-Offset 0–1,2 s ab Start | siehe Orakel |

Zeitfenster der Rennfälle: Senden bei 1,75 s liegt ≥ 0,5 s nach der Frist (1,0 s) und ≥ 0,5 s
vor dem Abbruch (2,5 s); ein Test pinnt diese Abstände an die Konstanten.

**Kampagnen-Orakel** (rein, portabel getestet):

- Server: Exit ∈ {0, 22, 23}, nie 31 und nie ein Kill. Der Client sieht nichts oder genau
  `PEER_OK`, nie ein Fragment. Exit 0 ⇒ `PEER_OK` zugestellt, Exit 22 ⇒ nichts zugestellt.
- Schutzband ±0,2 s um die Frist. Darunter ist Exit 0 Pflicht, darüber Exit 22.
- Client: Exit ∈ {0, 22}. Antwort ≤ Budget − 0,2 s ⇒ Exit 0, Antwort ≥ Budget + 0,6 s ⇒ Exit 22.
  Die Frist des Clients beginnt erst mit seinem Prozessstart.
- Jede Kampagne muss beide Seiten der Grenze wirklich treffen, je ≥ 10 Läufe mit Exit 0
  und mit Exit 22. Seeds 20261122 und 20261123; die Zwangszonen sind mit 26/15 bzw. 12/11
  Läufen besetzt (Test).

## Belege

- Portabel: `tests/test_w30_cancel_race.py` (Produktionsidentität, FI-Kapselung, Verdikte,
  Orakel, Seeds). Gesamtsuite nach dem Merge von `main` (W27/W28): 630 Tests OK, 136 übersprungen.
- Diskriminierung `evidence/w30_dk_spec.json`: 11/11 getötet, in der CI registriert. Alle
  anderen portablen CI-Specs sind unverändert OK (W24 10/10 mit einem gepinnten veralteten
  Anker, W27 12/12, W28 22/22).
- Typprüfung gegen echte Windows-Header: mingw-w64 g++ 13 mit `-Wall -Wextra -Werror
  -Wconversion -Wshadow`, alle drei Varianten × zwei Quellen warnungsfrei (optionaler Test).
- Nativ: siehe „CI-Lauf“.

## Was W30 NICHT belegt

- Ein `CancelIoEx`, das für eine anhängige I/O scheitert. Der Skip-Haken bildet die *Wirkung*
  nach (die I/O bleibt anhängig), nicht einen echten Fehler des Kernels.
- Handle- und Speicherprofile: offen. Bei Exit 31 räumt der Kernel beim Prozessende auf; dass
  der Pipe-Name danach frei ist, ist gemessen.
- Standardkonto und Windows 11 für die C++-Binaries: nur der erhöhte gehostete Runner.
- Die Kampagnen sind Stichproben (2 × 100) auf einem Runner, kein Beweis der Abwesenheit von
  Rennen. Die Zwangszonen-Orakel sind bewusst grob (±0,2 s), damit Scheduling-Jitter nicht als
  Fehler zählt.
- Versioniertes ACK / Receipts, Exit-Code-Parität der Python-CLI, G2-App: unverändert offen.

## Quellen (Microsoft Learn, abgerufen 2026-11-22)

- CancelIoEx: https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func
- Canceling Pending I/O Operations: https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations
- GetOverlappedResultEx: https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresultex
- TerminateProcess: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess

## CI-Lauf (nativ, 2026-11-22)

GitHub Actions Lauf [44966956558](https://github.com/marcohost33-maker/ultratreiber/actions/runs/44966956558),
PR #12, Kopf `885ffa1`, gemessen auf dem Merge-Commit `2f159a4` mit `main` `92282c3`: **9/9 Jobs grün**
(Suiten Ubuntu/Windows × Python 3.13/3.14 inkl. DK-Specs mit W30, nativer Collector,
Konto-Matrix, Principal-Matrix, Guard-Sweep, `cpp-candidate`).

`cpp-candidate`, Schritt W30 (Windows Server 2025 10.0.26100, erhöhter Administrator,
Python 3.13.17): Compiler `Microsoft (R) C/C++ Optimizing Compiler Version 19.52.37029 for x64`,
`/nologo /W4 /WX /EHsc /std:c++17`, Verdikt **`CANCEL_RACE_OK`**, 8/8 Fälle `ok`.
Header-SHA-256 `153f8178eb6a741b8e0129b100d6cf696b676e482f187a55cdeb9641808bc266`.

| Fall | Exit | Zeit | Beobachtung |
|---|---|---|---|
| `fi_banner` | 6 × 24 | – | Banner bei den 4 FI-Binaries, keiner bei den 2 Produktionsbinaries |
| `fi_skip_server_exit31` | 31 | 1,792 s | stderr: `UDX_FAULT_INJECTION_BUILD`, `UDX_FI_CANCEL_SKIPPED`, `UDX_FI_DIE_CANCEL_UNCERTAIN`; Pipe-Name danach frei |
| `fi_skip_client_exit31` | 31 | 1,823 s | dieselben drei Marker; der Server sah den Connect |
| `fi_sleep_server_race` | 22 | 2,488 s | `UDX_FI_COMPLETED_IN_RACE bytes>0`; Client hat gesendet und **0 Bytes** empfangen |
| `fi_sleep_client_race` | 22 | 2,519 s | `UDX_FI_COMPLETED_IN_RACE bytes>0`; der Fake-Server hat `PEER_OK` geschrieben (Fehler 0) |
| `fi_controls` | 0 / 0 (beide Varianten) | – | nur der Banner, kein Zweigmarker |
| `race_server_campaign` (Seed 20261122) | 53 × 0, 47 × 22 | – | 0 Fehlläufe; kein 23, kein 31, kein Fragment |
| `race_client_campaign` (Seed 20261123) | 38 × 0, 62 × 22 | – | 0 Fehlläufe |

Einordnung der Zeiten: Exit 31 liegt bei Budget (0,8 s) + Gnadenfrist (1,0 s) ≈ 1,8 s. Die
Gnadenfrist wurde also abgewartet und nicht übersprungen, und das Ende kam lange bevor der
Halter (8 s) losließ. Die Rennfälle enden bei Budget (1,0 s) + FI-Schlaf (1,5 s) ≈ 2,5 s. Die
Operation war zum Abbruchzeitpunkt bereits mit Daten abgeschlossen (`bytes>0`), und das
Ergebnis blieb trotzdem der Timeout. Die W18/W24-Fälle im selben Job sind unverändert grün
(`CROSSRUN_OK`, 11/11).

Binär-SHA-256 (Variante: Probe / Client):

| Variante | `udx_sid_probe.exe` | `udx_sid_client.exe` |
|---|---|---|
| production | `fbbd77e7a3dd33065ecab480f50af855bd0ddbf84be67372e6fb5f5c824ac479` | `e34bbea62362cc70761eb0ce9a2aecdf84ab37901c5919f96c31fe7a104739c8` |
| fi_skip | `4f9c1fe9937a549f5d4e577afeb7349a854b14f352aa02b7b047a4b6e7127194` | `7cadcabb7e11f257428723d23cfc5b1c8d0229e3b6c68c5a43b95320b3b68c1a` |
| fi_sleep | `424e4706733acf1fdd23e104bc8f761a15e18fee8f46f59825e62f3d097a0eb6` | `6b7d308e22df5ca15c3513268a5ebda5311f40db393cea25d19cfeb5aae02cb7` |

Bericht: Artefakt `udx-w30-cancel-race-2f159a4bf9b59cd98bc2740e193cc3b1d4bdad20` (ID 14731889000,
30 Tage). Weiterhin gilt: erhöhter Admin auf Windows Server, keine Freigabe.
