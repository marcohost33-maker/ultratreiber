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

## CI-Lauf

Ausstehend.
