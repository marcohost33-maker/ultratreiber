# UDX W24 – Begrenzte Overlapped-I/O für die C++-Kandidaten, Integration der Reviews W21–W23

Datum: 2026-11-04 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED / KEIN RELEASE**

## Ausgangslage

Nach W20 (`3c47a07`, CI 7/7 grün) entstanden drei externe Reviews, die nie ins
Repository integriert wurden (007acc2 R5: `ORIGINAL_REPOSITORIES_NOT_INTEGRATED`):

| Review | Kernaussage | Nativ ausgeführt? |
|---|---|---|
| W21 (GPT-6, R28 Q8) | UDX-W21-01 P1: C++-Probe ohne Deadline (`ConnectNamedPipe`/`ReadFile`/`WriteFile`/`FlushFileBuffers` blockierend). UDX-W21-02 P2: Statusdrift in `SECURITY.md`, `NEXT_GATES.md`, `W5_RELEASE_GATES.md`. UDX-W21-03: SID ≠ App-Identität. UDX-W21-04: `main` ohne Branch-Schutz. UDX-W21-05: FD-Handoff-Flake nicht falsifiziert. | nein |
| W22 (GPT-6, Reaudit) | Korrigiert W21: dessen Exit-22-Orakel war ein „false green“ (jedes Programm mit Exit 22 hätte bestanden). Fordert getrennte Read- und Drain-Stalls mit Positivkontrolle. | nein |
| W23 (GPT-6, Kandidat) | Overlapped-Server-Kandidat (5-s-Budget, `CancelIoEx`, Exit 22/30/31), aber: **der C++-Client bleibt blockierend** (P1 CLIENT); nur Fake-Win32/clang geprüft, kein MSVC, kein Windows-Kernel. | nein |

Alle drei Reviews hatten keinen Zugang zu einem Windows-Kernel. Dieses Repository hat
ihn: den CI-Job `cpp-candidate` (MSVC auf `windows-latest`). W24 setzt deshalb die
Befunde um **und** belegt das Verhalten nativ, negativ-zuerst.

## Umsetzung

### 1. `windows/udx_bounded_pipe_io.hpp` (neu, von Server und Client genutzt)

- **Eine** monotone Frist (`GetTickCount64`) für den ganzen Austausch – Connect,
  Anfrage, Antwort, Peer-Close (W23 PR-1). Pro Datei genau ein `udx::Deadline`
  (Test `test_one_deadline_per_exchange`).
- Jede Operation `OVERLAPPED` mit eigenem Manual-Reset-Event;
  `ERROR_PIPE_CONNECTED` beim Connect = Erfolg, `ERROR_IO_PENDING` = warten.
- Warten nur mit `GetOverlappedResultEx(..., remaining_ms, FALSE)`, nie alertable,
  nie `INFINITE`, nie `GetOverlappedResult(bWait=TRUE)`. Microsoft Learn:
  Ablauf liefert `WAIT_TIMEOUT`, bei 0 ms `ERROR_IO_INCOMPLETE` – beides heißt
  „noch ausstehend“. Ein früher Wecker (Timer-Granularität) wartet den Rest.
- Fristablauf: `CancelIoEx` (nur eine Anforderung, wartet nicht), dann **begrenzt**
  1000 ms (= `CANCEL_GRACE_MS` der Python-Lane) auf die Completion. Eine im
  Rennen erfolgreich abgeschlossene Operation bleibt ein Timeout. Ist die
  Completion danach nicht bestätigt, darf der Stack-Frame mit `OVERLAPPED` und
  Puffer nicht verlassen werden: der Einmalprozess beendet sich mit **Exit 31**.
- Fail-closed Argument-Parser: keine Argumente (10000 ms) oder exakt
  `--budget-ms N`, 1–6 ASCII-Ziffern, 100 ≤ N ≤ 300000; sonst **Exit 24**, bevor
  ein Pipe-Objekt existiert.

### 2. Server `udx_sid_probe.cpp`

- `CreateNamedPipeW(... | FILE_FLAG_OVERLAPPED)`; DACL, Owner, SACL, Instanzzahl,
  Token-Prüfungen und `RevertToSelf`-Abbruch (Exit 30) unverändert.
- `FlushFileBuffers` entfernt. Microsoft: es wartet auf der Serverseite, bis der
  Client alles gelesen hat – unbegrenzt. Ersatz: begrenztes `ReadFile` bis EOF
  (`ERROR_BROKEN_PIPE`/`ERROR_NO_DATA`), wie `OneShotPipeServer.serve`. Daten statt
  EOF zählen nicht als Close.
- Neue Exit-Codes: **22** Frist vor dem Schreiben von `PEER_OK` abgelaufen (auch
  strikt: keine Antwort nach Fristablauf), **23** `PEER_OK` geschrieben, Peer hat
  nicht rechtzeitig geschlossen (die ungelesene Antwort wird von
  `DisconnectNamedPipe` verworfen). 0/20/21/30 und 10–15 wie bisher.

### 3. Client `udx_sid_client.cpp` (W23 P1 CLIENT)

- Öffnen mit `FILE_FLAG_OVERLAPPED`; `CreateFileW` wartet bei Pipes nicht (fehlend
  → `ERROR_FILE_NOT_FOUND`, belegt → `ERROR_PIPE_BUSY`), deshalb begrenzte
  Wiederholung bis zur Frist, wie `client_ping`.
- Owner-Prüfung vor dem ersten Byte unverändert; Schreiben und Lesen begrenzt; die
  7 Byte werden bei Teil-Lesungen bis zur Frist vervollständigt.
- Neu: Exit **22** (Frist), **24** (Argumente), **31** (Cancel unklar).

### 4. Nativer Harness `tools/w18_cpp_crossrun.py` (6 neue Fälle, jetzt 11)

Jede Blockade hält eine echte zweite Partei `HOLD_S = 8 s`, das Binary bekommt
1500 ms. PASS verlangt den **typisierten** Exit-Code **und** ein Ende innerhalb
`STALL_LIMIT_S = 5 s` – ein Programm, das erst endet, wenn der Halter loslässt
(W20-Verhalten), oder das gekillt werden muss, fällt durch. Damit ist der
„false green“ aus W21 (beliebiger Exit 22) ausgeschlossen (`stall_verdict`, rein
und portabel getestet).

| Fall | Halter | Erwartung | W20-Quellen |
|---|---|---|---|
| `cpp_server_connect_timeout` | niemand verbindet | Probe Exit 22, Name danach aus dem Namespace verschwunden | blockiert für immer |
| `cpp_server_read_stall` | Client verbindet, sendet nie | Probe Exit 22 | blockiert bis Client schließt |
| `cpp_server_drain_stall` | Client sendet, liest nie, hält offen | `PEER_OK` geschrieben, Probe Exit 23 | `FlushFileBuffers` blockiert |
| `cpp_client_silent_server` | Server verbindet, antwortet nie | C++-Client Exit 22 | blockiert für immer |
| `cpp_bad_arguments` | 8 fehlerhafte Argumentvektoren × 2 Binaries | 16 × Exit 24 | – |
| `cpp_pair_small_budget` | Positivkontrolle C++↔C++ mit 1500 ms | 0 / 0 | – |

Die fünf W18/W20-Fälle (C++↔C++, beide Python-Richtungen, Exit-21-Parität,
Legacy-Open-Ablehnung) laufen unverändert als Positivkontrollen mit Standardbudget.

### 5. Dokumentationsdrift (W21 N1, UDX-W21-02 / UDX22-04)

- `SECURITY.md`: die falschen aktuellen Aussagen („C++ nie kompiliert“, „keine
  Zweitkonto-Evidenz“) ersetzt durch den Stand W18/W20/W24 mit ausdrücklichen Grenzen.
- `docs/ADR-UDX-006.md`: Querverweis Produkt-Gate – G2-App bleibt FAIL/OPEN,
  ROADMAP P0 bleibt Pflicht; UDX14-08 ist „out of scope“, nicht „fixed“.
- `docs/NEXT_GATES.md` und `docs/W5_RELEASE_GATES.md`: als historische Snapshots
  markiert (nicht rückwirkend umgeschrieben, keine Gates auf PASS gesetzt).

## Belege

- Lokal (Linux, nicht nativ): Suite ohne neue Fehler (die 9 Fehler in
  `test_w7`–`test_w10` bestehen identisch am unveränderten Stand `3c47a07`: dieses
  Container-Python kennt `fcntl.F_SEAL_*` nicht; in CI nicht vorhanden).
  Neue Tests `tests/test_w24_bounded_cpp_io.py`.
- Diskriminierung `evidence/w24_dk_spec.json`: 11/11 Mutationen machen den
  genannten Test rot (ausgeführt mit `python -B`; ohne `-B` kann eine
  größengleiche Mutation in derselben Sekunde den alten Bytecode treffen).
- Typprüfung gegen echte Windows-Header: mingw-w64 g++ 13
  `-std=c++17 -Wall -Wextra -Werror -Wconversion -Wshadow`, beide Quellen fehlerfrei
  (optionaler Test `OptionalCrossCompile`, übersprungen ohne mingw). **Kein Ersatz**
  für MSVC und den Windows-Kernel.
- Nativ (MSVC `/W4 /WX`, Windows Server Runner, erhöhter Administrator): CI-Job
  `cpp-candidate`, Bericht als Artefakt `udx-w18-cpp-crossrun-<sha>`. Ergebnis: siehe
  Abschnitt „CI-Lauf“ unten.

## Was W24 NICHT belegt

- Den Exit-31-Pfad (Completion nach `CancelIoEx` nicht bestätigt): nicht
  provozierbar ohne Kernel-Fault-Injection; nur Quellwächter + DK4/DK5.
- 100-fache Cancel-/Close-Race-Läufe, Handle-/Speicherprofil (W23-N2): offen.
- Standardkonto/Win11 für die **C++**-Binaries (Matrix W20 betrifft die Python-Lane).
- Zustellung: Peer-Close beweist nicht, dass `PEER_OK` verarbeitet wurde (kein
  versioniertes ACK, keine durable Receipts; W23 P1 DELIVERY).
- App-Identität (G2-App FAIL/OPEN), Pre-Start-Squatting durch Same-SID (ADR-UDX-006:
  außerhalb des Forschungs-Scopes), AppContainer/Low-IL/Service/Remote-Host.
- Exit-Code-Parität Python-CLI ↔ C++: Die Python-CLI (`udx_ref/windows_pipe.py`,
  gepinnt) fasst Timeouts weiter in 20 zusammen und meldet 0 auch ohne Peer-Close;
  C++ unterscheidet jetzt 22/23. Bewusst nicht in W24 angeglichen (würde die
  gepinnte, 47/47-belegte Python-Lane verändern) – offener Punkt.
- Branch-Schutz für `main` (UDX-W21-04): Owner-Entscheid, nicht durch diese Welle geändert.

## Quellen (Microsoft Learn, abgerufen 2026-11-04)

- GetOverlappedResultEx: https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresultex
- CancelIoEx: https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func
- Canceling Pending I/O Operations: https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations
- Named Pipe Server Using Overlapped I/O: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o
- Named Pipe Client: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
- FlushFileBuffers: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers

## CI-Lauf (nativ, 2026-11-04)

GitHub Actions Lauf [41746553253](https://github.com/marcohost33-maker/ultratreiber/actions/runs/41746553253),
PR #5, Kopf `d5b61c7` (Merge-Commit `e7e817a`): **7/7 Jobs grün** – Suite auf Ubuntu
und Windows (Python 3.13/3.14, bash und pwsh), nativer Collector 47/47 + `--verify`,
Konto-Matrix W20, `cpp-candidate`.

`cpp-candidate` (Windows Server, erhöhter Administrator, Python 3.13.17):
Compiler `Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36260 for x64`,
`/nologo /W4 /WX /EHsc /std:c++17`, Verdikt `CROSSRUN_OK`, 11/11 Fälle `ok`.

| Quelle / Binary | SHA-256 |
|---|---|
| `udx_sid_probe.cpp` | `7b70f0c2f404320c75f5566e9f7d80c6dca3f8ad7861c2148b9c99c1fc8e84bc` |
| `udx_sid_client.cpp` | `06de216ae6a8970ac94b516ebe5a12357f6b58106d52c952451a55e526575007` |
| `udx_bounded_pipe_io.hpp` | `1c5ea2c957aea96b5003a9e3d4c060cdd3247892e17755e7cac7447cd64bfa7c` |
| `udx_sid_probe.exe` | `122ece330c53e44c619ee7625953c289daf8f8c4f2dbd9fc50cfbeb163a976de` |
| `udx_sid_client.exe` | `7ce8121563e9ff000a8f9aef85ffab1ded9792a73e3021804594fb634d352518` |

| Fall | Exit | Zeit bis Exit | Zusatz |
|---|---|---|---|
| `cpp_server_connect_timeout` | 22 | 1,506 s | Name danach freigegeben |
| `cpp_server_read_stall` | 22 | 1,493 s | Halter: `SILENT_HOLD` |
| `cpp_server_drain_stall` | 23 | 1,487 s | Halter hat gesendet |
| `cpp_client_silent_server` | 22 | 1,512 s | Server sah den Connect |
| `cpp_bad_arguments` | 16 × 24 | – | Probe und Client |
| `cpp_pair_small_budget` | 0 / 0 | – | Positivkontrolle |
| W18/W20-Kontrollen (5) | wie bisher | – | C++↔C++, C++↔Python beide Richtungen, Exit 21, Legacy-Open `ERROR_ACCESS_DENIED` |

Die Halter hielten jeweils 8 s; alle Binaries endeten nach dem 1,5-s-Budget, also
durch die eigene Frist und nicht durch das Loslassen der Gegenseite. Die Zeiten
liegen am Budget (GetTickCount64-Auflösung ~15,6 ms; die Messung beginnt erst, wenn
die Pipe sichtbar ist bzw. der Halter startet). Bericht: Artefakt
`udx-w18-cpp-crossrun-e7e817a1bd3d6b7a813376e0b4168783dfd133ee` (30 Tage Aufbewahrung).
Weiterhin: erhöhtes Admin-Token auf Windows Server, kein Standardkonto, kein
Windows 11, Exit-31-Pfad nicht provoziert – keine Freigabe.
