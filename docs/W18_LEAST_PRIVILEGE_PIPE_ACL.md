# UDX W18 – Least-Privilege-Maske für die Pipe-ACEs und erster C++-Build

Datum: 2026-10-22 | Autor: Coworker Research | Status: **RESEARCH / NOT WINDOWS-APPROVED**

## Befund (offen seit W14)

Bis W17 gewährten alle drei ACEs `GRGW` = `FILE_GENERIC_READ | FILE_GENERIC_WRITE` = `0x12019f`. Darin steckt `FILE_APPEND_DATA` (0x4). Für Named Pipes ist das dasselbe Bit wie `FILE_CREATE_PIPE_INSTANCE`. Das ist W14-Review UDX14-01 bzw. „UDX14-02“ in `docs/W17_PIPE_OWNER.md`. Microsoft schreibt dazu wörtlich (*Named Pipe Security and Access Rights*):

> Because FILE_APPEND_DATA and FILE_CREATE_PIPE_INSTANCE have the same definition, so FILE_GENERIC_WRITE enables permission to create the pipe. To avoid this problem, use the individual rights instead of using FILE_GENERIC_WRITE.

Auf derselben Seite steht auch: Wer `CreateNamedPipe` auf eine **bereits existierende** Pipe aufruft, wird gegen deren DACL geprüft. Diese muss zusätzlich `FILE_CREATE_PIPE_INSTANCE` gewähren. Die **erste** Instanz übernimmt ihren Deskriptor aus den Security Attributes und wird dagegen nicht geprüft.

## Änderung

| Stelle | bis W17 | W18 |
|---|---|---|
| ACE-Maske SY / Benutzer / OW (`build_sddl`) | `GRGW` = 0x12019f | `0x12008b` = `FILE_GENERIC_READ \| FILE_WRITE_DATA` |
| Python-Client (`client_ping`) | `GENERIC_READ \| GENERIC_WRITE` | `CLIENT_ACCESS` = 0x12008b |
| C++-Server/Client | GRGW / `GENERIC_READ \| GENERIC_WRITE` | gleiche Parität |

- Gegenüber GRGW **entfallen** genau `FILE_CREATE_PIPE_INSTANCE` (0x4), `FILE_WRITE_EA` (0x10) und `FILE_WRITE_ATTRIBUTES` (0x100). Es kommt nichts hinzu. Der Client braucht nur Daten lesen/schreiben, `READ_CONTROL` (Owner-Prüfung vor dem ersten Byte) und `SYNCHRONIZE`.
- Der Server selbst braucht das Bit nicht: Er legt nur die erste Instanz an (`nMaxInstances=1`, `FILE_FLAG_FIRST_PIPE_INSTANCE`). Sein Handle trägt die beim Anlegen gewährten Rechte (laut Microsoft für `PIPE_ACCESS_DUPLEX`: FILE_GENERIC_READ, FILE_GENERIC_WRITE, SYNCHRONIZE).
- **Bruch für Alt-Clients:** Ein Open mit `GENERIC_WRITE` wird abgewiesen, weil es auf `FILE_GENERIC_WRITE` abgebildet wird und damit 0x4 enthält. Das ist beabsichtigt, gemessen und getestet. Drei Roh-Clients in der gepinnten Testdatei nutzen jetzt `CLIENT_ACCESS`; die 47 gepinnten Test-IDs sind unverändert.

## Belege

**Diskriminierende Laufzeittests** (`tests/test_w18_least_privilege.py`, jeder Test hat eine Kontrolle im selben Lauf):

| Test | Kontrolle (W17-Deskriptor, GRGW) | W18 |
|---|---|---|
| zweite Instanz auf existierendem Namen, identische Parameter beider Aufrufe | zugelassen | `ERROR_ACCESS_DENIED` |
| Client-Open `GENERIC_READ \| GENERIC_WRITE` | zugelassen | `ERROR_ACCESS_DENIED` |
| Client-Open `CLIENT_ACCESS` | – | zugelassen (Positivkontrolle) |
| `client_ping` fordert genau `CLIENT_ACCESS` an | – | aufgezeichnet, Handshake `PEER_OK` |

**CI-Lauf 39760160792 (Branch-Kopf `3968d67`, geprüft als PR-Merge-Ref `6eef214`; Windows Server, erhöhter Administrator):** Alle 6 Jobs grün. Die drei W18-Windows-Tests liefen (nicht übersprungen). Suite unter bash und pwsh, Python 3.13 und 3.14. Der Collector lief mit 47/47 und `--verify` OK; der DACL-Readback zeigt drei ACEs mit `0x12008b`.

**C++ (UDX14-04, erster Schritt):** Die Quellen `windows/*.cpp` sind seit W4 nie kompiliert worden. Neu ist `tools/w18_cpp_crossrun.py` mit dem CI-Job `cpp-candidate`: MSVC über vswhere, `cl /W4 /WX /EHsc /std:c++17`. Der Build lief ohne Warnungen; die SHA-256 der Binärdateien stehen im Artefakt-Bericht. Kreuzläufe auf dem festen Pipe-Namen:

| Fall | Ergebnis (Lauf 39760160792) |
|---|---|
| C++-Server ↔ C++-Client | Server 0, Client 0 |
| C++-Server ↔ Python `client_ping` | Server 0, `OK` |
| Python `OneShotPipeServer` ↔ C++-Client | `PEER_OK`, Client 0 |
| Legacy-Open gegen C++-Server, danach regulärer Client | WinError 5; die Instanz bleibt frei, danach `OK` |

**Mutationsprüfung** (`evidence/w18_dk_spec.json`, lokal Linux): 5/5 Mutationen werden erkannt. Das Original ist grün, jede Mutation rot: ACE zurück auf GRGW, Python-Client `GENERIC_WRITE`, Maske plus 0x4, C++-Client `GENERIC_WRITE`, C++-SDDL GRGW.

**UDX14-06 (FD-Handoff-Flake, Linux):** Nicht reproduziert: `test_w8_fd_handoff` isoliert 0/15 rot, Gesamtsuite unter vierfacher CPU-Last 0/10 rot (4 Kerne). Der Befund bleibt offen. Es gibt bewusst keine Timeout-Erhöhung ohne gemessene Ursache.

## Grenzen / offen

- **UDX14-08 unverändert:** Ein Prozess mit derselben SID, der den Namen **vor** dem echten Server anlegt, ist selbst die erste Instanz und wählt seinen eigenen Deskriptor. W18 verhindert nur, dass über die DACL des echten Servers weitere Instanzen entstehen. Das bleibt ein Threat-Model-Gate.
- C++ arbeitet weiter blockierend ohne Deadlines und ohne `CancelIoEx`. Der Build und der Kreuzlauf belegen Parität des Handshakes, nicht des Fehler- und Deadline-Verhaltens (UDX14-04 bleibt offen).
- Der gehostete Runner ist Windows Server mit erhöhtem Administrator. Ein Standardkonto, ein zweites Konto, AppContainer/Low-IL, ein Dienstkonto und ein unabhängiger Review fehlen weiterhin.
- Der lokale Windows-11-Collector-Lauf (Standardkonto) steht seit W17 aus und ist für W18 erneut nötig.
- Kein Release, keine Sicherheitsfreigabe.

Pins: `PINNED_SOURCE_SHA256` in beiden Werkzeugen, `PINNED_NATIVE_TEST_SHA256` und `SHA256SUMS_W12` sind neu. Historische Evidenzberichte behalten absichtlich ihre alten Hashes.
