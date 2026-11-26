# UDX W31 – Versioniertes Zustell-ACK und durable Receipts (Linux-Lane)

Datum: 2026-11-24 | Autor: Coworker Research | Status: **RESEARCH / KEIN RELEASE / KEINE SICHERHEITSFREIGABE**

## Ausgangslage

Seit W23 (P1 DELIVERY) und W24 offen: *Peer-Close beweist nicht, dass `PEER_OK` bzw. eine
Antwort verarbeitet wurde.* Gate G4 (`docs/W5_RELEASE_GATES.md`) stand auf FAIL/OPEN mit dem
Befund „volatile deque/cache only“: Der Replay-Schutz des Brokers (`Broker.seen`) und das
Audit leben nur im Prozess, ein Neustart vergisst beides.

Roadmap W30, Punkt (5): „versioned ACK / durable receipts“. W31 schließt diesen Punkt für die
**Linux-AF_UNIX-Lane**. Windows ist bewusst nicht Teil dieser Welle (siehe Grenzen).

## Warum jetzt und warum nur Linux

- GitHub Actions sind laut Auftrag vom 2026-11-24 (007acc2) bis etwa Mi/Do wegen Billing
  gesperrt. Neue native Windows-Belege sind derzeit nicht erzeugbar; ein portabler Punkt
  lässt sich vollständig lokal belegen.
- `udx_ref/windows_pipe.py` wird in W29 (#11) gesweept; W31 fasst es nicht an.
- Punkt (6) Exit-Code-Parität ändert die gepinnte 47/47-Lane und braucht einen nativen
  Lauf: zurückgestellt.

## Entwurf

### Was ein ACK bedeutet (Claim-Grenze)

Ein ACK sagt genau eines: Ein Prozess **derselben UID** (ADR-UDX-006: eine Vertrauensdomäne)
hat exakt die Antwort-Bytes mit diesem SHA-256 erhalten, und sein strikter Decoder
(`core.decode_response`, inkl. Request-ID-, Capability- und Objektbindung) hat sie
angenommen (`ACCEPTED`) oder abgelehnt (`REJECTED`). Es sagt **nicht**, dass eine Anwendung
die Daten benutzt hat, und ein Same-UID-Prozess kann es fälschen.

### Drahtformat (`udx-ack/1`, Frames wie udx/0.1: 4-Byte-Länge big-endian + JSON)

| Richtung | Frame | Felder (exakt) |
|---|---|---|
| C → S | Request | unverändert `udx/0.1` |
| S → C | Response | unverändert `udx/0.1`-Antwort |
| C → S | ACK | `version="udx-ack/1"`, `request_id` (kanonische UUID), `response_sha256` (64 hex, klein), `verdict` ∈ {`ACCEPTED`,`REJECTED`} |
| S → C | Quittung | `version`, `request_id`, `receipt` ∈ {`DELIVERED`,`CLIENT_REJECTED`} |

ACK und Quittung: höchstens 256 Bytes, derselbe strikte I-JSON-Parser wie der Request
(doppelte Schlüssel, Floats, NaN, Surrogate, Tiefe > 16 → abgewiesen). Die Längenangabe wird
**vor** dem Lesen geprüft (kein 2-GiB-Body wird gelesen; Test `huge_receipt_header`).

### Zustandsmaschine (`udx_ref/delivery_receipts.py`, SQLite WAL + `synchronous=FULL`)

```
reserve()            RESERVED      vor dem Dispatch  -> dauerhafter Replay-Schutz über Neustarts
respond(digest)      RESPONDING    vor dem ersten gesendeten Byte (write-ahead)
acknowledge(ACK)     DELIVERED | CLIENT_REJECTED
                     UNACKED (ACK_REQUEST_MISMATCH | ACK_DIGEST_MISMATCH), festgeschrieben, dann Abweisung
unacknowledged(r)    UNACKED (ACK_MISSING | ACK_TIMEOUT | ACK_MALFORMED | SEND_FAILED | DISPATCH_FAILED)
recover()            RESERVED/RESPONDING -> UNCERTAIN (RECOVERED_AFTER_CRASH); nie erneut senden
```

- Schlüssel ist `(subject, request_id)`; jeder bekannte Schlüssel ist ein Replay, gleich in
  welchem Zustand (auch UNACKED/UNCERTAIN). Ein fremder Prinzipal mit derselben ID wird nicht
  blockiert (DK12).
- **Keine Antwort ohne festgeschriebenes Receipt**: Scheitert `respond()`, verlässt kein Byte
  den Server (Test `no_response_without_committed_receipt`, DK1 vertauscht die Reihenfolge
  und wird getötet).
- Ist das Journal selbst unbenutzbar, bleibt die Zeile offen; `recover()` beim nächsten Start
  macht sie UNCERTAIN (Test `unusable_journal_leaves_receipt_open_for_recovery`).
- Store-Härtung wie `durable_grants` (wiederverwendet: absoluter Pfad, Verzeichnis 0700 des
  Eigentümers, Datei 0600, `O_EXCL|O_NOFOLLOW`, `st_nlink == 1`); WAL und FULL werden
  zurückgelesen, sonst `WAL_REQUIRED` / `FULL_SYNC_REQUIRED`. Schema-Version und ACK-Version
  stehen in `receipt_meta`; eine Abweichung ist `SCHEMA_MISMATCH`.
- Uhr: typisiert (`INVALID_CLOCK`), monotone Hochwassermarke (`CLOCK_ROLLBACK`), wie W28.
- Kapazität: `max_receipts` (Standard 100 000) → `JOURNAL_FULL` **vor** dem Dispatch.
  `prune(older_than_ns)` entfernt nur terminale Zeilen; Aufbewahrung = Replay-Fenster
  (dokumentiert und getestet).

### Transport (`udx_ref/linux_ipc.py`, additiv)

- `serve_connection_acked(conn, broker, journal)`; `serve_forever(..., receipt_journal=path)`
  und CLI `--receipt-journal`. Ohne Journal läuft **unverändert** die udx/0.1-Lane
  (`serve_connection`, `request_on_socket`, Signaturen getestet; DK13).
- Eigene ACK-Frist `ACK_DEADLINE_S = 1.0` ab dem letzten Antwortbyte; die Request-Frist
  (1 s, absolut) wird nicht gestreckt.
- Ein Request ohne kanonische ID wird wie in udx/0.1 beantwortet und nicht journalisiert
  (`NOT_JOURNALED`).
- Replay/`JOURNAL_FULL`/Journalfehler: `DENIED` mit dem Code, **ohne Dispatch** (der Adapter
  wird nicht erreicht, `read_count` unverändert).
- Client `request_on_socket_acked()` → `(result, receipt)`; `receipt` ∈ {`DELIVERED`,
  `NOT_CONFIRMED`, `NOT_JOURNALED`}. Lehnt der strikte Decoder ab, wird `REJECTED` quittiert und
  die Abweisung danach geworfen. Eine Quittung zu einer anderen ID oder mit einem nicht zum
  Verdikt passenden Zustand ist eine Abweisung (`RECEIPT_REQUEST_MISMATCH`,
  `RECEIPT_STATE_MISMATCH`).
- **Zwei-Generäle-Grenze, offen benannt**: Die letzte Nachricht wird nie quittiert. Der
  Server kann `DELIVERED` verbuchen, während der Client `NOT_CONFIRMED` meldet (Quittung
  verloren). Umgekehrt nie: Der Server bestätigt nur, was er festgeschrieben hat.

### R6 B3/B4: Journal-Eigentum und beobachtete Worker-Fehler

- **Eigentum (I3).** `serve_forever` öffnet das Journal als `ReceiptJournal(path,
  exclusive_owner=True)` innerhalb seines `try/finally`, **vor** `recover()`, und schließt es
  erst nach dem Ende des Worker-Pools. Der Modus setzt `PRAGMA locking_mode=EXCLUSIVE` vor dem
  ersten WAL-Zugriff und `busy_timeout=0`; die SQLite-Sperre liegt auf der Inode, gilt also
  auch für andere Pfade zur selben Datei und für andere Prozesse. Jedes zweite Journal (zweiter
  Supervisor, direkte API, Diagnose) scheitert beim Öffnen mit `JOURNAL_OWNER_BUSY`, bevor es
  eine Zeile liest oder ändert (die direkte API wartet dabei bis zu 3 s). Die Sperre stirbt mit
  dem Prozess (SIGKILL getestet), ein Neustart wird nicht blockiert.
  **Folge für den Betrieb:** Das Journal eines laufenden Servers ist nicht lesbar; nach dem
  Ende lesen. **Grenzen:** `recover()` auf dem eigenen Handle bleibt möglich (Startoperation,
  nicht bewacht); kein Schutz vor einem Same-UID-Prozess, der die Datei ersetzt; ungeprüft auf
  Netzdateisystemen.
- **Worker-Fehler (I4).** Eine unerwartete Ausnahme in einem Worker bleibt nicht im
  unbeobachteten Future: Sie setzt einen Latch, wird als `UDX_WORKER_FAULT: admission
  suspended` geloggt (fester Text, ohne Ausnahmetext und ohne `exc_info`), Slot und Socket
  werden freigegeben. Danach wird keine Anfrage mehr bedient: ein schon zugelassener, noch
  nicht gestarteter Task kehrt ohne Bedienung zurück, die nächste Verbindung wird geschlossen
  und `serve_forever` endet nach den laufenden Workern mit `RuntimeError('UDX_WORKER_FAULT')`
  (auch am Ende eines begrenzten Laufs). Damit wird auch das Journal für einen Neustart frei.
  **Grenzen:** ein hängender (statt werfender) Worker wird nicht erkannt; das Log erscheint
  sofort, das Ende der Accept-Schleife erst mit der nächsten Verbindung (bis dahin bleibt das
  Journal gesperrt).

## Belege (lokal, Linux, unprivilegiert)

Alle Läufe unter einer unprivilegierten UID (65534, `setpriv`, Kopie des Arbeitsbaums), weil
die Linux-Lane als root bewusst überspringt; Interpreter `/usr/bin/python3.13` (CPython 3.13.18,
GCC-Build mit `fcntl.F_SEAL_*`), Linux 6.18.

- `tests/test_w31_delivery_receipts.py`: 52 Tests, 0 übersprungen, 5 Wiederholungen grün.
  Darunter: echter **SIGKILL** eines Prozesses zwischen `respond()` und ACK (Receipt
  RESPONDING überlebt, danach UNCERTAIN), echter **SIGKILL des Servers** nach gesendeter
  Antwort (nach Neustart UNCERTAIN, Replay derselben ID abgewiesen), **Replay über einen
  Server-Neustart**, Legacy-Client gegen ACK-Server (Antwort unverändert, Receipt
  `UNACKED/ACK_MISSING`), 12 gleichzeitige `reserve()` mit genau einem Gewinner.
- Gesamtsuite: 682 Tests, OK, 94 übersprungen (Windows-only bzw. plattformfremd): `evidence/W31_NONROOT_TESTS.log`.
- Guard-Sweep v2 (`tools/guard_sweep.py`, jetzt 13 Module inkl. `delivery_receipts.py`):
  473 Mutanten (414 raise, 30 return, 29 handler), **462 getötet und per Wiederholung
  bestätigt, 11 nicht getötet = genau die 11 W28-Pins**, 0 blockierend, kein neuer Pin.
  `delivery_receipts.py` 75/75, `linux_ipc.py` 51/53 (die 2 sind die W28-Pins in
  `peer_identity`). Baseline `evidence/w31_guard_sweep_baseline.json`, Zusammenfassung
  `evidence/W31_GUARD_SWEEP.json`. Ein erster Lauf mit dem Clang-Build-Interpreter ohne
  `F_SEAL_*` (UDX28-01) meldete 21 „neue“ Überlebende in `sealed_snapshot.py`/`fd_handoff.py`,
  weil deren Siegel-Tests dort überspringen: Umgebungsartefakt, kein Befund, nicht gepinnt.
  Auf dem Weg gefunden und behoben (eigene Tests): der Frame-Wächter für eine zu große
  Quittung überlebte zuerst (der Decoder lehnt mit demselben Code ab); ein Test mit 2-GiB-
  Header und EOF trennt beide. Test-Helfer ohne Deadline ließen einen Mutanten auf EOF endlos
  kreisen (TIMEOUT); alle Lesevorgänge der Tests sind jetzt befristet.
- Diskriminierende Mutationen `evidence/w31_dk_spec.json`: 14/14 getötet (Semantik: write-ahead-
  Reihenfolge, Replay vor Dispatch und über Neustart, Recovery, Verdikt-Abbildung,
  FULL-Sync, Quittungsprüfung, unveränderte udx/0.1-Lane). Ein erster Entwurf von DK14 war
  ein äquivalenter Mutant (jeder Pfad setzt die Quittung neu) und wurde durch eine echte
  Diskriminierung ersetzt.
- Kosten (`tools/bench_w31_ack.py`, `evidence/W31_ACK_BENCH.json`; 2 × 400 Requests, in
  20er-Blöcken verschränkt, ein Client, lokale Platte): udx/0.1 Median 0,192 ms (p95 0,330),
  ACK-Lane Median 1,109 ms (p95 1,811), gepaarter Medianfaktor 5,34; 400/400 `DELIVERED`.
  Der Aufpreis sind drei Commits mit `synchronous=FULL` pro Austausch. Keine Durchsatz- oder
  DoS-Zahl.

## Was W31 NICHT belegt

- **Stromausfall.** Getestet ist der Prozessabsturz (SIGKILL). Die Dauerhaftigkeit bei
  Stromausfall folgt aus `synchronous=FULL` im WAL-Modus laut SQLite-Dokumentation, nicht aus
  einem eigenen Versuch (kein Power-Cut-Rig, Dateisystem- und Laufwerks-Cache ungeprüft).
- **Windows / Named Pipes, C++.** Keine ACK-Lane dort; `windows_pipe.py` und die C++-Quellen
  sind unverändert. Die Python-CLI meldet weiter 0 ohne Peer-Close (Punkt Exit-Code-Parität).
- Anwendungsseitige Verarbeitung, Manipulationssicherheit des Journals (kein signiertes
  Ledger), Schutz gegen Same-UID-Fälschung, Mehrhost-/Remote-Zustellung.
- Fairness/DoS: Ein Client kann die ACK-Frist (1 s) pro Verbindung ausschöpfen; der Pool
  bleibt auf 4 Worker begrenzt, Sättigung schließt sofort (unverändert).
- Unabhängige Prüfung: Die Zahlen sind E2 (lokal, Original-Repo), für Prüfer E0 bis
  nachvollzogen. CI-Lauf folgt, sobald Actions wieder verfügbar sind.

## Quellen

- SQLite, Write-Ahead Logging (synchronous=FULL vs. NORMAL im WAL-Modus): https://www.sqlite.org/wal.html
- SQLite, PRAGMA synchronous: https://www.sqlite.org/pragma.html#pragma_synchronous
- RFC 7493 (I-JSON), wie im udx/0.1-Parser.
