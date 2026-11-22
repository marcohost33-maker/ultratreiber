# UDX W28 / W28.1 – Guard-Sweep v2, Uhrbereich und Siegelkonstanten

Datum: 2026-11-21 | Autor: Coworker Research | Status: **RESEARCH / NOT PRODUCTION READY**
Basis: PR #8, Kopf `a0de743` (W27). Gestapelt als PR #9 (#5 → #6 → #7 → #8 → #9).
Keine Änderung an der Windows-Lane und an den gepinnten Quellen (`udx_ref/windows_pipe.py`,
`windows/*.cpp`, `tests/test_w12_windows_pipe.py`).

Anlass: die Cross-Family-Runde A7-R6 (Auftrag vom 2026-11-17, Antworten R15/R16/R17) zu PR #8.
Offen waren dort U6-1 (4 EQUIVALENT-Pins nur auf E1 plausibel), U6-2 (Start-/Protokoll-Matrix),
U6-3 (weitere übernommene Deskriptoren?), U6-4 (`if … return`, `assert`, Handler vom Sweep nicht
erfasst, „NICHT_PRUEFBAR“) und PR-R17-06 („Kill durch RUNTIME_ERROR ist kein Kill“).

## Kurzfassung

1. **UDX28-02 (Laufzeitfehler, widerlegt einen W27-Pin):** Eine Uhr, die einen `int` jenseits des
   float-Bereichs liefert, führte in `PortalRequest`, `PreviewGate` und `DurableGrantStore` zu einem
   **untypisierten `OverflowError`** statt zu einer Abweisung. Für `now = 2**1024 - 2**970 - 1`
   besteht die Uhrprüfung von `PortalRequest` (der Wert rundet auf den grössten float), aber
   `now + 300` läuft über: Die in W27 als **unerreichbar (EQUIVALENT)** gepinnte Abweisung
   `BAD_CLOCK` der Deadline ist erreichbar. Die W27-Messung hatte nur floats geprüft. Jetzt typisiert
   (`BAD_CLOCK`, `CLOCK_ANOMALY`, `INVALID_CLOCK` mit `MAX_CLOCK_NS`); der Pin ist entfernt, die
   Abweisung wird von einem Test getötet.
2. **UDX28-01 (Robustheit):** Ein Clang-Build von CPython 3.13.18 (Linux 6.18) hat in `fcntl` keine
   `F_ADD_SEALS`/`F_GET_SEALS`/`F_SEAL_*`. `sealed_snapshot` las sie beim Import; der Import scheiterte
   mit `AttributeError`, fünf Testmodule luden nicht (11 Fehler). Jetzt zur Laufzeit aufgelöst, nie
   aus dem Kernel-ABI geraten; fehlt eine, `SEALING_UNAVAILABLE` vor jedem Lesen der Quelle.
3. **Guard-Sweep v2 (U6-4, PR-R17-06):** Inventar um `if … return <Abweisung>` und typisierende
   `except`-Handler (neuer Mutant `UNTYPED`) erweitert; Kills müssen einer Testmethode zuzuordnen
   sein (Import-/`setUpClass`-Fehler = `STRUCTURAL`, kein Kill). Erstlauf auf den W27-Tests:
   **9 neue ungetestete Abweisungen**, darunter zwei sicherheitsrelevante Testlücken in `PreviewGate`.
   Alle 9 jetzt mit Negativtest.
4. **U6-2 / U6-3:** Startmatrix vervollständigt (frühes Sterben wird über EOF sofort erkannt,
   falsches Bereitschaftsbyte); statisches Gate für übernommene Sockets (3 Stellen, alle konform).

## 1. UDX28-02: Uhrwerte ausserhalb des float- bzw. SQLite-Bereichs

| Stelle | Eingabe | W27 | W28 |
|---|---|---|---|
| `PortalRequest._checked_clock` | `10**400`, `2**1024 - 2**970` | `OverflowError` | `BAD_CLOCK` |
| `PortalRequest.__init__` (Deadline) | `2**1024 - 2**970 - 1` | `OverflowError` | `BAD_CLOCK` |
| `PreviewGate._prune` | `10**400` | `OverflowError` | `CLOCK_ANOMALY` |
| `DurableGrantStore._clock` | `2**63`, `10**400` ns | `OverflowError` (SQLite) | `INVALID_CLOCK` |

- `math.isfinite(x)` wandelt ein `int` in float um und wirft für Werte ab `2**1024 - 2**970`
  `OverflowError`. Ein int knapp darunter rundet auf `sys.float_info.max` und besteht die Prüfung;
  `+ 300` hebt ihn über die Rundungsgrenze. Für floats bleibt `max + 300.0 == max` (die
  W27-Begründung stimmte für floats).
- Behebung: Hilfsfunktion `_finite_number` (je Modul, keine neue Kopplung) wertet `OverflowError`
  als „nicht endlich“. Der Journal-Takt ist auf `MAX_CLOCK_NS = 2**63 - 1 - 300·10**9` begrenzt, damit
  auch `now + ttl` in den 64-Bit-INTEGER passt. Dasselbe Muster hatte `windows_pipe` bereits
  (Aegis P3-g).
- Belege: `tests/test_w28_equivalence_witnesses.py`. Deterministischer Property-Korpus
  (Seed 20261121): Randwerte, `2**k ± 1` für k bis 1100, 2000 zufällige Bitmuster als float.
  Gegen den W27-Laufzeitcode: **10 Fehler (untypisierter `OverflowError`)**, gegen W28 grün.

Bewertung: kein Autoritätsfehler (die Anfrage wird in keinem Fall angenommen), aber ein
Fail-closed-Verstoss: Der Aufrufer bekommt statt einer typisierten Abweisung eine unerwartete
Ausnahme. Erreichbar nur über eine fehlerhafte oder feindliche Uhr (Injektion der Uhrfunktion).

## 2. UDX28-01: Siegelkonstanten zur Laufzeit

| Interpreter | W27 | W28 |
|---|---|---|
| `/usr/bin/python3.13` (3.13.18, GCC, Konstanten vorhanden) | 551 OK, 93 übersprungen | 603 OK, 93 übersprungen |
| `/usr/local/bin/python3` (3.13.18, Clang, ohne Konstanten) | 11 Fehler (Import) | 603 OK, 116 übersprungen |

Die zusätzlichen Überspringungen sind genau die Positivläufe, die einen echten versiegelten
Snapshot brauchen; jeder nennt den Grund. Die Negativfälle laufen weiter. Ein `OSError` beim
Versiegeln wird `SNAPSHOT_UNSEALED` (Ursache angehängt), die memfd-Kopie wird geschlossen.

## 3. Guard-Sweep v2

| | W27 (Sweep v1) | W28 Erstlauf (v2, W27-Tests) | W28 (v2, mit W28-Tests) |
|---|---|---|---|
| Abweisungen im Inventar | 163 (`raise`) | 164 raise · 11 return · 18 handler | 164 raise · 13 return · 20 handler (197) |
| Mutanten | 326 | 368 | 374 |
| getötet | 313 | 346 | 363 |
| davon durch Assertion / Fehler in Testmethode | 239 / 74 (nicht getrennt ausgewiesen) | 260 / 86 | 279 / 84 |
| strukturell (kein Kill) | nicht erkannt | 0 | 0 |
| nicht getötet | 13 (gepinnt) | 22 (13 W27 + 9 neu) | 11 (alle gepinnt, 0 neu, 0 veraltet) |

Antwort auf PR-R17-06: Von den 74 „Fehler-Kills“ von W27 war **keiner strukturell**; alle entstanden
in Testmethoden (in der Regel: die erwartete typisierte Abweisung fehlt, eine spätere Operation
wirft eine andere Ausnahme). Der Sweep weist das jetzt je Fall aus und zählt strukturelle Fehler nie.
Dass die Unterscheidung greift, zeigte sich beim ersten W28-Lauf: Neue, noch nicht eingecheckte
Testmodule fehlten in den Arbeitskopien, der Ausgangsstand wurde `FAIL_STRUCTURAL` statt grün
gemeldet.

Ein Zwischenlauf (mit den Tests unten) fand zwei weitere: den Handler in `core.decode_response`,
der im ersten v2-Lauf nur scheinbar getötet war – allein durch `test_linux_ipc.test_real_kernel_uid_and_fixture`,
der nie fehlerhaftes JSON sendet und unter Sweep-Last offenbar am Timing scheiterte (ein Kill durch einen
lastabhängig flackernden Test ist kein Beleg) – und die Typprüfung der Uhr in `PreviewGate` (ohne sie
akzeptiert `math.isfinite(True)` eine bool-Uhr). Beide jetzt getestet.

Die 9 neuen Lücken des Erstlaufs (Antwort auf U6-4) und ihre Tests (`tests/test_w28_negative_controls.py`):

| Abweisung | Form | Folge ohne Abweisung (Test vorher grün) |
|---|---|---|
| `PreviewGate` `INVALID_REQUEST` | return | Vorschlag mit Nicht-UUID-Request-ID **verbraucht einen gültigen Grant und wird angenommen** |
| `PreviewGate` `REPLAY_REJECTED` | return | wiederholte Request-ID mit frischem Grant **angenommen** |
| `PreviewGate` `INVALID_SCOPE` | return | als `SCOPE_MISMATCH` gemeldet (falscher Code) |
| `PreviewGate` `INVALID_GRANT` | return | als `NO_ACTIVE_GRANT` gemeldet (falscher Code) |
| `ApprovedFdReader` `INVALID_FD` | handler | roher `OSError` |
| `_fd_properties` `INVALID_SOURCE_HANDLE` | handler | rohe `ReadGuardError` statt `GrantDenied` |
| `fd_handoff._peer_uid` `NO_OS_PEER` | handler | roher `OSError` |
| `linux_ipc.peer_identity` `UNAUTHENTICATED_PEER` | handler | roher `OSError` |
| `validate_chooser_result` `INVALID_URI` | handler | roher `ValueError` |

Der Code war in allen neun Fällen richtig; die Tests hätten eine Entfernung nicht bemerkt.
`assert`: 0 im Laufzeitpaket; ein statisches Gate hält das fest (`python -O` entfernt Asserts).

Baseline `evidence/w28_guard_sweep_baseline.json`: 11 Einträge (W27: 13): 8 DEFENSE_IN_DEPTH, 3 EQUIVALENT mit Zeugen, 0 OPEN_NO_TEST, 0 STRUCTURAL_ONLY. Entfallen: der widerlegte EQUIVALENT-Pin `BAD_CLOCK` (UDX28-02) und der DEFENSE_IN_DEPTH-Pin auf die frühe Stempelprüfung in `ApprovedFdReader.read` – den tötet jetzt der Wachstums-Zeuge (ohne frühe Prüfung lautet der Code `SIZE_LIMIT` statt `RESOURCE_CHANGED`). Zusammenfassung aller Läufe: `evidence/W28_GUARD_SWEEP.json`.

## 4. U6-1: die W27-EQUIVALENT-Pins

| Pin | Urteil W28 | Zeuge |
|---|---|---|
| `PortalRequest` `BAD_CLOCK` (Deadline) | **widerlegt** (UDX28-02), Pin entfernt, Abweisung getötet | `PortalClockExtremes.test_deadline_overflow_is_reachable_and_refused` |
| `send_approved_fd` `SIZE_LIMIT` | bestätigt: eine Länge für jede akzeptierte ID | `EnvelopeLengthIsFixed.test_every_canonical_uuid_gives_the_same_length_far_below_max_wire` |
| `send_readonly_request` `SIZE_LIMIT` | bestätigt (gleiche Hülle) | dito |
| `ApprovedFdReader.read` `SIZE_LIMIT` (nach Stempel) | bestätigt: Wachstum nach Zulassung ist `RESOURCE_CHANGED` | `GrowthAfterAdmission.test_growth_past_the_limit_is_resource_changed_before_the_size_check` |

Für die Hüllen: Nur eine kanonische 36-Zeichen-UUID besteht die Argumentprüfung; UUID-Zeichen
brauchen kein JSON-Escaping; Protokoll und Operation sind Konstanten. 5002 IDs ergeben eine einzige
Länge, weit unter `MAX_WIRE`. Lange oder escapende IDs enden vorher in `BAD_ARGUMENT`.

## 5. U6-2 und U6-3

- **U6-2:** Ein bereites, dann stummes Kind endet weiter nach 2 s (`PROTOCOL_TIMEOUT`, W27-Test).
  Ein feindliches Kind kann höchstens das Startbudget (60 s) verbrauchen: Lebendigkeit, keine
  Autorität; es wird beendet und eingesammelt. Neu getestet: Ein vor READY gestorbenes Kind wird
  über EOF sofort erkannt (gemessen 0,13 s bei 60 s Budget) – nur weil der Elternprozess sein
  Schreibende schliesst; DK15 zeigt, dass der Test das bemerkt. Neuer Fehlerfall `bad_ready_byte`:
  sofort `BAD_READY_BYTE`, Kind eingesammelt.
- **U6-3:** Im Repository gibt es drei Übernahmen per `socket.socket(fileno=…)` (Demos W8, W9, W10),
  alle setzen zuerst ein eigenes Timeout. Per SCM_RIGHTS empfangene Deskriptoren sind reguläre
  Dateien (`S_ISREG` erzwungen), für die `O_NONBLOCK` wirkungslos ist; `accept()` erbt unter Linux
  kein `O_NONBLOCK`, `linux_ipc` setzt das Timeout dennoch explizit. Statisches Gate:
  `tests/test_w28_static_gates.py` (eine vierte Übernahme muss angesehen werden).

## 6. Belege

- Lokal (E2), Linux 6.18, unprivilegierter Benutzer, CPython 3.13.18 (GCC): Suite 603 Tests, OK, 93 übersprungen (Clang-Build ohne Siegelkonstanten: 603, OK, 116 übersprungen);
  Guard-Sweep wie oben; DK: `w28_dk_spec.json` 16/16 getötet, alle CI-Specs OK
  (`w27_dk_spec.json` 14/14 mit 2 veralteten Ankern, die DK13/DK14 neu verankern).
- CI: siehe PR #9.

## 7. Grenzen

- Die Erkennung einer „Abweisung per return“ ist formbasiert (Code-String in Grossbuchstaben,
  `False`, Aufruf mit literalem `False`), nicht semantisch.
- Nicht erfasst: `udx_ref/windows_pipe.py`, C++, die Werkzeuge; Abweisungen über Ausnahmebehandler,
  die nur `return` (ohne Wert) ausführen.
- Ein Kill durch einen lastabhängig flackernden Test war in W28 nicht zu unterscheiden (einmal
  beobachtet, siehe §3); seit W28.1 wird jeder Kill durch Wiederholung bestätigt (§8). Ein Test,
  der zweimal hintereinander zufällig scheitert, bliebe unerkannt.
- Die Property-Tests sind deterministisch, kein Hypothesis-Shrinking; ein Gegenbeispiel ausserhalb
  des Korpus ist nicht ausgeschlossen, die Grenzwerte sind analytisch begründet.
- Keine unabhängige Reproduktion; Zahlen dieses Dokuments sind für Prüfer E0.

## 8. W28.1 – Selbstprüfung und Korrektur (2026-11-22)

**Eigener Prozessfehler:** W28 baute auf PR #8 auf, ohne dessen Review-Threads zu lesen. Dort standen seit
dem 2026-11-19 zwei **ungelöste Codex-Befunde (P2)**. Beide waren berechtigt; einer betrifft die in §3
berichteten Zahlen.

1. **Mutanten entfernten Seiteneffekte (Codex, `tools/guard_sweep.py:112`).** Bei
   `if len(raw) > MAX_STATUS or sock.send(raw) != len(raw): raise …` entfernte der ADMIT-Mutant `if False:`
   auch das `send`. Positivtests scheiterten und zählten als Kill einer Abweisung, die sie nie prüfen. Jetzt:
   ADMIT `((cond) and False)`, REFUSE `((cond) or True)`; die Bedingung läuft weiter, nur ihr Ergebnis wird
   erzwungen. **Folge:** drei in W28 als getötet gezählte Abweisungen waren Überlebende:
   `fd_handoff.handle_once` und `credentialed_handoff.process_one` (`REPLY_FAILED` bei kurzem `send`) und
   `core.decode_response` (parsebare, aber nicht-kanonische Request-ID: Grossbuchstaben, `{…}`, `urn:uuid:`,
   ohne Bindestriche – ohne die Prüfung angenommen). Alle drei haben jetzt einen Negativtest
   (`tests/test_w28_1_side_effect_survivors.py`); jeder tötet seinen Mutanten (einzeln geprüft).
2. **Lastwerkzeug (Codex, `tools/w27_fd_handoff_load.py:106`).** Brenner-Prozesse wurden vor dem
   `try/finally` gestartet; ein Teilfehlschlag liess Endlosschleifen zurück. Jetzt im geschützten Bereich;
   Test mit scheiterndem dritten Start (alt rot, neu grün).
3. **Kill-Bestätigung (neu, nach Shi, Bell, Marinov, ISSTA 2019).** Jeder Kill wird bestätigt, indem die
   fehlgeschlagenen Tests allein gegen denselben Mutanten erneut laufen; reproduziert er nicht, gilt er als
   `UNRELIABLE` (Nicht-Kill, braucht einen Pin). Das schliesst die in §3 dokumentierte Grenze (Schein-Kill
   durch einen unter Last flackernden Test). Ein synthetischer Test, der nur beim zweiten Lauf scheitert,
   ergibt nachweislich `UNRELIABLE`.
4. **UDX28-03 (gleiche Klasse wie UDX28-02).** `DurableGrantStore.issue` nahm jede nicht-negative int-UID an
   (`2**63` → `OverflowError` aus SQLite statt `BAD_PRINCIPAL`); `claim` prüfte den Empfänger weder auf Typ
   noch auf Bereich und verglich mit `==`, sodass `1000.0` und `True` (für uid 1) passten. Jetzt gilt ein
   exakter `int` in `0 … 2**32-2` (`uid_t`, ohne den Platzhalter `(uid_t)-1`). Der Aussteller bleibt beim
   W27-Vertrag (`BAD_OWNER` über die Besitzerprüfung des Deskriptors). Der erste Fix hatte diesen Vertrag
   gebrochen; der Sweep meldete das korrekt als `BASELINE_RED`, statt Zahlen zu liefern.

| | W28 (berichtet) | W28.1 (korrigiert) |
|---|---|---|
| Abweisungen | 197 | 198 (+ Empfängerprüfung in `claim`) |
| Mutanten | 374 | 376 |
| getötet | 363 (davon 3 Schein-Kills durch entfernte Seiteneffekte) | 365, **alle 365 durch Wiederholung bestätigt** |
| Assertion / Fehler im Test | 279 / 84 | 282 / 83 |
| unzuverlässig / strukturell | nicht geprüft / 0 | 0 / 0 |
| gepinnt | 11 | 11 (unverändert, keiner veraltet) |

Laufzeit lokal 9 min (4 CPUs, `--jobs 4`), inklusive Bestätigungsläufen. DK: `w28_dk_spec.json` jetzt 23/23
(DK17–DK23 für W28.1). DK19 überlebte zunächst – kein Test prüfte, dass `UNRELIABLE` in der Ratsche als
Nicht-Kill zählt; die Mengenbildung ist jetzt eine getestete Funktion (`not_killed`).

**Lehre:** Vor dem Aufbau auf einem PR dessen offene Review-Threads lesen, auch die von Bots. Ein grüner
CI-Lauf sagt nichts über offene Befunde.
