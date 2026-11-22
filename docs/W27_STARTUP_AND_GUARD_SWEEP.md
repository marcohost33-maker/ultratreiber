# UDX W27 – FD-Handoff-Flake (UDX14-06) und zweiseitiger Guard-Sweep

Datum: 2026-11-17 | Autor: Coworker Research | Status: **RESEARCH / NOT PRODUCTION READY**
Basis: PR #7, Kopf `40f1aa9` (W26.1). Keine Änderung an der Windows-Lane, an den gepinnten Quellen
(`udx_ref/windows_pipe.py`, `windows/*.cpp`, `tests/test_w12_windows_pipe.py`) oder am Laufzeitcode
unter `udx_ref/`. Geändert sind ein Demo-Werkzeug, Tests, zwei neue Werkzeuge und die CI.

## Kurzfassung

1. **UDX14-06 (FD-Handoff-Flake, offen seit W14):** Die Ursache ist jetzt gemessen und behoben.
   Der Elternprozess der Demo rechnete die Startzeit des Kind-Interpreters auf das
   2-Sekunden-Protokoll-Timeout an. Unter CPU-Überbuchung fiel die alte Demo in 12 von 15 und
   15 von 15 Läufen aus, die neue in 0 von 15.
2. **Zweiter Befund, beim Beheben gefunden:** Das Kind erbte einen nicht-blockierenden Socket, den
   Python als blockierend meldet. Es funktionierte nur, weil die Nachricht immer schon in der
   Warteschlange lag.
3. **Zweiseitiger Guard-Sweep (neu):** Jede Abweisung der portablen Laufzeit wird einmal entfernt
   und einmal erzwungen. Ergebnis am Ausgangsstand: Alle 163 Abweisungen haben eine
   Positivkontrolle, aber **80 von 163 hatten keinen Negativtest**. Nach W27 sind es 13, alle
   begründet gepinnt, keine davon erreichbar und ungetestet.

## 1. UDX14-06: Ursache und Behebung

### Ausgangslage

`tests/test_w8_fd_handoff.py::test_separate_process` startet `tools/demo_w8_fd_handoff.py`. W18
hat den Ausfall nicht reproduziert (0 von 25) und bewusst kein Timeout erhöht, solange die Ursache
nicht gemessen war. Der ursprüngliche Fehlertext von W14 liegt nicht im Repository.

### Messung

`tools/w27_fd_handoff_load.py` lässt die Demo des Ausgangsstands (`git show 40f1aa9:…`, der
Checkout bleibt unverändert) und die neue Demo abwechselnd unter N Endlosschleifen-Prozessen
laufen. Bericht: `evidence/W27_FD_HANDOFF_LOAD.json`. Umgebung: Linux 6.18, 4 CPUs, Python 3.13.18,
unprivilegierter Benutzer, 15 Läufe je Stufe und Variante. Gemessen wurde die Demo mit
sha256 `91f0a83d000b9fcddc104bcce70e01bc1c25c7d029d505dc445373e00ba89789`.

| Lastprozesse (je CPU) | alt: Ausfälle | alt: Fehlerklasse | neu: Ausfälle | neu: Start (Median / Max) | neu: Protokoll (Median / Max) |
|---|---|---|---|---|---|
| 0 (0) | 0/15 | – | 0/15 | 26 ms / 37 ms | 0,5 ms / 0,6 ms |
| 64 (16) | 0/15 | – | 0/15 | 480 ms / 570 ms | 8 ms / 16 ms |
| 320 (80) | **12/15** | `TimeoutError` | 0/15 | 2 670 ms / 3 155 ms | 20 ms / 184 ms |
| 480 (120) | **15/15** | `TimeoutError` | 0/15 | 4 501 ms / 5 078 ms | 12 ms / 372 ms |

Lesart:

- Die Startzeit des Kindes wächst linear mit der Überbuchung (rund 9 ms je Lastprozess auf dieser
  Maschine). Ab etwa 2 s Startzeit läuft `recv_status` im Elternprozess in sein 2-s-Timeout.
- Der eigentliche Austausch bleibt auch bei 120-facher Überbuchung unter 0,4 s. Das
  Protokoll-Timeout von 2 s war also nie zu knapp; es wurde für etwas anderes verbraucht.
- Bei den beiden hohen Stufen dauerte jeder Lauf länger als das alte äussere Test-Timeout von 5 s.
  Der alte Test wäre dort auch mit der neuen Demo ausgefallen.

Grenze der Aussage: Gemessen ist ein Mechanismus, der genau das beobachtete Bild erzeugt
(gelegentlicher Ausfall unter Last, sonst grün). Ob der W14-Ausfall dieselbe Ursache hatte, lässt
sich ohne dessen Fehlertext nicht beweisen. Tritt der Ausfall wieder auf, nennt die Demo jetzt die
Phase.

### Zweiter Befund: geerbtes O_NONBLOCK

`settimeout()` setzt `O_NONBLOCK` auf der offenen Dateibeschreibung. Eltern und Kind teilen sie.
`socket.socket(fileno=fd)` im Kind meldet `gettimeout() is None`, ein `recv` auf leerer
Warteschlange wirft trotzdem sofort `BlockingIOError`. Die alte Demo hat das nie gezeigt, weil der
Elternprozess vor dem Start des Kindes sendete. Sobald der Elternprozess auf die Bereitschaft
wartet, sieht das Kind die leere Warteschlange zuerst. Der erste Lauf der neuen Demo fiel deshalb
in 6 von 6 Versuchen mit `PROTOCOL_BrokenPipeError` aus. Das Kind setzt jetzt sein eigenes Timeout
(2 s). `demo_w9_cross_uid.py` und `demo_w10_cross_uid.py` tun das bereits.

### Behebung

Die Demo trennt drei Phasen mit je eigener Schranke und eigenem typisiertem Ausgang:

| Phase | Schranke | Ausgang bei Verletzung |
|---|---|---|
| Start: Kind meldet Bereitschaft mit einem Byte auf einer privaten Pipe | `STARTUP_BUDGET_S` = 60 s | Exit 3 `CHILD_NOT_READY`, Exit 4 `CHILD_EXITED_BEFORE_READY` |
| Protokoll: Deskriptor senden, Status lesen | unverändert 2 s (`private_pair`) | Exit 5 `PROTOCOL_TIMEOUT` / `PROTOCOL_<Fehler>` |
| Abbau: Kind beendet sich | `EXIT_BUDGET_S` = 60 s | Exit 6 `CHILD_EXIT_TIMEOUT` / `CHILD_RETURN_<n>` |

- Das Startbudget ist eine Lebendigkeitsschranke für die Prozesserzeugung. Von ihm hängt keine
  Sicherheitseigenschaft ab.
- Das Protokoll-Timeout wurde **nicht** erhöht. Ein Test belegt, dass ein bereites, aber stummes
  Kind weiterhin nach 2 s als `PROTOCOL_TIMEOUT` endet.
- Jeder Fehlerpfad beendet und erntet das Kind (`child_reaped`).
- Das äussere Timeout von `test_separate_process` (vorher 5 s) ist jetzt ein reiner Hängeschutz
  von 60 s.

### Tests

`tests/test_w27_fd_handoff_startup.py`, 10 Tests. Jeder injiziert genau einen Fehler:

- Kind startet 2,3 s verzögert (mehr als das Protokoll-Timeout): Erfolg, Start ≥ 2 300 ms,
  Protokoll < 2 000 ms. Die alte Demo scheitert hier deterministisch.
- Kind wird nie bereit: Exit 3, typisiert, Kind geerntet, deutlich vor Ablauf seiner Wartezeit.
- Kind endet vor der Bereitschaft: Exit 4, nicht als bereit gewertet.
- Kind ist bereit und bleibt stumm: Exit 5 nach mindestens 2 s.
- Elternprozess sendet 0,5 s nach der Bereitschaft: Erfolg (vorher `BlockingIOError` im Kind).
- OS-Tatsache festgehalten: übernommener Deskriptor ist nicht-blockierend, obwohl Python
  blockierend meldet.
- Argumentgrenzen der Fehlerinjektion.

## 2. Zweiseitiger Guard-Sweep

### Warum

W26.1 fand einen Test, der nur Abweisungen prüfte: Ein Mutant, der alles abweist, überlebte
(SR-10). Die handgeschriebenen DK-Specs finden diese Klasse nicht, weil sie je Guard eine
Abschwächung nennen. Die A7-Frage dazu lautete: Gibt es weitere Abweisungstests ohne
Positivkontrolle? Die Gegenfrage ist genauso wichtig: Gibt es Abweisungen ohne Negativtest?

### Verfahren (`tools/guard_sweep.py`)

- Das Inventar kommt aus dem Code, nicht aus einer Liste: Ein Guard ist ein `if`/`elif`, dessen
  Rumpf mit `raise` endet.
- Je Guard zwei Mutanten gegen alle Tests, die das Modul erreichen (direkt oder über Importe):
  - `ADMIT`: Bedingung wird `False`. Überlebt er, prüft kein Test diese Abweisung.
  - `REFUSE`: Bedingung wird `True`. Überlebt er, läuft keine Positivkontrolle durch diesen Guard.
- Überlebende werden mit `evidence/w27_guard_sweep_baseline.json` verglichen. Ein neuer
  Überlebender macht den Lauf rot. Ein Eintrag, der nicht mehr überlebt, ebenfalls.
- Wie beim DK-Runner: private Arbeitskopien, kein Bytecode-Cache, bytegenaue Mutation und
  Rücknahme. Ein Timeout ist nie ein Kill.
- Schlüssel eines Guards: Datei, umgebende Funktion, Bedingungstext, Abweisungscode. Keine
  Zeilennummern.

### Ergebnis

12 Module, 163 Guards, 326 Mutanten.

| Stand | REFUSE getötet | ADMIT getötet | ADMIT überlebt |
|---|---|---|---|
| Ausgang (`40f1aa9` plus W27-Demo) | 163/163 | 83/163 | **80** |
| nach W27 | 163/163 | 150/163 | 13 (alle gepinnt) |

- **Keine Abweisung ohne Positivkontrolle.** Die SR-10-Klasse tritt in der portablen Laufzeit
  nicht auf.
- **80 Abweisungen ohne Negativtest.** Darunter sicherheitstragende: der Client prüft die UID des
  Dienstes, bevor er sendet; das Laufzeitverzeichnis darf kein Symlink sein und muss dem Server
  gehören; der Server verweigert den Start als root; eine Statusantwort mit angehängtem Deskriptor
  wird abgewiesen; unbekannte Grants lassen sich weder beanspruchen noch widerrufen.
- 67 davon sind jetzt mit `tests/test_w27_negative_controls.py` (57 Tests) belegt.
- 13 bleiben gepinnt: 9 `DEFENSE_IN_DEPTH` (ein anderer, getesteter Check weist dieselbe Eingabe
  ab), 4 `EQUIVALENT` (keine Eingabe erreicht die Abweisung). Klasse `OPEN_NO_TEST`: 0.

Kein Laufzeitfehler wurde gefunden: Alle 80 Abweisungen verhielten sich korrekt, sie waren nur
nicht gegen Rückbau gesichert.

### Was der Sweep NICHT sagt

- Er sieht nur `if … raise`. Abweisungen über `return`, `assert`, Ausnahmebehandler oder
  Datenbank-Constraints sind nicht im Inventar. `udx_ref/windows_pipe.py` hat 29 solche Guards und
  62 `if … return`; das Modul läuft nur unter Windows und ist nicht Teil dieses Sweeps.
- Er läuft unter Linux. Die C++-Quellen und die Werkzeuge unter `tools/` sind nicht erfasst.
- 74 der 313 Kills entstehen durch einen Testfehler (falsche Ausnahme), nicht durch eine
  fehlgeschlagene Zusicherung. Das ist eine Erkennung, aber eine schwächere.
- 16 der 57 neuen Negativtests ersetzen einen OS-Aufruf durch ein minimales Ersatzstück (zum
  Beispiel ein Kernel, der pid 0 meldet). Sie belegen den Guard, nicht dass das Betriebssystem diesen
  Zustand je liefert. Die Beschreibung der Testdatei nennt diese Einschränkung.
- Die Testauswahl folgt den Importen. Ein Test, der ein Modul nur über einen Unterprozess erreicht
  und es nirgends nennt, würde übersehen; der Sweep meldete dann fälschlich einen Überlebenden,
  nie fälschlich einen Kill.

## 3. Belege

Lokal (Linux 6.18, 4 CPUs, Python 3.13.18, unprivilegierter Benutzer):

| Prüfung | Ergebnis |
|---|---|
| `python -m unittest discover -s tests` | siehe PR-Beschreibung (exakte Zeile am Kopf) |
| `tools/guard_sweep.py --baseline …` | 326 Mutanten, 313 getötet, 13 gepinnt, OK |
| `tools/dk_runner.py evidence/w27_dk_spec.json` | 16/16 |
| übrige portable DK-Specs | unverändert, siehe PR-Beschreibung |
| `sha256sum -c SHA256SUMS_W12`, W14-Gate | OK, rc=0 |

Nicht belegt in W27: jeder Windows-Lauf dieser Änderungen vor dem ersten CI-Lauf des PR; die
Sweep-Werkzeugtests unter Windows; alle offenen Punkte aus W26 (Owner-Entscheid ADR-UDX-007,
LPAC, UIAccess, zweite Sitzung, C++-Cancel-Race, versioniertes ACK, G2-App, Attestierung).

## 4. Lernzuwachs (Methoden)

1. **Neu:** Ein Timeout gehört zu genau einer Phase. Wer Prozessstart und Protokollaustausch auf
   dieselbe Uhr legt, bekommt einen Ausfall, dessen Meldung auf die falsche Stelle zeigt.
2. **Neu:** Ein von einem anderen Prozess übernommener Socket hat den Blockiermodus der geteilten
   Dateibeschreibung, nicht den, den das neue Socket-Objekt meldet. Timeout nach der Übernahme
   immer selbst setzen.
3. **Neu:** Positiv- und Negativkontrolle lassen sich mechanisch und vollständig prüfen, wenn das
   Inventar aus dem Code kommt. Die handgeschriebene Liste hatte die Hälfte der Abweisungen nie
   erfasst.
4. **Bekannte Regel, neue Instanz:** „Nicht reproduziert“ ist kein Befund über die Ursache. Die
   Last von W18 (vierfach) lag weit unter der Schwelle (etwa 80-fach auf dieser Maschine).

Quellen (Einordnung, nicht Beleg für dieses Repository): Luo et al., „An Empirical Analysis of
Flaky Tests“ (FSE 2014): asynchrones Warten ist die häufigste Ursache, behoben meist durch Warten
auf eine Bedingung statt auf Zeit (V1). Just et al., „Do Redundant Mutants Affect the Effectiveness
and Efficiency of Mutation Analysis?“ (ICST 2012) zu Ersetzungen von Bedingungen durch
`true`/`false` (V1). Martin und Xie, Mutationsoperatoren für Zugriffsregeln (NCSU TR-2006-12, V3).
