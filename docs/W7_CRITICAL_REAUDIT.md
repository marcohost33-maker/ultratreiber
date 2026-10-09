# UDX Standalone W7 — Reaudit W6, Bugfixes, adversarial tests, release gates

**Datum:** 2026-10-09  | **Branch:** ausschließlich isolierte Kopie aus W6-ZIP | **Version:** Forschung v0.7

## 1. Evidenzhierarchie

- **Befund mit Red/Green-Gegenversuch** = in W6 reproduziert und in W7 als regressionstestbare Änderung behoben.
- **Getestetes Sicherheitsmuster** = in der lokalen Nicht-Root-Linux-Testumgebung funktionsfähig, kein Betriebssystem-Produktfreigabenachweis.
- **Plattform-Zielkonzept** = nur Architektur / offene Gates. Kein implizites Betriebssystem-Privileg.
- Nachweise: `evidence/W7_RED_GREEN.json`, `evidence/W7_NONROOT_TESTS.log`, `evidence/W7_PAIRED_INPROCESS_BENCH.json`; reproduzierbar via `tools/red_green_w7.py` und `tools/bench_w7_controls.py`.

## 2. Befunde aus den vorherigen zwei Antworten (Quellenkritik + W6-Umsetzung)

| Priorität | Quelle | Falsifikations- / Auditbefund | W7-Entscheid |
|---|---|---|---|
| **P0** | W6 PreviewGate | Abgleich ignorierte Typäquivalenz: `True==1`, `32.0==32`; Freigabe falsch akzeptiert | **GEFIXT** streng typisierter vollständiger Proposal-Check VOR Scopevergleich; Red/Green-Test |
| **P0** | W6 TileChangeTracker | Änderung kleiner als `change_threshold` zählt als „ruhig“, sogar `STABLE_HEURISTIC` nach mehreren geänderten Frames | **GEFIXT** nur exakt keine Änderung (`changed==0`) fördert Quiet-Zähler; eigener Status `LOW_CHANGE` |
| **P1** | W6 PreviewGate | Bei Uhranomalie hätte die absolute TTL ihre Gültigkeitsannahme verloren | **GEFIXT** rückläufige/nichtendliche Zeit verwirft alle in-memory Grants fail-closed |
| **P1** | W6 Bildhashes | Unkeyed/konstante Tile-Fingerprints geräteübergreifend korrelierbar | **REDUZIERT** zufälliger BLAKE2b-Schlüssel pro Tracker, nach Reset neu; Hashes bleiben schutzbedürftige Metadaten |
| **P1** | W6 Perception | Mutable State ohne Serialisierung; konkurrierende Frame-Inspektionen können unzuverlässige Beobachtungsfolgen ergeben | **GEFIXT** RLock um inspect/reset; zeitliche Anordnung ist weiterhin Aufrufreihenfolge, keine echte Frame-Zeitachse |
| **P1** | W6 FD Reader | `pread` auf unveränderlich wirkendem, aber extern beschreibbarem FD ist **kein** atomarer Dateisnapshot; vor/nach `fstat` kann in-place Mutation nicht grundsätzlich ausschließen | **ERGÄNZT** optionaler `SealedSnapshot` kopiert zweimal prüfend und versiegelt Ziel mit `memfd`; Quelle bleibt potenziell inkonsistent |
| **P0 OFFEN** | Autoritätsgrenze | `human_approved=True` ist lediglich vom Test-Harness gesetztes Flag; same-UID untrusted App nicht identifizierbar | **NICHT** als Consent-/Identitätsbeweis umbenennen; keine Exposition im IPC |
| **P0 OFFEN** | IPC / Windows | Linux `SO_PEERCRED` stellt UID nicht App-Identität her; Windows-Kandidat unkompiliert, nicht runtimegetestet | Produktionsfreigabe gesperrt |
| **P1 OFFEN** | Recovery | Replay- und Evidence-Puffer bleiben flüchtig; Restart-Wiederholungen nicht dauerhaft ausgeschlossen | Schreibaktionen weiterhin nicht verfügbar; persistente Idempotenz-/UNCERTAIN-Journal als neues Gate |
| **P1 OFFEN** | Consent/UI | Kein XDG FileChooser-/Document-Portal und kein Windows File Picker implementiert | Trusted-GUI-/Portal-Integration eigenständige Entwicklungswelle |
| **P2 OFFEN** | Performance | W6 nur künstliche Mikrobenchmarks; kein Windows, macOS, Android, iOS, GPU oder Cloud | Gepaarte W6/W7-Mikromessungen dokumentieren Overhead, keine SLO |

## 3. Codeänderungen und Invarianten

### W7 Preview

- Echte Instanztypen statt Python-Zahlen-Gleichwertigkeit; keine `bool`-, `float`- oder nicht-kanonischen Scope-Werte in Erfolgsanfragen.
- Ablaufzeit im monotonen Zeitmodell; Regressions-/NaN-Zeit räumt Grants leer und verweigert.
- Grant weiterhin **ephemer**, **one-shot**, **dry-run**, keine extern bezeugte Einwilligung, kein OS-Event.
- Keine Client-API zur Grant-Erstellung, keine Einbindung von `SealedSnapshot` in den Linux-IPC-Server.

### W7 Tile-Change

- Alle geänderten Tiles resetten den Quiet-Zähler, auch bei einem konfigurierten positiven Schwellenwert.
- Bei kleinem aber positivem Anteil: `LOW_CHANGE`, **nicht** `QUIET_CANDIDATE` und **nicht** `STABLE_HEURISTIC`.
- `STABLE_HEURISTIC` bedeutet weiterhin **nicht** „sicher zu klicken“, keinen semantischen Gleichstand der UI und keine Zustimmung.
- Schlüsseldifferenzierung minimiert gleichförmige Hash-Fingerprints, ist keine Anonymisierungsgarantie.
- `LOW_CHANGE` erweitert den Ergebniswertebereich: Client-Migration und explizite Behandlung unbekannter Status erforderlich, bevor ein Wire-Contract eingeführt wird.

### W7 Linux SealedSnapshot

- Nur Linux mit `memfd_create`, `MFD_ALLOW_SEALING` und allen vier Kernel-Seals `WRITE|GROW|SHRINK|SEAL`.
- Quelle nur `ApprovedFdReader` (read-only, regular, byte bounded, erwartete UID). Zweite Leseprüfung lehnt uneinheitliche Bytes ab.
- Veröffentlichung erfolgt ausschließlich nach erfolgreichem Versiegeln; `read()` prüft Größe und Digest.
- Quelle kann während beider Lesevorgänge wechseln; doppelte Übereinstimmung bedeutet nicht serialisierte Sicht auf externe Writer. Besonders Netzdateisysteme / Geräte / schreibbare mmap bleiben risikoreich.
- `SealedSnapshot` hat keinen IPC-Export, keine beliebigen Pfade, keine echte UI-Zustimmung und keinen Eignungsnachweis für sensitive Daten.

## 4. Evidenz und abzugrenzende Aussagen

- **110/110** Tests im unprivilegierten Linux-Kontext (Null Übersprünge), einschließlich W6-Regressionen und **14 neuen W7-Tests**; Quelle `evidence/W7_NONROOT_TESTS.log`.
- Vorherige W6 **96/96** sind historische Aussage und deckten die gefundenen Fehlermodelle nicht ab.
- Red/Green: W6 akzeptiert Typverwechslung und meldet eine veränderte Bildsequenz stabil; W7 weist beides zurück.
- W7-Datei-Quelle wird nach Verifizierung zweimal gelesen und erst dann in ein kernel-sealed `memfd` kopiert. **Kein atomarer Quellsnapshot-Nachweis**.
- Langzeit-/Stress-, Fuzz-Coverage-, Windowssignatur-, Browser-, HIL- und Mobile-Tests sind offen.

## 5. Nächste Meilensteine, nach Evidenz priorisiert

1. **G2**: Applikationsidentität getrennt von UID durch OS-konforme Ausführungsgrenzen. Für Linux z. B. explizite separierte Benutzer/Container und vermittelter Desktop-Portal-Zugriff. Kein Privileg für beliebige lokale gleichnamige Prozesse.
2. **G3**: Zustimmungsnachweis vom nativen Plattformdienst über sichtbaren Nutzer-Dialog, kurzlebig, pro Ressource und Session. Dokument-Portal/Widerruf mit Testroutine; niemals durch Boolean vom Client.
3. **G3-R**: FileChooser-/Documents-Portal liefert den freigegebenen Zugriff; Host öffnet read-only FD und kann optional versiegelte Kopie bereitstellen. Eingabe-/Bildschirmrechte gesondert einholen.
4. **G4**: Persistentes Journal vor jedem potenziell mutierenden Effekt, Zustände `PREPARED/APPLIED/UNCERTAIN`, Neustartfaults und keine blind wiederholten Effekte.
5. **G2-Win**: Auf echtem Windows `PIPE_REJECT_REMOTE_CLIENTS`, SID-basierte DACL, Named-Pipe-Impersonation und abgebrochene/abgelaufene OVERLAPPED-I/O beweisen, inklusive Negativtests.
6. **G5/6**: Plattform- und Security-Abnahme, SBOM, Packaging, Release-Signierung, Last-/Privacytests. Erst danach echte UI-Aktionen.
7. **Integrationen**: Digi/Nigin/andere Clients erst nach unabhängigem Standalone-Release-Gate.

## 6. Transfer- und Compliance-Kandidaten (nicht produktiv freigegeben)

- CodeFactory: `CF-UDX-W7-STRICT-INT-01`, `CF-UDX-W7-QUIET-EXACT-02`, `CF-UDX-W7-KEYED-EPHEMERAL-HASH-03`, `CF-UDX-W7-SEALED-READ-04`.
- Datenschutz: `UDX-DP-W7-1` Tile-Fingerprints bleiben personenbezogenes/korrelierbares Datum je Anwendungsfall; `UDX-DP-W7-2` Widerruf löscht künftigen Zugriff, bereits kopierte Daten aber nicht automatisch; `UDX-DP-W7-3` FD-/Screen-Picker-Auswahl, Zweckbindung und Datenminimierung; `UDX-DP-W7-4` legitimer Nutzer darf den Kill-Switch unabhängig von UDX betätigen; `UDX-DP-W7-5` kein privilegierter Client-Bypass.
- Lernstatistik: **14 zusätzliche Tests** vs. W6, **2 reproduzierte und behobene Logikfehler**, **1 neues Kernel-Snapshot-Muster** mit eingeschränkter Quellenkonsistenz. Kein selbst behauptetes „Expertenwissen“ ohne Quellen/Gegentest.

## 7. Fachquellen und Abgleich

- Linux `memfd_create(2)` und Sealing: https://man7.org/linux/man-pages/man2/memfd_create.2.html
- Linux `openat2(2)` für künftige pfadbasierte Host-Integration: https://man7.org/linux/man-pages/man2/openat2.2.html
- XDG Desktop Portal FileChooser: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html
- Microsoft Named-Pipe Impersonation: https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
- OWASP ASVS V4 Access Control: https://github.com/OWASP/ASVS/blob/master/4.0/en/0x12-V4-Access-Control.md
- NIST IR 8587 (2026) Token/Assertion Protection: https://csrc.nist.gov/pubs/ir/8587/final
- NIST SP 800-63B Replay Resistance: https://pages.nist.gov/800-63-4/sp800-63b.html

**Release-Urteil:** W7 = lokaler Forschungsprototyp. Keine native Autorisierung, Produktionsreife, Windows-/Mobile-Ausführung oder sichere allgemeine OS-Steuerung belegt.
