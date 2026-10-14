# UDX W16 – Evidenz-Eingabehärtung und Test-Identitäts-Pin

Datum: 2026-10-14 | Autor: Coworker Research | Status: **LOCAL CANDIDATE / NOT WINDOWS-APPROVED**

## Grundlage und Abgrenzung

W14 originaler Git-HEAD `26309e997fea1ac90edba8a51e457fd494cac978`. W16 ist **nur nach** dem unabhängigen W14-Patch und dem W15-Inkrement anzuwenden. Keine Remote-Berechtigung, keine Sicherheitsfreigabe und kein Windows-Execution-Nachweis. Original-Quell-SHA der bestehenden Windows-Negativtests: `30cfbd31ba7b856df7dd3ff525cb2ab0908e1b2a2ca74d89709c4d9ce1a88aff` (Datei `tests/test_w12_windows_pipe.py`; Byte-Basis, `core.autocrlf=false`).

## Reproduzierte Ausgangsbefunde (NR)

1. `native_suite.cases[0].id=[]` -> `TypeError: unhashable type: list` in W15-Prüfer, statt maschinenlesbarem `BLOCKED`.
2. `native_suite.cases[0].id=12` -> `TypeError: argument of type 'int' is not iterable`.
3. W15 akzeptierte synthetische 23+24-Test-ID-Listen ohne Vergleich mit den tatsächlichen 47 Methoden der W14-Quelle; eine Fälschung allein anhand der Anzahl hätte `UNTRUSTED_REPORT_SCHEMA_VALID` erhalten (nicht Release).
4. Roh-`stdout`/`stderr`/Runnertext konnte aus dem isolierten Prozess in Evidenzberichte gelangen. Darin können Benutzer-SIDs, lokale Namen und Pfade stehen.
5. Bei `pytest -q` ohne `PYTHONPATH=.` scheitert ein vorhandener W8-Subprozessfall mit `ModuleNotFoundError: udx_ref` (Umgebungskonfiguration), mit `PYTHONPATH=.` besteht die Suite. Kein Windows-bezogener Erkenntnisgewinn durch den falschen Fehlerschluss.

## Umgesetzte Änderungen

- Parser lehnt nicht-string IDs, Nicht-PASS-Zeilen, ungültige Laufzeiten einschliesslich NaN/Infinity sowie zu grosse oder nicht standardkonforme JSON-Berichte kontrolliert ab. Keine `TypeError`-Propagierung für geprüfte Fuzz-Fälle.
- Harter Satz von **47 exakten** unittest-IDs plus SHA-256 des W12-Testquelltexts wird sowohl im nativen Worker als auch in der externen Schemaüberprüfung verwendet. Falsche/umbenannte Tests = BLOCKED.
- Laufzeitgetriebener SHA vor und nach den Tests; ausserdem Git-HEAD nach dem Test erneut prüfen; Symlinks aus den festgelegten Quellpfaden nicht folgen.
- Subprozess-Ausgaben (`stdout`/`stderr`), `runner_text` und rohe Worker-Tracebacks nicht in den generierten Report übernehmen; Fehler erhalten einen redigierten Diagnosecode. Roh-Ausgaben können lokal in flüchtigen Puffern der Worker-Ausführung existieren, aber nicht als Teil der Evidenz ausgeliefert werden.
- JSON `--verify`-Eingabe auf 2 MiB begrenzt. Dieses Limit begrenzt nur Dateigrösse; weder Signatur, Testauthentizität noch Trust-Root werden durch den Parser bestätigt.
- Elf neue gezielte adversariale Testmethoden (gegenüber W15 insgesamt); Baseline-Smoke und unabhängiger Clean-Replay separat protokollieren.

## Windows-G2: Exakt geforderte Prüfabfolge

1. Windows 11 **VM**, isoliert, zwei normale getrennte Testkonten; gezielte EOL-sichere Checkoutkonfiguration (`git -c core.autocrlf=false ...`). Erst W14- und W15-Patch, dann W16-Patch anwenden; `git apply --check` bei jeder Stufe.
2. `python tools/w15_windows_evidence.py --collect --repo . --timeout 300 --output w16_native.json` (Python 3.13+). `python tools/w15_windows_evidence.py --verify w16_native.json --repo .`. 47 namentlich identische Einzeltests, keine Skips, Datei-SHA und unveränderter HEAD. Diese positive Resultate wären weiterhin nur **lokaler Testbeleg**.
3. Separate manual gates: echter zweiter User, echtes Low-IL/AppContainer-Token, Owner/AccessCheck, SCM/Service, zweite Maschine remote, kompiliertes C++ einschliesslich Timeouts, unabhängiger Review; alle in W15 `NOT_EXECUTED`, bis ein anderer autorisierter und eigenständiger Evidenzkanal sie testet und belegt.
4. Das C++-Paar benutzt weiterhin einen statischen Pipe-Namen und **blockierende** Win32-I/O; W16 verändert es absichtlich nicht. Native Kompilierung ist für diese Runde nicht nachgewiesen. Der im W15-Dokument vorgeschlagene zufällige Name ist nicht für dieses C++-Paar implementiert.
5. Microsoft: `FILE_CREATE_PIPE_INSTANCE` ist bei Named-Pipe-Serverhandle eine notwendige Zugriffsbedingung, auch bei nicht-Autorisierungsgrenzen. Same SID ist kein Prozessidentitätsnachweis. `ImpersonateNamedPipeClient`-Fehlschlag bedeutet: **keine** weitere Aktion mit Serverrechten.
6. GitHub-hosted `windows-2025` ist Windows Server 2025, **nicht** Windows 11. Testberichte müssen die tatsächliche OS-Version ausweisen. Hosted-Runner-Befunde sind kein Ersatz für die ausdrücklich geforderte Win11/2-Accounts-G2-Lane.

## Evidenz-/Freigabepolitik

Das Skript bleibt ein lokaler Sammler mit `release_authorized=false`. `UNTRUSTED_REPORT_SCHEMA_VALID` = **nur** Syntax-/lokale-Konsistenzprüfung. Hashes ohne unabhängige Vertrauenswurzel liefern keine Identität und keine Attestation. Nur ein echtes, extern validiertes und vom Autor separates Freigabeverfahren kann später über GitHub-Checks/Rulesets entscheiden. Keine API-Tokens/SIDs in gemeinsame Logbundles hochladen.

## Quellen (Primärdokumentation)

- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
