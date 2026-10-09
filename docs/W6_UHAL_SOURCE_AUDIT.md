# UHAL / Ultra-Treiber — unabhängiges Quellen- und Machbarkeitsaudit

**Datum:** 2026-10-09. **Basis:** Benutzer-DOCX `Unbenanntes Dokument.docx`, 19 Seiten, 528 Absätze; mehrere Gemini-Iterationen UHAL 1–6, plus isoliertes UDX-W5-v0.5-Archiv. **Stand:** Belegtes Architektur-/Codeaudit mit lokal getesteten W6-Forschungsbausteinen; keine Produktionsfreigabe.

## Methodik / Evidenzhierarchie

1. **Primärquelle:** exakter DOCX-Text und im Dokument enthaltene Codefragmente. Aussagen werden als Hypothesen gelesen, nicht als durch Tests belegt.
2. **Normativ:** OS-Herstellerdokumentation, veröffentlichte API-Verträge, XDG-Portal- und GStreamer-Dokumentation; deren Detailanforderungen hängen von OS-Version, Berechtigung, Distribution und Deployment ab.
3. **Executable:** Tests in `tests/test_w6_source_hardening.py` sowie unveränderte W5-Regressionstests; isoliert, in-process oder Linux-Nichtroot; keine mobilen/Windows-Laufzeittests.
4. **Nicht als Beweise:** bloße Codeblöcke, Behauptungen von 0 % CPU, <50 ms, iOS-Umgehung, 'Enterprise-ready' oder 'perfekt'.

## 20 priorisierte Befunde / korrigierte Lösung

| ID | Stelle des DOCX | Einstufung | Erklärung und korrigierter Ansatz |
|---|---|---|---|
| F01 | S. 1, 'OS Standardgerät vorgaukeln' | Grundannahme falsch | Es gibt keinen OS-übergreifenden universellen virtuellen Gerätetyp. Standard: Standalone-User-Space-Broker, OS-Adapter nur für konkrete Fähigkeiten. |
| F02 | S. 1–2, UMDF/iOS DriverKit/Android HAL | Plattform-Verwechslung | HAL ist nicht gewöhnliche APK-API; DriverKit betrifft macOS/unterstütztes iPadOS, nicht beliebigen iPhone-Systemdienst. Default: App-sandbox und dokumentierte APIs. |
| F03 | S. 2, gRPC 'fatal' für 4K | pauschal/nicht belegt | Kontrollnachrichten über gRPC sind sinnvoll; Frame-Daten brauchen getrennten gemessenen Datenpfad. Nicht ohne Messung 'fatal'. |
| F04 | S. 3–4, Shared Memory 'Zero-Copy Revolution' | physikalisch überzogen | Kopien, GPU/CPU-Synchronisierung, Buffer-Lifetime, Encoder-Format und Sicherheitsgrenzen separat messen. Handle ist keine universelle übertragbare Adresse. |
| F05 | S. 4, 'Composite Device + Accessibility = vollständiger Kontext' | unzulässige Verallgemeinerung | UI-Trees sind optional/unvollständig. Multimodale Beobachtung unter Berechtigung, niemals pauschales Global-Screen-Scraping. |
| F06 | S. 5–7, iOS BLE self-loopback | technisch nicht belegt | Nicht als Produktweg. BLE-HID-Hardware erfordert externes Gerät/Pairing und schafft keinen uneingeschränkten OS-Zugriff. |
| F07 | S. 7, iOS XCUITest als unsichtbarer Hintergrunddienst | für Consumer unzulässig/ungeeignet | Test-Runner nicht mit persistentem App-Store-fähigem Fernsteuerungsdienst verwechseln. Unterstützte App Intents/Shortcuts statt Global-Touch. |
| F08 | S. 8–9, DXGI Acquire -> texture -> Release | **konkreter Code-Lifetime-Fehler** | `ReleaseFrame` macht die Oberfläche ungültig. Owned-Frame-Lease mit guaranteed release und Tests; kein Pointer nach Ende der Lease. |
| F09 | S. 9, 0–1 % CPU durch DXGI-Textur | unbelegt | GPU-Transfer, Encode, Synchronisierung, Transport und Laufzeitprofile messen; keine CPU-Garantie. |
| F10 | S. 10–12, CDP/Anthropic Computer Use als universeller Standard | Kategorienfehler | Browser-Debug-Protokoll und Anbieter-Toolformate sind keine verbindliche OS-API. UDX-Versionierung + optionale Export-Adapter. |
| F11 | S. 12–13, GStreamer Pipeline garantiert zero-copy | unbelegt | GStreamer-Elemente/Caps zur Laufzeit aushandeln, explizit `d3d11download` als GPU-Download erkennen; Encoder/Konverter müssen die Caps tatsächlich unterstützen. |
| F12 | S. 13–14, WebRTC <50ms und <2% CPU | reine Behauptung | End-to-End-RTT/encode/display messen; Percentile, Hardware und Codec spezifizieren. Remote-Medienpfad getrennt von lokaler Control Plane. |
| F13 | S. 14, `SendInput` Flags kombiniert | **Codefehler** | 'Down'/'Up' als zwei Input-Events; Koordinaten korrekt skalieren; UIPI/secure desktop berücksichtigen. Vorerst keine native Injektion freigeben. |
| F14 | S. 15–16, Wayland-Portals/Polkit | Sicherheitsfehler | Portalrechte über authentisierte Nutzersitzung + gegebenenfalls Restore-Token, kein selbstvergebener Polkit-Consent-Bypass. |
| F15 | S. 16, `uiAccess` als Universal-Privileg | Sicherheitsfehler | Signatur/Installationsort/Accessibility-Zweck; UAC-Secure-Desktop nicht pauschal steuerbar. Kein stillschweigender Privilegienwechsel. |
| F16 | S. 16–18, Shizuku/ADB Shell als Consumer-Standard | erhebliche Policy-/Sicherheitslücke | Debugging-Berechtigungen nicht als Allgemeinlösung. Play-Policy, Nutzerzustimmung und Android-Enterprise trennen. Kein Shizuku-Code eingebaut. |
| F17 | S. 18, `calculate_pixel_diff => 0.0` | **ausführbarer Logikfehler** | Der Algorithmus markiert nach dem ersten Frame auch Änderungen als stabil; W6 ersetzt dies durch BLAKE2b-Kacheldigests + Quiet-State-Nachweis. |
| F18 | S. 19, 'Zero-Knowledge' = Token + Socketrechte | Sicherheitsbegriff falsch | Das ist AuthN/AuthZ, kein Zero-Knowledge-Nachweis. Gleiches Linux-UID ≠ isolierte App. Explizite Produktbedrohungsmodelle notwendig. |
| F19 | S. 15, local RAM pointer-passing über IPC | fehlendes Besitzmodell | Pointer über Prozessgrenzen sind nicht gültig. Plattformgebundene FD/Handle-Transfers + sichere Ownership/Sync, sonst serialisierte Frames. |
| F20 | S. 17–19, autonome Computersteuerung und sensitive Apps nur per Koordinatenblockliste | unzureichend | Least privilege, konkrete Ressource, Sitzung, Consent, Frame-Epoche, Kurzzeitgrant, Preview, unabhängige Policy, sichere Abbruchfunktion. Keine systemweite freie Aktionen. |

## Verlässliche externe Quellen

- Apple DriverKit (macOS / unterstütztes iPadOS): https://developer.apple.com/documentation/DriverKit
- Apple App Intents (App-scoped Funktionen): https://developer.apple.com/documentation/AppIntents
- Google Play AccessibilityService-Autonomie-Regeln: https://support.google.com/googleplay/android-developer/answer/10964491?hl=en
- Android `dispatchGesture` inkl. Capability-Anforderung: https://developer.android.com/reference/kotlin/android/accessibilityservice/AccessibilityService
- Android 14 MediaProjection Einwilligung pro Session: https://developer.android.com/about/versions/14/behavior-changes-14
- Windows SendInput + UIPI: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput
- Windows UIAccess: https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-securityoverview
- Windows `IDXGIOutputDuplication::ReleaseFrame`: https://learn.microsoft.com/en-us/windows/desktop/api/DXGI1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe
- XDG RemoteDesktop portal: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html
- XDG ScreenCast portal: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html
- GStreamer D3D11 source/caps: https://gstreamer.freedesktop.org/documentation/d3d11/d3d11screencapturesrc.html

## Entscheidungen: Übernehmen / Umgestalten / Ablehnen

- **Übernehmen:** Standalone-first, User-Space, Port-/Adapter-Trennung, optionale multimodale Signale, risikobegrenzte Steuerung, GPU-Buffer-Lebensdauern, Test-First.
- **Umgestalten:** Rust als möglicher Zielkern, aber Python Referenz validieren; Shared Memory optional pro Plattform, Remote WebRTC optional; A11y nur wenn API/Store-Regeln es erlauben, keine garantierten Latenzen.
- **Ablehnen:** Verkleidung als virtuelles Systemgerät als generelle Lösung; iOS XCUITest als unsichtbarer Dauer-Dienst; automatische Admin-/Shell-Rechte; Consent-Bypass; Shizuku/ADB als Consumer Standard; frei formulierbare computer-use Aktionen ohne geschlossene Capability-Registry.

## Korrekte Entwicklungspriorität

1. Versionierter geschlossener Vertrag und OS-unabhängige Policy + expliziter Consent (W6 Dry-Run) — **lokal implementiert**.
2. Zeitlich, ressourcen- und framegebundene Actions mit 1-Use-Grant (W6 Dry-Run) — **lokal implementiert**; keine OS-Berechtigung.
3. Bildänderungssignal mit bounded RAM, kein Frame-Retention (W6 TileChangeTracker) — **lokal implementiert**; keine Screenshots/semantische Erkennung.
4. Owned Frame-Lease und garantierte Release-Aufrufe (W6 simuliert) — **lokal implementiert**; keine DXGI/GPU-Kompilierung.
5. Vorab geöffneter read-only POSIX-Descriptor ohne Client-Pfade (W6 Hostadapter) — **lokal implementiert**; noch nicht als IPC-Capability freigeben.
6. Vertrauenswürdige Principal-Isolation, Host-Consent, Linux-Portals und Windows-Reallauf, persistente Quittungen — **offen**.

## Qualitätsgrenzen

Das UDX-W6-Archiv ist ein **offline Forschungs-/Validierungsartefakt**. Windows-/Android-/iOS-SDKs, Hardware-GPU, Portale und privilegierte Dialoge wurden hier nicht ausgeführt. Ein echter user-consent-nachgewiesener Bildschirminput ist nicht implementiert. Ein zum **Nutzer erkennbares** Feedback (UI, Kill-Switch) und plattformgebundene Berechtigungsspeicher fehlen. Keine Produktionsfreigabe.
