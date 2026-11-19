# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [0.1.0] – 2026-11-19

Erste Version: Software für **Stufe 0** (Inventar + DNS-Protokoll ohne Netzumbau) samt Dashboard, KI-Vorbewertung, MCP-Server und Laptop-Agent. Noch nicht auf echter Hardware im Dauerbetrieb geprüft.

### Neu
- **Stufe 0 per Docker Compose:** AdGuard Home + NetAlertX, gehärtete Container, Einrichtungsskript für AdGuard (`scripts/adguard-setup.sh`).
- **Kern:** Datenmodell, Vorfall-Ablauf (zusammenfassen, dauerhaft ignorieren, wieder öffnen), Schutzliste, Firmengeräte nur passiv.
- **Regeln:** neues Gerät · neue Domain bei IoT-Geräten nach Lernphase · **bekannte Schad-Domain** (HaGeZi TIF, erweiterbar).
- **Runner:** regelmäßiger Lauf, Lernmodus beim ersten Lauf, Meldungen per **ntfy**.
- **Dashboard (Design V1):** Lagebild, Kennzahlen, DNS-Diagramm, Chronik, Vorfälle als Karten, Gerätekarten mit Mini-Verlauf, Gerätedetail; hell/dunkel; strikte CSP.
- **KI-Vorbewertung (optional):** Claude bewertet neue Vorfälle datensparsam (nie Namen, IPs, MACs, Firmengeräte).
- **MCP-Server (optional):** Claude Desktop/Code fragt das Netz **nur lesend** über stdio/SSH.
- **Laptop-Agent (osquery, optional):** offene Ports, Autostart, Fern-Anmeldungen, Firewall/FileVault/Gatekeeper/SIP auf privaten Macs.
- **Kommandozeile:** `aluco run|once|web|mcp`, `aluco device …`, `aluco agent …`.

### Sicherheit
- Unabhängige Sicherheitsprüfung, alle Befunde (3 mittel, 6 niedrig) behoben: u. a. keine IPs/Hostnamen über lokale DNS-Namen an die KI, sichere Zuordnung bei DHCP-Wechseln, Schutz vor DNS-Rebinding, Secrets je Container getrennt.
- Abhängigkeiten, Images, Actions und Hooks auf Versionen/Commits festgelegt; 7 Tage Wartezeit für Updates.

### Bekannte Grenzen
- Ohne Firewall (Stufe 1): kein „Trennen“, keine Datenmengen pro Gerät.
- Dashboard ohne eingebautes HTTPS – Reverse-Proxy mit TLS empfohlen.
- NetAlertX-Scan und Dauerbetrieb auf dem Raspberry Pi noch nicht getestet.

[0.1.0]: https://github.com/rene404/aluco/releases/tag/v0.1.0
