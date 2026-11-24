# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [Unreleased]

### Neu
- **Regel „neu registrierte Domain“ (#25):** Anfragen an Domains, die jünger als 14 Tage sind (HaGeZi NRD, ~5 Mio. Domains), Schweregrad mittel. Binärsuche direkt in der Datei statt im Speicher (unter 30 MB), Erlaubnisliste `ALUCO_NRD_ALLOW`, abschaltbar mit `ALUCO_NRD_FEEDS=off`. ~90 MB Download pro Tag ([docs/stage-0.md](docs/stage-0.md#neu-registrierte-domains)).
- **Beispielsatz für die KI-Vorbewertung (#30):** `aluco ai-eval` misst die Bewertungsqualität eines Modells ([docs/ai.md](docs/ai.md)).

### Geändert
- **KI-Prompt v2 (#31):** erklärt, was „sperren“ bewirkt, verbietet Wissen von außen und härtet gegen eingeschleuste Anweisungen; qwen3:4b von 75 % auf 88 % Treffer.

## [0.2.0] – 2026-11-23

Stufe 1 in der Software: Geräte über **OPNsense** trennen, KI-Vorbewertung auch **lokal mit Ollama**, dazu HTTPS, Sicherung/Update und ein Integrationstest des ganzen Stacks. Weiterhin nicht im Dauerbetrieb auf echter Hardware geprüft.

### Neu
- **OPNsense (Stufe 1, optional):** Gerät eines Vorfalls per Klick vom Internet **trennen** und wieder **freigeben** (IP im Firewall-Alias `aluco_quarantine`), immer mit Rückfrage; Schutzliste und Firmengeräte nie. Bei DHCP-Wechsel wird die neue IP nachgezogen. ARP-Tabelle der Firewall als weitere Geräte-Quelle. Gegen OPNsense 26.7 mit Minimalrechten geprüft ([docs/opnsense.md](docs/opnsense.md)).
- **Lokale KI mit Ollama (optional):** `ALUCO_AI_PROVIDER=ollama` – Vorfallsdaten verlassen das Heimnetz nicht, keine API-Kosten ([docs/ai.md](docs/ai.md)).
- **HTTPS fürs Dashboard:** Caddy mit lokaler Zertifizierungsstelle, Compose-Profil `https` ([docs/https.md](docs/https.md)).
- **Betrieb:** `scripts/backup.sh`, `restore.sh`, `update.sh`; Warnung bei wenig Speicherplatz ([docs/operations.md](docs/operations.md)).
- **README auf Englisch**, deutsche Fassung in `README.de.md`.

### Geändert
- KI-Prompt: Eine zufällige (private) MAC-Adresse allein gilt nicht mehr als verdächtig; eine Domain von einer Bedrohungsliste bleibt ein starker Hinweis, auch wenn AdGuard sie blockiert hat.
- Datenbankschema v5 (Tabelle `blocks` für getrennte Geräte) – wird beim Start automatisch migriert. Vor dem Update `scripts/backup.sh` ausführen.

### Behoben
- OPNsense legt eine IP bei erneutem Sperren unter Umständen doppelt in der Konfiguration ab, entfernt beim Löschen aber nur einen Eintrag; Aluco räumt beim Freigeben jetzt vollständig auf, sonst wäre das Gerät nach dem nächsten Neuladen der Firewall wieder gesperrt.

### Intern
- CI: Integrationstest des ganzen Stacks (Job `integration`), Pflichtprüfung für `main` und `develop`.

### Bekannte Grenzen
- Getrennt wird vom **Internet**, nicht vom übrigen Heimnetz (dafür braucht es VLANs).
- Dass die Block-Regel echten Verkehr stoppt, ist noch nicht mit einem echten Gerät hinter OPNsense geprüft.
- Keine Datenmengen pro Gerät; NetAlertX-Scan und Dauerbetrieb auf dem Raspberry Pi noch nicht getestet.

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

[0.2.0]: https://github.com/rene404/aluco/releases/tag/v0.2.0
[0.1.0]: https://github.com/rene404/aluco/releases/tag/v0.1.0
