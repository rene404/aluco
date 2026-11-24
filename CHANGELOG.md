# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [SemVer](https://semver.org/lang/de/).

## [0.4.1] – 2026-11-24

Claude für die KI-Vorbewertung jetzt auch **über OpenRouter** – und erstmals gemessen: 100 % im Beispielsatz, auf Deutsch und auf Englisch.

### Neu
- **KI über OpenRouter:** `ALUCO_AI_PROVIDER=openrouter` mit `OPENROUTER_API_KEY` und z. B. `ALUCO_AI_MODEL=anthropic/claude-opus-5.5` (günstiger: `anthropic/claude-sonnet-5.5`, `anthropic/claude-haiku-5.5`). Gleicher Prompt, strenges Antwortschema, Schutzregel; OpenRouter leitet nur an Anbieter weiter, die Anfragen nicht speichern oder zum Training nutzen (`data_collection: deny`). Claude-Modelle bekommen keine `temperature` (Claude 5 lehnt sie ab). Auch für `aluco ai-eval --provider openrouter` ([docs/ai.md](docs/ai.md#über-openrouter)).
- **Claude gemessen (#24):** Claude Opus 5.5 über OpenRouter trifft im Beispielsatz 64/64 – auf Deutsch und auf Englisch, ohne dass die Schutzregel eingreifen musste. Empfehlung: Ollama, wenn die Daten das Heimnetz nicht verlassen sollen; Claude für die beste Einschätzung ([docs/ai.md](docs/ai.md)).

### Hinweis
- Wer `ALUCO_AI_PROVIDER=openrouter` setzt, braucht mindestens diese Version – ältere brechen mit einem Konfigurationsfehler ab.

## [0.4.0] – 2026-11-24

**Aluco auf Englisch** und eine KI-Vorbewertung, die Zusammenhänge pro Gerät sieht und sich nicht durch eingeschleusten Text kleinreden lässt. Weiterhin nicht im Dauerbetrieb auf echter Hardware geprüft.

### Neu
- **Englische Version (#29):** `ALUCO_LANGUAGE=en` stellt Dashboard, Wochenbericht, ntfy-Meldungen, Titel neuer Vorfälle und Ereignisse, MCP-Server und KI-Vorbewertung auf Englisch um; Deutsch bleibt Standard. Übersetzung über `aluco.i18n` (deutscher Text als Schlüssel, Katalog in `aluco/locale_en.py`); Tests melden fehlende Übersetzungen und fest eingebaute Texte in Vorlagen. Zahlen und Daten im jeweiligen Format. Schon gespeicherte Titel bleiben in ihrer ursprünglichen Sprache.
- **KI-Vorbewertung auf Englisch:** eigener englischer Prompt mit erklärten Antwortwerten; der deutsche Prompt bleibt Zeichen für Zeichen unverändert. `aluco ai-eval --language en`. qwen3:4b: Englisch 91 %, Deutsch 88 % ([docs/ai.md](docs/ai.md)).
- **Schutzregel gegen eingeschleuste Anweisungen:** Enthalten die Vorfallsdaten Text, der wie eine Anweisung an die KI aussieht (z. B. ein Domainname `ignore-previous-instructions…`), fällt die Einschätzung nie unter „beobachten / prüfen“ – unabhängig von Sprache und Modell. Anlass: Der englische Prompt ließ sich so auf „harmlos“ drehen.
- **KI erkennt Zusammenhänge pro Gerät (#26):** Die Vorbewertung sieht bis zu 5 andere offene Vorfälle desselben Geräts (±7 Tage) – nur Regel, Abstand, Status, KI-Einstufung, keine Kennungen. Ein neues Gerät, das kurz darauf eine Schad-Domain anfragt, gilt jetzt als „verdächtig“ statt „beobachten“. Erledigte und ignorierte Vorfälle bleiben bewusst weg (gemessen). Beispielsatz: 32 Fälle.

### Geändert
- Wochenbericht: Eine Datenquelle gilt erst als gestört, wenn sie mindestens 30 Minuten am Stück ausgefallen war. Kurze Aussetzer machen eine Woche nicht mehr unruhig.
- Ereignisse tragen sprachneutrale Merkmale (`tag`, `subject`); Wochenbericht und Chronik werten nicht mehr den Wortlaut der Titel aus. Datenbankschema v7 – wird beim Start automatisch migriert, bestehende Ereignisse werden eingeordnet. Vor dem Update `scripts/backup.sh` ausführen.
- „Inventar übernommen: 1 Gerät“ statt „1 Geräte“; Blockquote im Dashboard mit Dezimalkomma.

### Bekannte Grenzen
- Die Dokumentation in `docs/` ist weiterhin deutsch.
- KI-Vorbewertung nur mit qwen3:4b gemessen; Messung mit Claude steht aus (#24). Auf Englisch erkennt qwen3:4b die Kombination „neues Gerät, kurz danach Schad-Domain“ nicht.
- Dass die Block-Regel echten Verkehr stoppt, ist noch nicht mit einem echten Gerät hinter OPNsense geprüft; Dauerbetrieb auf dem Raspberry Pi noch nicht getestet.

## [0.3.0] – 2026-11-24

Mehr Erkennung, weniger Abstumpfen: neue Regel für **neu registrierte Domains**, eine Übersicht zur **Regel-Qualität**, ein **Wochenbericht** und ein Beispielsatz, mit dem sich die KI-Vorbewertung messen lässt. Weiterhin nicht im Dauerbetrieb auf echter Hardware geprüft.

### Neu
- **Regel „neu registrierte Domain“ (#25):** Anfragen an Domains, die jünger als 14 Tage sind (HaGeZi NRD, ~5 Mio. Domains), Schweregrad mittel. Binärsuche direkt in der Datei statt im Speicher (unter 30 MB), Erlaubnisliste `ALUCO_NRD_ALLOW`, abschaltbar mit `ALUCO_NRD_FEEDS=off`. ~90 MB Download pro Tag ([docs/stage-0.md](docs/stage-0.md#neu-registrierte-domains)).
- **Beispielsatz für die KI-Vorbewertung (#30):** `aluco ai-eval` misst die Bewertungsqualität eines Modells ([docs/ai.md](docs/ai.md)).
- **Regel-Qualität (#28):** neue Seite „Regeln“ im Dashboard und MCP-Werkzeug `rule_quality` – je Regel ausgelöst, ignoriert, erledigt, getrennt, Ignorier-Quote und Zeit bis zur Entscheidung; Regeln mit über 70 % ignorierten Vorfällen werden hervorgehoben. Datenbank-Schema v6 (Verlauf ohne Gerätekennungen, 400 Tage).
- **Wochenbericht (#27):** jeden Sonntag 18 Uhr per ntfy „Ruhige Woche – alles normal“ oder was los war – nur Zahlen, keine Namen. Tag und Uhrzeit einstellbar (`ALUCO_REPORT_WEEKDAY`, `ALUCO_REPORT_HOUR`), abschaltbar (`ALUCO_REPORT=off`). Im Dashboard als Karte in der Übersicht.

### Geändert
- **KI-Prompt v2 (#31):** erklärt, was „sperren“ bewirkt, verbietet Wissen von außen und härtet gegen eingeschleuste Anweisungen; qwen3:4b von 75 % auf 88 % Treffer ([docs/ai.md](docs/ai.md)).
- Datenbankschema v6 (Tabelle `incident_history`) – wird beim Start automatisch migriert; vorhandene Vorfälle zählen als „ausgelöst“, frühere Entscheidungen lassen sich nicht rekonstruieren. Vor dem Update `scripts/backup.sh` ausführen.
- Breite Tabellen verbreitern auf dem Handy nicht mehr die ganze Seite.

### Bekannte Grenzen
- Die NRD-Listen kosten ~90 MB Download pro Tag (~2,6 GB im Monat); bei knappem Datenvolumen `ALUCO_NRD_FEEDS=off`.
- KI-Vorbewertung bisher nur mit qwen3:4b gemessen (88 %); Messung mit Claude steht aus (#24).
- Dass die Block-Regel echten Verkehr stoppt, ist noch nicht mit einem echten Gerät hinter OPNsense geprüft; Dauerbetrieb auf dem Raspberry Pi noch nicht getestet.

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

[0.4.1]: https://github.com/rene404/aluco/releases/tag/v0.4.1
[0.4.0]: https://github.com/rene404/aluco/releases/tag/v0.4.0
[0.3.0]: https://github.com/rene404/aluco/releases/tag/v0.3.0
[0.2.0]: https://github.com/rene404/aluco/releases/tag/v0.2.0
[0.1.0]: https://github.com/rene404/aluco/releases/tag/v0.1.0
