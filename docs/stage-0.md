# Stufe 0 – DNS-Protokoll und Geräteinventar

Stand: 2026-11-19 · Ziel: sehen, welche Geräte im Netz sind und welche Domains sie anfragen – ohne das Netz umzubauen.

| Dienst | Aufgabe | Oberfläche |
|---|---|---|
| AdGuard Home | DNS für das Heimnetz, Protokoll pro Gerät, Filter | `http://<server>/` |
| NetAlertX | Geräteinventar per ARP-Scan, Meldung bei neuen Geräten | `http://<server>:20211/` |
| Aluco | Führt beides zusammen: Inventar, Domains pro Gerät, Vorfälle, Meldungen per ntfy | – |
| Aluco-Dashboard | Übersicht, Vorfälle bearbeiten, Geräte einordnen | `http://<server>:8088/` |

Alle laufen per Docker Compose (`compose.yaml`) im Host-Netz des Servers.

## Voraussetzungen

- Server mit 64-bit-Linux (z. B. Raspberry Pi OS Lite 64-bit), per Kabel im Heimnetz.
- **Feste IP** für den Server per DHCP-Reservierung im Router.
- Zugang per SSH mit Schlüssel, Passwort-Login abgeschaltet.
- Docker Engine + Compose-Plugin (`curl -fsSL https://get.docker.com | sh` – Skript vorher lesen).
- Port 53 frei: unter Ubuntu belegt `systemd-resolved` ihn (`DNSStubListener=no` setzen). Raspberry Pi OS ist nicht betroffen.

## Einrichtung

```sh
git clone https://github.com/rene404/aluco.git && cd aluco
cp .env.example .env              # TZ, Speichergrenzen anpassen
chmod 600 .env                    # enthält später Passwörter
mkdir -p data/aluco && sudo chown 10001:10001 data/aluco   # Aluco läuft als Benutzer 10001
docker compose pull adguardhome netalertx
docker compose up -d adguardhome netalertx
scripts/adguard-setup.sh          # Login, verschlüsseltes Upstream-DNS, 30 Tage Protokoll
```

`adguard-setup.sh` fragt das Passwort ab (mindestens 12 Zeichen, nirgends gespeichert) und lässt sich gefahrlos erneut ausführen.

**Kontrolle am Server:**

```sh
docker compose ps                                  # beide "running"
dig +short @127.0.0.1 example.com                  # liefert eine IP
```

### NetAlertX

1. `http://<server>:20211/` öffnen → **Settings**.
2. `SCAN_SUBNETS` auf das eigene Netz setzen, z. B. `192.0.2.0/24 --interface=eth0` (Netz und Schnittstelle mit `ip -4 addr` prüfen).
3. Benachrichtigung bei neuem Gerät einschalten (z. B. ntfy oder E-Mail).
4. Oberfläche mit Passwort schützen (`SETPWD_enable_password`).
5. **API-Token für Aluco:** Settings → `API_TOKEN` kopieren und in `.env` als `NETALERTX_API_TOKEN` eintragen. Das Token erlaubt auch Schreiben und Löschen – Aluco nutzt es nur lesend, trotzdem wie ein Passwort behandeln.

### Aluco-Dienst

1. In `.env` eintragen: `ADGUARD_PASSWORD` (aus `adguard-setup.sh`), `NETALERTX_API_TOKEN` (siehe oben).
2. Optional Meldungen: `NTFY_URL` (komplette Topic-URL). Bei öffentlichem ntfy-Server einen langen, zufälligen Topic-Namen wählen und `ALUCO_NOTIFY_MINIMAL=true` setzen – dann verlassen keine Geräte- oder Domainnamen das Heimnetz.
   - **Wochenbericht:** Mit ntfy kommt jeden Sonntag um 18 Uhr (Zeitzone `TZ`) eine leise Meldung – „Ruhige Woche – alles normal“ oder was los war: neue Geräte, Vorfälle je Schweregrad, Entscheidungen, Offenes, getrennte Geräte, DNS-Anfragen und Blockquote, Laptops, ausgefallene Datenquellen. Nur Zahlen, keine Namen. Einstellbar mit `ALUCO_REPORT_WEEKDAY` (mo … so) und `ALUCO_REPORT_HOUR`, abschaltbar mit `ALUCO_REPORT=off`. Der erste Bericht kommt zum ersten Termin nach dem Start; war Aluco zum Termin aus, wird er beim nächsten Lauf nachgeholt. Dieselben Zahlen zeigt die Übersicht im Dashboard (Karte „Wochenbericht“, letzte 7 Tage).
3. Dashboard-Passwort setzen: `ALUCO_DASHBOARD_PASSWORD` (mindestens 12 Zeichen).
4. Starten: `docker compose up -d --build aluco aluco-web`, Kontrolle: `docker logs -f aluco`.
5. Dashboard: `http://<server>:8088/` – nur im Heimnetz bzw. per VPN, nie per Portfreigabe ins Internet. Aufruf über die IP-Adresse; für einen Namen (z. B. `aluco.lan`) diesen in `ALUCO_WEB_ALLOWED_HOSTS` eintragen.
6. **HTTPS empfohlen:** Ohne TLS gehen Passwort und Sitzung im WLAN unverschlüsselt über die Luft. Caddy mit lokaler Zertifizierungsstelle ist vorbereitet: [docs/https.md](https.md). Aluco warnt beim Start, solange HTTPS fehlt.
7. NetAlertX- und AdGuard-Oberfläche ebenfalls mit Passwort schützen (siehe oben) – sie zeigen das komplette Inventar bzw. alle DNS-Anfragen.

Der **erste Lauf lernt nur** (übernimmt alle vorhandenen Geräte ohne Alarm). Ab dem zweiten Lauf meldet Aluco unbekannte Geräte; Anfragen an neue Domains meldet es nur bei IoT-Geräten und erst nach 7 Tagen Lernphase. ### Geräte einordnen

**Direkt nach dem ersten Lauf** Firmengeräte markieren – dabei löscht Aluco alles, was es über deren DNS-Verhalten schon gespeichert hat. Am einfachsten im Dashboard unter **Geräte**; alternativ per Kommandozeile:

```sh
docker compose run --rm aluco device list                         # Inventar mit MAC-Adressen
docker compose run --rm aluco device set-trust <MAC> company      # Firmengerät: nur passiv, nie trennbar
docker compose run --rm aluco device set-trust <MAC> iot          # IoT: Meldung bei neuen Domains
docker compose run --rm aluco device protect <MAC>                # Schutzliste (Server, Firewall …)
docker compose run --rm aluco device name <MAC> "Fernseher"       # Namen vergeben
```

Stufen: `known`, `iot`, `guest`, `unknown`, `company`. Den Aluco-Server selbst und die Firewall auf die Schutzliste setzen.

### Bekannte Schad-Domains

Aluco gleicht jede DNS-Anfrage mit öffentlichen Bedrohungslisten ab (Malware, Phishing, Command-and-Control). Ein Treffer ist ein Vorfall mit Schweregrad **hoch** – auch wenn AdGuard die Anfrage schon blockiert hat, denn der Versuch selbst deutet auf Schadsoftware oder einen Phishing-Link hin. Firmengeräte sind ausgenommen.

- Standardliste: [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (mini, ~210 000 Domains, ohne Schlüssel, GPL-3.0). Wird alle 12 Stunden geladen und im Datenordner zwischengespeichert; fällt der Download aus, gilt die letzte Liste weiter.
- Weitere Listen (z. B. abuse.ch URLhaus/ThreatFox mit kostenlosem Auth-Key) über `ALUCO_THREAT_FEEDS`, Formate: Domains, Hosts-Datei, Adblock.
- Tipp: dieselbe Liste zusätzlich in AdGuard unter *Filter → DNS-Sperrlisten* eintragen, dann wird auch blockiert.
- Speicherbedarf ca. 20–40 MB.

### Neu registrierte Domains

Aluco meldet Anfragen an Domains, die erst in den letzten 14 Tagen registriert wurden. Solche Domains nutzen Betrüger gern für Phishing, Schadsoftware und Command-and-Control, weil sie billig und schnell wieder weg sind. Viele neue Domains sind aber harmlos (neue Webseiten, Kampagnen, Dienste) – darum nur Schweregrad **mittel**. Firmengeräte sind ausgenommen.

- Ein Vorfall je Gerät und registrierter Domain (`login.neu.example` und `neu.example` zählen zusammen), Wiederholungen zählen hoch.
- Steht die Domain zugleich auf einer Bedrohungsliste, meldet Aluco nur die Schad-Domain (hoch).
- Standardliste: [HaGeZi NRD](https://github.com/hagezi/nrd), letzte 14 Tage (`nrd7` + `nrd14-8`, ~5 Mio. Domains). Wird einmal am Tag geladen (**~90 MB Download pro Tag**, ~2,6 GB im Monat) und im Datenordner zwischengespeichert (~90 MB); fällt der Download aus, gilt die letzte Liste weiter.
- Arbeitsspeicher: kaum (unter 30 MB). Aluco sucht per Binärsuche direkt in der sortierten Datei, statt 5 Mio. Domains in den Speicher zu laden (wären ~500 MB).
- `ALUCO_NRD_ALLOW`: eigene oder bekannte neue Domains, die nie als neu registriert gelten (inkl. Subdomains), z. B. `meinverein-2026.at, neuer-shop.example`.
- `ALUCO_NRD_FEEDS=off` schaltet die Regel ab, z. B. bei knappem Datenvolumen. Eigene Listen: `name=https-URL` (reine Domains).

## DNS im Router umstellen

Erst wenn AdGuard am Server antwortet.

- **Router verteilt per DHCP:** primären DNS auf die IP des Servers setzen. **Keinen öffentlichen Zweit-DNS** eintragen – Geräte würden ihn nutzen und am Protokoll vorbeigehen.
- **Router/Mesh im Access-Point-Modus:** dort lässt sich kein DNS eintragen. Dann im Gerät einstellen, das DHCP macht (meist der Provider-Router), oder DHCP an AdGuard Home übergeben (nur ein DHCP-Server im Netz!).

Geräte übernehmen den neuen DNS erst mit der nächsten DHCP-Verlängerung (WLAN aus/an beschleunigt das).

## Rückweg (vorher testen!)

Fällt der Server aus, funktioniert im Netz keine Namensauflösung mehr.

1. Im Router den DNS-Eintrag wieder auf **automatisch/Provider** stellen.
2. Geräte neu verbinden (WLAN aus/an).

Diesen Ablauf einmal bewusst durchspielen und die Schritte für den Router notieren (privat, nicht im Repo).

## Abnahme

- [ ] Jedes Gerät benannt (NetAlertX oder `aluco device name`), Firmengeräte als `company` markiert, Server auf der Schutzliste.
- [ ] AdGuard zeigt Anfragen pro Gerät (nicht nur die IP des Routers).
- [ ] Meldung bei neuem Gerät kommt an (Test: Handy im Gästemodus/mit zufälliger MAC verbinden).
- [ ] Rückweg getestet.
- [ ] Eine Woche Baseline: Fehlalarme notiert.

## Betrieb

- **Updates:** `scripts/update.sh` (sichert vorher, prüft danach) – siehe [operations.md](operations.md).
- **Sicherung:** `scripts/backup.sh`, am besten täglich per cron – siehe [operations.md](operations.md).
- **Protokolle:** werden nach `ALUCO_RETENTION_DAYS` (Standard 30) gelöscht. Haushalt informieren, dass DNS-Anfragen protokolliert werden.

## Lokal testen (Mac)

```sh
docker compose -f compose.yaml -f compose.local.yaml up -d
AGH_SETUP_URL=http://127.0.0.1:3300 AGH_URL=http://127.0.0.1:8300 scripts/adguard-setup.sh
dig @127.0.0.1 -p 5300 example.com
docker compose -f compose.yaml -f compose.local.yaml down -v   # aufräumen
```

NetAlertX läuft lokal nicht (ARP-Scan braucht ein Linux-Host-Netz).

## Sicherheitshinweise

- Beide Container: Dateisystem schreibgeschützt, Rechte auf das Nötige beschränkt, Speicher- und Prozessgrenzen.
- AdGuard läuft als root (Vorgabe beim ersten Start), aber ohne weitere Rechte als Ports binden und Daten schreiben, ohne Rechteausweitung.
- Oberflächen nur im Heimnetz erreichbar machen, nie per Portfreigabe ins Internet.
- NetAlertX enthält PHP; bei PHP-Sicherheitswarnungen das Image zeitnah aktualisieren.
