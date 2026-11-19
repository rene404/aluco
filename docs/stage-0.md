# Stufe 0 – DNS-Protokoll und Geräteinventar

Stand: 2026-11-19 · Ziel: sehen, welche Geräte im Netz sind und welche Domains sie anfragen – ohne das Netz umzubauen.

| Dienst | Aufgabe | Oberfläche |
|---|---|---|
| AdGuard Home | DNS für das Heimnetz, Protokoll pro Gerät, Filter | `http://<server>/` |
| NetAlertX | Geräteinventar per ARP-Scan, Meldung bei neuen Geräten | `http://<server>:20211/` |
| Aluco | Führt beides zusammen: Inventar, Domains pro Gerät, Vorfälle, Meldungen per ntfy | – (Dashboard folgt) |

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
3. Starten: `docker compose up -d --build aluco`, Kontrolle: `docker logs -f aluco`.

Der **erste Lauf lernt nur** (übernimmt alle vorhandenen Geräte ohne Alarm). Ab dem zweiten Lauf meldet Aluco unbekannte Geräte; Anfragen an neue Domains meldet es nur bei IoT-Geräten und erst nach 7 Tagen Lernphase. Die Vertrauensstufe (IoT, Firma …) lässt sich vorerst nur direkt in der Datenbank setzen; das Dashboard folgt.

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

- [ ] Jedes Gerät im NetAlertX-Inventar benannt, Firmengeräte markiert.
- [ ] AdGuard zeigt Anfragen pro Gerät (nicht nur die IP des Routers).
- [ ] Meldung bei neuem Gerät kommt an (Test: Handy im Gästemodus/mit zufälliger MAC verbinden).
- [ ] Rückweg getestet.
- [ ] Eine Woche Baseline: Fehlalarme notiert.

## Betrieb

- **Updates:** Dependabot schlägt neue Image-Versionen als Pull Request vor. Danach am Server: `git pull && docker compose pull adguardhome netalertx && docker compose up -d --build`.
- **Sicherung:** Ordner `data/` (Konfiguration + Datenbanken) regelmäßig sichern.
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
