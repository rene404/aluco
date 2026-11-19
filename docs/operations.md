# Betrieb: Sicherung, Wiederherstellung, Update

Stand: 2026-11-19

## Sicherung – `scripts/backup.sh`

```sh
scripts/backup.sh                 # nach ./backups, die letzten 7 bleiben
ALUCO_BACKUP_KEEP=14 scripts/backup.sh /mnt/usb/aluco
```

- Läuft **im Betrieb** – kein DNS-Ausfall. Die Aluco-Datenbank wird per SQLite-Online-Backup konsistent kopiert (funktioniert mit jeder Aluco-Version, auch vor einem Update).
- Enthält `data/` (Aluco, AdGuard, NetAlertX, Caddy-Zertifikate), `.env` und ggf. `compose.override.yaml`. Der Zwischenspeicher der Bedrohungslisten wird ausgelassen.
- Archive sind nur für den Besitzer lesbar (`600`). Sie enthalten **Passwörter, Tokens und den privaten Schlüssel der HTTPS-Zertifizierungsstelle** – außer Haus nur verschlüsselt lagern.

Täglich automatisch (crontab des Benutzers, der Docker bedienen darf):

```cron
30 3 * * *  cd /opt/aluco && scripts/backup.sh >/dev/null 2>>backups/backup.log
```

## Wiederherstellung – `scripts/restore.sh`

```sh
scripts/restore.sh backups/aluco-20261119-033000.tar.gz
```

Fragt nach, stoppt die Dienste, verschiebt den aktuellen Stand nach `data.vor-restore-<Zeit>` (und `.env` entsprechend), entpackt, setzt die Rechte und startet neu. Archive mit absoluten Pfaden oder `..` werden abgelehnt.

## Update – `scripts/update.sh`

```sh
scripts/update.sh           # neuester Stand von main
scripts/update.sh v0.2.0    # bestimmte Version
```

Ablauf: **Sicherung → `git` auf neuen Stand → Images ziehen/bauen → neu starten → Gesundheitsprüfung des Dashboards**. Bricht ab, wenn es lokale Änderungen im Repo gibt. Läuft HTTPS (Caddy), bleibt es aktiv.

Zurück bei Problemen: `git checkout <vorherige Version> && docker compose up -d --build` oder `scripts/restore.sh <letzte Sicherung>`.

## Speicherplatz

Aluco prüft bei jedem Lauf den freien Platz auf dem Datenträger der Daten. Unter **1 GB oder 5 %** erscheint eine Warnung bei den Datenquellen im Dashboard und in der Chronik („Speicherplatz knapp“). Gegenmittel: alte Sicherungen löschen, Aufbewahrung (`ALUCO_RETENTION_DAYS`) verkürzen, `docker image prune`.
