#!/usr/bin/env bash
# Aluco aus einer Sicherung wiederherstellen.
#   scripts/restore.sh backups/aluco-20261119-033000.tar.gz
# Stoppt die Dienste, verschiebt den aktuellen Datenordner nach data.vor-restore-<Zeit>,
# entpackt die Sicherung, setzt die Rechte und startet wieder.
set -euo pipefail

cd "$(dirname "$0")/.."
ARCHIVE="${1:-}"
DATA_DIR="${ALUCO_DATA_DIR:-./data}"
[[ -f "$ARCHIVE" ]] || { echo "Aufruf: $0 <Sicherung.tar.gz>" >&2; exit 1; }

# Archiv vorab prüfen: nur relative Pfade unter data/ bzw. .env, keine Ausbrüche.
if tar -tzf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  echo "restore: Archiv enthält unsichere Pfade – abgebrochen" >&2
  exit 1
fi
tar -tzf "$ARCHIVE" | grep -q "aluco/backup-snapshot.db" \
  || echo "restore: Hinweis – keine Aluco-Datenbank im Archiv" >&2

read -r -p "Aktuelle Daten werden ersetzt (Kopie bleibt erhalten). Fortfahren? [j/N] " answer
[[ "$answer" =~ ^[jJyY]$ ]] || { echo "Abgebrochen."; exit 0; }

docker compose --profile https stop
STAMP=$(date +%Y%m%d-%H%M%S)
if [[ -d "$DATA_DIR" ]]; then
  mv "$DATA_DIR" "$DATA_DIR.vor-restore-$STAMP"
  echo "Bisherige Daten: $DATA_DIR.vor-restore-$STAMP"
fi
[[ -f .env ]] && cp -p .env ".env.vor-restore-$STAMP"

tar -xzf "$ARCHIVE"
if [[ -f "$DATA_DIR/aluco/backup-snapshot.db" ]]; then
  mv "$DATA_DIR/aluco/backup-snapshot.db" "$DATA_DIR/aluco/aluco.db"
fi
# Aluco und Caddy laufen als Benutzer 10001.
for d in "$DATA_DIR/aluco" "$DATA_DIR/caddy"; do
  [[ -d "$d" ]] || continue
  if [[ $EUID -eq 0 ]]; then
    chown -R 10001:10001 "$d"
  elif ! sudo -n chown -R 10001:10001 "$d" 2>/dev/null; then
    echo "restore: Bitte ausführen: sudo chown -R 10001:10001 $d" >&2
  fi
done

docker compose up -d
echo "Wiederhergestellt aus $ARCHIVE. Mit HTTPS: docker compose --profile https up -d"
