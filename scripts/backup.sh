#!/usr/bin/env bash
# Aluco sichern – im laufenden Betrieb, ohne DNS-Ausfall.
#   scripts/backup.sh [ZIELORDNER]          (Standard: ./backups)
# Inhalt: Konfiguration und Daten aller Dienste (data/), .env, Compose-Overrides.
# Die Aluco-Datenbank wird per SQLite-Online-Backup konsistent kopiert.
# ACHTUNG: Das Archiv enthält Passwörter, Tokens und den privaten Schlüssel der
# HTTPS-Zertifizierungsstelle – nur verschlüsselt außer Haus lagern.
# Täglich per cron, z. B.:  30 3 * * *  cd /opt/aluco && scripts/backup.sh >/dev/null
set -euo pipefail

cd "$(dirname "$0")/.."
DATA_DIR="${ALUCO_DATA_DIR:-./data}"
TARGET="${1:-./backups}"
KEEP="${ALUCO_BACKUP_KEEP:-7}"
STAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$TARGET/aluco-$STAMP.tar.gz"

[[ -d "$DATA_DIR" ]] || { echo "backup: Datenordner $DATA_DIR fehlt" >&2; exit 1; }
[[ "$KEEP" =~ ^[0-9]+$ && "$KEEP" -ge 1 ]] || { echo "backup: ALUCO_BACKUP_KEEP ungültig" >&2; exit 1; }
mkdir -p "$TARGET"
umask 077

# 1) Aluco-Datenbank konsistent kopieren (läuft der Dienst, über ihn; sonst direkt).
SNAPSHOT="$DATA_DIR/aluco/backup-snapshot.db"
if [[ -f "$DATA_DIR/aluco/aluco.db" ]]; then
  if docker compose ps --status running --services 2>/dev/null | grep -qx aluco; then
    # Bewusst ohne Aluco-Kommando: funktioniert mit jeder Version des laufenden Images
    # (wichtig vor einem Update, wenn dort noch die alte Version läuft).
    docker compose exec -T aluco python -c '
import sqlite3, pathlib
target = pathlib.Path("/data/backup-snapshot.db")
target.unlink(missing_ok=True)
src, dst = sqlite3.connect("/data/aluco.db"), sqlite3.connect(target)
src.backup(dst)
dst.close()
src.close()
'
  else
    cp "$DATA_DIR/aluco/aluco.db" "$SNAPSHOT"  # Dienst gestoppt → Datei ist konsistent
  fi
fi
trap 'rm -f "$SNAPSHOT"' EXIT

# 2) Archiv: live genutzte SQLite-Dateien von Aluco auslassen (stattdessen der Snapshot),
#    Zwischenspeicher der Bedrohungslisten ebenfalls (wird neu geladen).
files=("$DATA_DIR")
for f in .env compose.override.yaml; do [[ -f "$f" ]] && files+=("$f"); done
tar -czf "$ARCHIVE" \
  --exclude="$DATA_DIR/aluco/aluco.db" \
  --exclude="$DATA_DIR/aluco/aluco.db-wal" \
  --exclude="$DATA_DIR/aluco/aluco.db-shm" \
  --exclude="$DATA_DIR/aluco/threatintel" \
  "${files[@]}"
chmod 600 "$ARCHIVE"

# 3) Nur die letzten KEEP Sicherungen behalten (Zeitstempel im Namen → alphabetisch = zeitlich).
shopt -s nullglob
all=("$TARGET"/aluco-*.tar.gz)
if (( ${#all[@]} > KEEP )); then
  for f in "${all[@]:0:${#all[@]}-KEEP}"; do rm -f -- "$f"; done
fi

size=$(du -h "$ARCHIVE" | cut -f1)
echo "Sicherung: $ARCHIVE ($size), behalten: $KEEP"
