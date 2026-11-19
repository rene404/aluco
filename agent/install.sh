#!/bin/bash
# Aluco Laptop-Agent installieren (macOS, mit sudo ausführen).
#   sudo agent/install.sh http://192.0.2.2:8088 <TOKEN>
#   sudo agent/install.sh https://aluco.lan:8443 <TOKEN> /Pfad/zu/root.crt   (HTTPS mit Caddy)
# Voraussetzung: osquery (brew install --cask osquery).
# Nur auf PRIVATEN Geräten – nie auf Firmengeräten installieren.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Bitte mit sudo ausführen." >&2; exit 1; }
[[ $# -eq 2 || $# -eq 3 ]] || { echo "Aufruf: sudo $0 <ALUCO_URL> <TOKEN> [CA-Zertifikat]" >&2; exit 1; }
URL=$1 TOKEN=$2 CA=${3:-}
[[ -z "$CA" || -r "$CA" ]] || { echo "CA-Zertifikat nicht lesbar: $CA" >&2; exit 1; }
url_re='^https?://[][A-Za-z0-9.:_-]+$'  # "]" zuerst in der Klasse = wörtlich
[[ "$URL" =~ $url_re ]] || { echo "URL ungültig: $URL" >&2; exit 1; }
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]{20,100}$ ]] || { echo "Token ungültig" >&2; exit 1; }
[[ -x /usr/local/bin/osqueryi || -x /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd ]] \
  || { echo "osquery fehlt: brew install --cask osquery" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
LABEL=dev.aluco.agent

install -d -o root -g wheel -m 755 /usr/local/libexec /usr/local/etc
install -o root -g wheel -m 755 "$HERE/aluco-agent.sh" /usr/local/libexec/aluco-agent
CA_LINE=""
if [[ -n "$CA" ]]; then
  install -o root -g wheel -m 644 "$CA" /usr/local/etc/aluco-ca.crt
  CA_LINE="ALUCO_CACERT=/usr/local/etc/aluco-ca.crt"
fi
umask 077
printf 'ALUCO_URL=%s\nALUCO_TOKEN=%s\n%s\n' "$URL" "$TOKEN" "$CA_LINE" > /usr/local/etc/aluco-agent.conf
chown root:wheel /usr/local/etc/aluco-agent.conf
chmod 600 /usr/local/etc/aluco-agent.conf
install -o root -g wheel -m 644 "$HERE/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"

launchctl bootout system "/Library/LaunchDaemons/$LABEL.plist" 2>/dev/null || true
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"
echo "Installiert. Erster Bericht läuft jetzt; Log: /var/log/aluco-agent.log"
