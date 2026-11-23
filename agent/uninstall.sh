#!/bin/bash
# Aluco Laptop-Agent vollständig entfernen (macOS, mit sudo). osquery selbst bleibt.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Bitte mit sudo ausführen." >&2; exit 1; }
LABEL=dev.aluco.agent
launchctl bootout system "/Library/LaunchDaemons/$LABEL.plist" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/libexec/aluco-agent \
  /usr/local/etc/aluco-agent.conf /usr/local/etc/aluco-ca.crt /var/log/aluco-agent.log
echo "Entfernt. Im Dashboard/CLI zusätzlich: aluco agent remove <Gerät>"
