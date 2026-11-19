#!/bin/bash
# Aluco Laptop-Agent (macOS): feste, nur lesende osquery-Abfragen → Bericht an Aluco.
# Läuft per launchd alle 10 Minuten als root (nötig für Ports aller Prozesse).
# Konfiguration: /usr/local/etc/aluco-agent.conf (nur root lesbar)
#   ALUCO_URL=http://192.0.2.2:8088
#   ALUCO_TOKEN=…            (aus: aluco agent add <Gerät>)
set -euo pipefail

CONF="${ALUCO_AGENT_CONF:-/usr/local/etc/aluco-agent.conf}"
[[ -r "$CONF" ]] || { echo "aluco-agent: $CONF fehlt" >&2; exit 2; }

# Konfiguration lesen, ohne sie auszuführen (kein "source").
ALUCO_URL=$(sed -n 's/^ALUCO_URL=//p' "$CONF" | head -1)
ALUCO_TOKEN=$(sed -n 's/^ALUCO_TOKEN=//p' "$CONF" | head -1)
[[ "$ALUCO_URL" =~ ^https?://[A-Za-z0-9.:_\[\]-]+$ ]] || { echo "aluco-agent: ALUCO_URL ungültig" >&2; exit 2; }
[[ "$ALUCO_TOKEN" =~ ^[A-Za-z0-9_-]{20,100}$ ]] || { echo "aluco-agent: ALUCO_TOKEN ungültig" >&2; exit 2; }

OSQ=""
for candidate in /usr/local/bin/osqueryi /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd; do
  [[ -x "$candidate" ]] && OSQ="$candidate" && break
done
[[ -n "$OSQ" ]] || { echo "aluco-agent: osquery nicht gefunden" >&2; exit 2; }

q() {  # Abfrage → JSON-Liste; bei Fehler (Tabelle fehlt) leere Liste
  local out
  if [[ "$OSQ" == *osqueryd ]]; then
    out=$("$OSQ" -S --json "$1" 2>/dev/null) || out='[]'
  else
    out=$("$OSQ" --json "$1" 2>/dev/null) || out='[]'
  fi
  [[ -n "$out" ]] && printf '%s' "$out" || printf '[]'
}

tmp=$(mktemp -t aluco-agent)
chmod 600 "$tmp"
trap 'rm -f "$tmp"' EXIT

{
  printf '{"agent_version":"1"'
  printf ',"system":%s' "$(q "SELECT hostname, computer_name, hardware_model FROM system_info;")"
  printf ',"os":%s' "$(q "SELECT name, version FROM os_version;")"
  printf ',"listening_ports":%s' "$(q "SELECT DISTINCT lp.port, lp.protocol, lp.address, p.name, p.path FROM listening_ports lp LEFT JOIN processes p USING (pid) WHERE lp.port != 0;")"
  printf ',"autostart":%s' "$(q "SELECT label, path, program, program_arguments FROM launchd WHERE (run_at_load = '1' OR keep_alive = '1') AND path NOT LIKE '/System/%';")"
  printf ',"logged_in_users":%s' "$(q "SELECT user, type, host FROM logged_in_users;")"
  printf ',"firewall":%s' "$(q "SELECT global_state FROM alf;")"
  printf ',"filevault":%s' "$(q "SELECT encrypted FROM disk_encryption WHERE encrypted IS NOT NULL;")"
  printf ',"gatekeeper":%s' "$(q "SELECT assessments_enabled FROM gatekeeper;")"
  printf ',"sip":%s' "$(q "SELECT enabled FROM sip_config WHERE config_flag = 'sip';")"
  printf '}'
} > "$tmp"

# Token über stdin an curl – nie auf der Kommandozeile (sonst in "ps" sichtbar).
curl -fsS --max-time 30 -X POST \
  -H 'Content-Type: application/json' \
  --data-binary @"$tmp" \
  -K - "$ALUCO_URL/api/agent/report" <<<"header = \"Authorization: Bearer $ALUCO_TOKEN\""
echo
