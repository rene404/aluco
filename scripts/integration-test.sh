#!/usr/bin/env bash
# Integrationstest: ganzer Stack in Docker, ohne Host-Netz (läuft in der CI und lokal).
#   scripts/integration-test.sh          testen und danach aufräumen
#   KEEP=1 scripts/integration-test.sh   Stack danach laufen lassen
# Achtung lokal: nutzt dieselben Containernamen wie der lokale Test-Stack und löscht am
# Ende dessen Volumes (down -v) – lokal nur ausführen, wenn dort nichts Wichtiges liegt.
set -euo pipefail
cd "$(dirname "$0")/.."

dc() { docker compose -f compose.yaml -f compose.local.yaml -f ci/compose.ci.yaml --profile https "$@"; }
fail() { echo "FEHLER: $*" >&2; dc logs --tail 40 >&2 || true; exit 1; }
ok() { echo "  ✓ $*"; }
wait_for() {  # wait_for <Sekunden> <Beschreibung> <Befehl …>
  local limit=$1 what=$2; shift 2
  local start=$SECONDS
  until "$@" >/dev/null 2>&1; do
    (( SECONDS - start > limit )) && fail "$what nach ${limit}s nicht bereit"
    sleep 2
  done
  ok "$what"
}
cleanup() { [[ "${KEEP:-0}" == 1 ]] || dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

WORK=$(mktemp -d)
ADGUARD_PW="ci-adguard-$(openssl rand -hex 8)"
WEB_PW="ci-web-$(openssl rand -hex 8)"
[[ -f .env && "${CI:-}" != true ]] && cp .env "$WORK/env.backup"
restore_env() { if [[ -f "$WORK/env.backup" ]]; then cp "$WORK/env.backup" .env; else rm -f .env; fi; rm -rf "$WORK"; }
trap 'cleanup; restore_env' EXIT

cp .env.example .env
{
  echo "ADGUARD_PASSWORD=$ADGUARD_PW"
  echo "ALUCO_DASHBOARD_PASSWORD=$WEB_PW"
  echo "ALUCO_INTERVAL_SECONDS=30"
  echo "ALUCO_THREAT_FEEDS=off"
} >> .env

echo "1) Stack bauen und starten"
dc build --quiet aluco caddy
dc up -d adguardhome netalertx
wait_for 90 "AdGuard-Assistent" curl -fsS http://127.0.0.1:3300/install.html
AGH_SETUP_URL=http://127.0.0.1:3300 AGH_URL=http://127.0.0.1:8300 ALUCO_ADGUARD_PASSWORD="$ADGUARD_PW" \
  scripts/adguard-setup.sh >/dev/null
ok "AdGuard eingerichtet"
for d in example.com example.org iana.org; do dig +short @127.0.0.1 -p 5300 "$d" >/dev/null || true; done

nax_token() { dc exec -T netalertx sqlite3 /data/db/app.db "select setValue from Settings where setKey='API_TOKEN'" | tr -d "'\"\r\n"; }
wait_for 180 "NetAlertX-API" bash -c "[[ -n \"\$(docker exec aluco-netalertx sqlite3 /data/db/app.db \"select setValue from Settings where setKey='API_TOKEN'\" 2>/dev/null)\" ]]"
TOKEN=$(nax_token)
echo "NETALERTX_API_TOKEN=$TOKEN" >> .env
wait_for 60 "NetAlertX antwortet" curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:20212/devices
GATEWAY=$(docker network inspect aluco_default -f '{{(index .IPAM.Config 0).Gateway}}')
add_device() {
  curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    "http://127.0.0.1:20212/device/$1" \
    --data "{\"createNew\": true, \"devName\": \"$2\", \"devLastIP\": \"$3\", \"devVendor\": \"Test\"}" >/dev/null
}
add_device 00:00:5e:00:53:01 "Testgeraet" 192.0.2.11
add_device 00:00:5e:00:53:04 "Host" "$GATEWAY"
ok "Testgeräte angelegt"

echo "2) Aluco-Läufe"
run_once() { dc run --rm -T aluco once 2>&1 || true; }
out=$(run_once)
[[ "$out" == *"Lernmodus"* ]] || fail "erster Lauf war kein Lernlauf: $out"
ok "erster Lauf lernt"
add_device 02:00:5e:00:53:99 "(unknown)" 192.0.2.99
out=$(run_once)
[[ "$out" == *"(1 neu)"* ]] || fail "neues Gerät nicht erkannt: $out"
ok "neues Gerät erkannt"

dc up -d aluco aluco-web caddy
wait_for 60 "Dashboard" curl -fsS http://127.0.0.1:8088/healthz

sql() { dc exec -T aluco python -c "import sqlite3,sys; print(sqlite3.connect('/data/aluco.db').execute(sys.argv[1]).fetchone()[0])" "$1"; }
[[ $(sql "select count(*) from devices") -ge 3 ]] || fail "zu wenige Geräte"
[[ $(sql "select count(*) from incidents where rule='new_device'") -ge 1 ]] || fail "kein Vorfall"
[[ $(sql "select coalesce(sum(total),0) from dns_hourly") -ge 1 ]] || fail "keine DNS-Statistik"
[[ $(sql "pragma user_version") -ge 4 ]] || fail "Schema zu alt"
ok "Datenbank: Geräte, Vorfall, DNS-Statistik, Schema"

echo "3) Dashboard"
JAR="$WORK/cookies"
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -H 'Origin: http://127.0.0.1:8088' \
  --data-urlencode "password=$WEB_PW" http://127.0.0.1:8088/login)
[[ "$code" == 303 ]] || fail "Login: HTTP $code"
for path in / /incidents /devices "/devices/00:00:5e:00:53:01"; do
  code=$(curl -s -o "$WORK/page" -w '%{http_code}' -b "$JAR" "http://127.0.0.1:8088$path")
  [[ "$code" == 200 ]] || fail "$path: HTTP $code"
  if grep -q 'style=' "$WORK/page"; then fail "$path: Inline-Style gefunden"; fi
done
page=$(curl -s -b "$JAR" http://127.0.0.1:8088/incidents)
[[ "$page" == *"Neues Gerät im Netz"* ]] || fail "Vorfall nicht im Dashboard"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' http://127.0.0.1:8088/login)
[[ "$code" == 400 ]] || fail "fremder Host nicht abgewiesen ($code)"
ok "Login, Seiten, Vorfall sichtbar, CSP ohne Inline-Styles, Host-Prüfung"

echo "4) Laptop-Agent-API"
AGENT_TOKEN=$(dc exec -T aluco python -m aluco agent add 00:00:5e:00:53:01 | tail -1)
report='{"system":[{"hostname":"ci"}],"os":[{"name":"macOS","version":"26"}],"listening_ports":[],"autostart":[],"logged_in_users":[],"firewall":[{"global_state":"0"}],"filevault":[{"encrypted":"1"}],"gatekeeper":[{"assessments_enabled":"1"}],"sip":[{"enabled":"1"}]}'
resp=$(curl -fsS -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' \
  --data "$report" http://127.0.0.1:8088/api/agent/report)
[[ "$resp" == *'"ok":true'* ]] || fail "Agent-Bericht: $resp"
[[ $(sql "select count(*) from incidents where rule='agent_posture'") -eq 1 ]] || fail "Firewall-Vorfall fehlt"
ok "Bericht angenommen, Firewall-aus als Vorfall"

echo "5) MCP über stdio"
dc exec -T aluco python - <<'PY' || fail "MCP"
import anyio
from mcp import Client, StdioServerParameters
async def main():
    # Das SDK startet den Server mit minimaler Umgebung → Datenbankpfad explizit mitgeben.
    params = StdioServerParameters(
        command="python", args=["-m", "aluco", "mcp"], env={"ALUCO_DB_PATH": "/data/aluco.db"}
    )
    async with Client(params) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"get_overview", "device_activity"} <= names, names
        o = (await c.call_tool("get_overview", {})).structured_content
        assert o["geraete"]["gesamt"] >= 3, o
anyio.run(main)
PY
ok "Werkzeuge gelistet, Lagebild abgefragt"

echo "6) HTTPS über Caddy"
wait_for 60 "Caddy" bash -c "docker exec aluco-caddy test -f /data/caddy/pki/authorities/local/root.crt"
docker cp aluco-caddy:/data/caddy/pki/authorities/local/root.crt "$WORK/root.crt" >/dev/null
code=$(curl -s -o /dev/null -w '%{http_code}' https://localhost:8443/login || true)
[[ "$code" == 000 ]] || fail "HTTPS ohne CA hätte abgelehnt werden müssen ($code)"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/root.crt" https://localhost:8443/login)
[[ "$code" == 200 ]] || fail "HTTPS mit CA: $code"
ok "ohne CA abgelehnt, mit CA erreichbar"

echo "Alle Integrationstests bestanden."
