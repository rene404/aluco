#!/usr/bin/env bash
# Ersteinrichtung von AdGuard Home über die API (statt Klick-Assistent).
# Setzt: Login, verschlüsseltes Upstream-DNS (DoH), Protokoll + Statistik mit Aufbewahrung.
#
# Aufruf auf dem Server:   scripts/adguard-setup.sh
# Aufruf lokal (Mac):      AGH_SETUP_URL=http://127.0.0.1:3300 AGH_URL=http://127.0.0.1:8300 scripts/adguard-setup.sh
#
# Passwort: aus ALUCO_ADGUARD_PASSWORD oder interaktive Abfrage (wird nirgends gespeichert).
set -euo pipefail

AGH_SETUP_URL="${AGH_SETUP_URL:-http://127.0.0.1:3000}" # Assistent vor der Einrichtung
AGH_URL="${AGH_URL:-http://127.0.0.1:80}"               # Oberfläche danach
AGH_USER="${ALUCO_ADGUARD_USER:-admin}"
AGH_WEB_PORT="${AGH_WEB_PORT:-80}"
RETENTION_DAYS="${ALUCO_RETENTION_DAYS:-30}"
# Verschlüsselter Upstream (DoH). Quad9: gemeinnützig, Sitz Schweiz, filtert bekannte Schadsoftware.
UPSTREAMS="${AGH_UPSTREAMS:-https://dns.quad9.net/dns-query}"
BOOTSTRAP="${AGH_BOOTSTRAP:-9.9.9.9 149.112.112.112}"

die() { echo "adguard-setup: $*" >&2; exit 1; }
command -v curl >/dev/null || die "curl fehlt"
command -v python3 >/dev/null || die "python3 fehlt"

if [[ -z "${ALUCO_ADGUARD_PASSWORD:-}" ]]; then
  read -rsp "Neues AdGuard-Passwort für '$AGH_USER': " ALUCO_ADGUARD_PASSWORD; echo
  read -rsp "Wiederholen: " pw2; echo
  [[ "$ALUCO_ADGUARD_PASSWORD" == "$pw2" ]] || die "Passwörter stimmen nicht überein"
fi
[[ ${#ALUCO_ADGUARD_PASSWORD} -ge 12 ]] || die "Passwort zu kurz (mindestens 12 Zeichen)"
export AGH_USER ALUCO_ADGUARD_PASSWORD AGH_WEB_PORT UPSTREAMS BOOTSTRAP RETENTION_DAYS

# JSON-Körper aus Umgebungsvariablen bauen (kein eval, sauberes Escaping).
body() { # body install|dns|querylog|stats
  python3 - "$1" <<'PY'
import json, os, sys
e = os.environ
ms = int(e["RETENTION_DAYS"]) * 24 * 3600 * 1000
bodies = {
    "install": {"web": {"ip": "0.0.0.0", "port": int(e["AGH_WEB_PORT"])},
                "dns": {"ip": "0.0.0.0", "port": 53},
                "username": e["AGH_USER"], "password": e["ALUCO_ADGUARD_PASSWORD"]},
    "dns": {"upstream_dns": e["UPSTREAMS"].split(), "bootstrap_dns": e["BOOTSTRAP"].split(),
            "upstream_mode": "load_balance"},
    "querylog": {"enabled": True, "interval": ms, "anonymize_client_ip": False, "ignored": []},
    "stats": {"enabled": True, "interval": ms, "ignored": []},
}
print(json.dumps(bodies[sys.argv[1]]))
PY
}

# Anfragen mit Login: Zugangsdaten per stdin-Konfiguration, damit sie nicht in der Prozessliste stehen.
api() { # api METHOD PFAD [JSON]
  local method=$1 path=$2 data=${3:-} cred
  cred="$AGH_USER:$ALUCO_ADGUARD_PASSWORD"
  cred="${cred//\\/\\\\}"; cred="${cred//\"/\\\"}" # für curl-Konfiguration escapen
  curl -fsS -K - -X "$method" -H 'Content-Type: application/json' \
    ${data:+--data "$data"} "$AGH_URL$path" <<<"user = \"$cred\""
}

# 1) Assistent: nur beim allerersten Start erreichbar.
if curl -fsS -o /dev/null "$AGH_SETUP_URL/control/install/get_addresses" 2>/dev/null; then
  echo "Ersteinrichtung: Login anlegen, Oberfläche auf Port $AGH_WEB_PORT, DNS auf Port 53 …"
  body install | curl -fsS -X POST -H 'Content-Type: application/json' --data @- \
        "$AGH_SETUP_URL/control/install/configure" >/dev/null
  for _ in $(seq 1 20); do
    curl -fsS -o /dev/null "$AGH_URL/login.html" 2>/dev/null && break
    sleep 1
  done
else
  echo "Assistent nicht erreichbar – AdGuard ist schon eingerichtet, setze nur die Einstellungen."
fi

# 2) Verschlüsseltes Upstream-DNS.
echo "Upstream-DNS: $UPSTREAMS"
api POST /control/dns_config "$(body dns)" >/dev/null

# 3) Protokoll und Statistik: Aufbewahrung in Tagen.
echo "Aufbewahrung Protokoll/Statistik: $RETENTION_DAYS Tage"
api PUT /control/querylog/config/update "$(body querylog)" >/dev/null
api PUT /control/stats/config/update "$(body stats)" >/dev/null

# 4) Kontrolle.
api GET /control/status | python3 -c "import json,sys; s=json.load(sys.stdin); \
print(f\"AdGuard {s['version']}: läuft={s['running']}, DNS-Port={s['dns_port']}, Schutz={s['protection_enabled']}\")"
echo "Fertig. Oberfläche: $AGH_URL"
