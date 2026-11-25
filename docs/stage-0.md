# Stage 0 – DNS log and device inventory

As of: 2026-11-19 · Goal: see which devices are on the network and which domains they query – without rebuilding the network.

| Service | Task | Interface |
|---|---|---|
| AdGuard Home | DNS for the home network, log per device, filters | `http://<server>/` |
| NetAlertX | Device inventory via ARP scan, alert on new devices | `http://<server>:20211/` |
| Aluco | Brings both together: inventory, domains per device, incidents, alerts via ntfy | – |
| Aluco dashboard | Overview, handling incidents, classifying devices | `http://<server>:8088/` |

All run with Docker Compose (`compose.yaml`) in the server's host network.

## Prerequisites

- Server with 64-bit Linux (e.g. Raspberry Pi OS Lite 64-bit), wired to the home network.
- **Fixed IP** for the server via DHCP reservation in the router.
- SSH access with a key, password login disabled.
- Docker Engine + Compose plugin (`curl -fsSL https://get.docker.com | sh` – read the script first).
- Port 53 free: on Ubuntu, `systemd-resolved` occupies it (set `DNSStubListener=no`). Raspberry Pi OS is not affected.

## Setup

```sh
git clone https://github.com/rene404/aluco.git && cd aluco
cp .env.example .env              # adjust TZ, memory limits
chmod 600 .env                    # will contain passwords later
mkdir -p data/aluco && sudo chown 10001:10001 data/aluco   # Aluco runs as user 10001
docker compose pull adguardhome netalertx
docker compose up -d adguardhome netalertx
scripts/adguard-setup.sh          # login, encrypted upstream DNS, 30-day log
```

`adguard-setup.sh` asks for the password (at least 12 characters, not stored anywhere) and can safely be run again.

**Check on the server:**

```sh
docker compose ps                                  # both "running"
dig +short @127.0.0.1 example.com                  # returns an IP
```

### NetAlertX

1. Open `http://<server>:20211/` → **Settings**.
2. Set `SCAN_SUBNETS` to your own network, e.g. `192.0.2.0/24 --interface=eth0` (check network and interface with `ip -4 addr`).
3. Turn on notifications for new devices (e.g. ntfy or email).
4. Protect the interface with a password (`SETPWD_enable_password`).
5. **API token for Aluco:** Settings → copy `API_TOKEN` and enter it in `.env` as `NETALERTX_API_TOKEN`. The token also allows writing and deleting – Aluco only uses it for reading, but treat it like a password anyway.

### Aluco service

1. In `.env`, set: `ADGUARD_PASSWORD` (from `adguard-setup.sh`), `NETALERTX_API_TOKEN` (see above).
2. Optional alerts: `NTFY_URL` (complete topic URL). With a public ntfy server, choose a long, random topic name and set `ALUCO_NOTIFY_MINIMAL=true` – then no device or domain names leave the home network.
   - **Weekly report:** With ntfy, a quiet notification arrives every Sunday at 6 pm (time zone `TZ`) – "Quiet week – all normal" or what happened: new devices, incidents per severity, decisions, open items, disconnected devices, DNS queries and block rate, laptops, data sources that were down for at least 30 minutes at a time (short interruptions, e.g. while the computer sleeps, do not count). Numbers only, no names. Configurable with `ALUCO_REPORT_WEEKDAY` (`mon` … `sun` or `mo` … `so`) and `ALUCO_REPORT_HOUR`, turned off with `ALUCO_REPORT=off`. The first report comes at the first due time after start; if Aluco was off at the due time, it is sent on the next run. The overview in the dashboard shows the same numbers ("Weekly report" card, last 7 days).
3. Set the dashboard password: `ALUCO_DASHBOARD_PASSWORD` (at least 12 characters). Language of the dashboard, ntfy alerts, weekly report, MCP server and AI pre-assessment: `ALUCO_LANGUAGE=de` (default) or `en`. Titles of incidents and events that are already stored stay in the language they were created in.
4. Start: `docker compose up -d --build aluco aluco-web`, check: `docker logs -f aluco`.
5. Dashboard: `http://<server>:8088/` – only in the home network or via VPN, never exposed to the internet via port forwarding. Open it via the IP address; to use a name (e.g. `aluco.lan`), add it to `ALUCO_WEB_ALLOWED_HOSTS`.
6. **HTTPS recommended:** Without TLS, the password and session travel unencrypted over Wi-Fi. Caddy with a local certificate authority is prepared: [docs/https.md](https.md). Aluco warns at startup as long as HTTPS is missing.
7. Protect the NetAlertX and AdGuard interfaces with a password as well (see above) – they show the complete inventory and all DNS queries respectively.

The **first run only learns** (takes over all existing devices without alarm). From the second run on, Aluco reports unknown devices; queries to new domains are only reported for IoT devices and only after a 7-day learning phase.

### Classifying devices

**Right after the first run**, mark company devices – Aluco then deletes everything it has already stored about their DNS behavior. Easiest in the dashboard under **Devices**; alternatively on the command line:

```sh
docker compose run --rm aluco device list                         # inventory with MAC addresses
docker compose run --rm aluco device set-trust <MAC> company      # company device: passive only, never disconnectable
docker compose run --rm aluco device set-trust <MAC> iot          # IoT: alert on new domains
docker compose run --rm aluco device protect <MAC>                # protected list (server, firewall …)
docker compose run --rm aluco device name <MAC> "TV"              # assign names
```

Trust levels: `known`, `iot`, `guest`, `unknown`, `company`. Put the Aluco server itself and the firewall on the protected list.

### Known malicious domains

Aluco checks every DNS query against public threat lists (malware, phishing, command-and-control). A match is an incident with severity **high** – even if AdGuard has already blocked the query, because the attempt itself points to malware or a phishing link. Company devices are excluded.

- Default list: [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (mini, ~210,000 domains, no key, GPL-3.0). Loaded every 12 hours and cached in the data folder; if the download fails, the last list stays in effect.
- More lists (e.g. abuse.ch URLhaus/ThreatFox with a free auth key) via `ALUCO_THREAT_FEEDS`, formats: domains, hosts file, Adblock.
- Tip: add the same list in AdGuard under *Filters → DNS blocklists* as well, then it is also blocked.
- Memory use about 20–40 MB.

### Newly registered domains

Aluco reports queries to domains that were registered only within the last 14 days. Scammers like to use such domains for phishing, malware and command-and-control because they are cheap and quickly gone again. Many new domains are harmless, though (new websites, campaigns, services) – hence only severity **medium**. Company devices are excluded.

- One incident per device and registered domain (`login.new.example` and `new.example` count together); repetitions increase the count.
- If the domain is also on a threat list, Aluco reports only the malicious domain (high).
- Default list: [HaGeZi NRD](https://github.com/hagezi/nrd), last 14 days (`nrd7` + `nrd14-8`, ~5 million domains). Loaded once a day (**~90 MB download per day**, ~2.6 GB per month) and cached in the data folder (~90 MB); if the download fails, the last list stays in effect.
- Memory: hardly any (below 30 MB). Aluco uses binary search directly in the sorted file instead of loading 5 million domains into memory (that would be ~500 MB).
- `ALUCO_NRD_ALLOW`: your own or known new domains that never count as newly registered (including subdomains), e.g. `myclub-2026.example, new-shop.example`.
- `ALUCO_NRD_FEEDS=off` turns the rule off, e.g. with a limited data plan. Your own lists: `name=https-URL` (plain domains).

## Switching DNS in the router

Only once AdGuard answers on the server.

- **Router hands out DHCP:** set the primary DNS to the server's IP. **Do not enter a public secondary DNS** – devices would use it and bypass the log.
- **Router/mesh in access point mode:** no DNS can be set there. Then configure it on the device that does DHCP (usually the ISP router), or hand DHCP over to AdGuard Home (only one DHCP server on the network!).

Devices only pick up the new DNS with the next DHCP renewal (turning Wi-Fi off and on speeds this up).

## Way back (test it beforehand!)

If the server fails, name resolution no longer works on the network.

1. In the router, set the DNS entry back to **automatic/ISP**.
2. Reconnect the devices (Wi-Fi off/on).

Go through this procedure once deliberately and note the steps for your router (privately, not in the repo).

## Acceptance

- [ ] Every device named (NetAlertX or `aluco device name`), company devices marked as `company`, server on the protected list.
- [ ] AdGuard shows queries per device (not just the router's IP).
- [ ] The alert for a new device arrives (test: connect a phone in guest mode/with a random MAC).
- [ ] Way back tested.
- [ ] One week of baseline: false alarms noted.

## Operations

- **Updates:** `scripts/update.sh` (backs up first, checks afterwards) – see [operations.md](operations.md).
- **Backup:** `scripts/backup.sh`, ideally daily via cron – see [operations.md](operations.md).
- **Logs:** deleted after `ALUCO_RETENTION_DAYS` (default 30). Let the household know that DNS queries are logged.

## Testing locally (Mac)

```sh
docker compose -f compose.yaml -f compose.local.yaml up -d
AGH_SETUP_URL=http://127.0.0.1:3300 AGH_URL=http://127.0.0.1:8300 scripts/adguard-setup.sh
dig @127.0.0.1 -p 5300 example.com
docker compose -f compose.yaml -f compose.local.yaml down -v   # clean up
```

NetAlertX does not run locally (the ARP scan needs a Linux host network).

## Security notes

- Both containers: read-only file system, privileges limited to what is needed, memory and process limits.
- AdGuard runs as root (default on first start), but without privileges beyond binding ports and writing data, and without privilege escalation.
- Make the interfaces reachable only from the home network, never via port forwarding to the internet.
- NetAlertX contains PHP; update the image promptly when there are PHP security advisories.
