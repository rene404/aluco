# Laptop agent (osquery)

As of: 2026-11-19 · for **private** Macs only – never install on company devices

Every 10 minutes, the agent runs fixed, **read-only** [osquery](https://osquery.io) queries and sends the result to Aluco. Aluco remembers what it knows and reports anything new as an incident.

| What | Incident when … | Severity |
|---|---|---|
| Open ports (external, not just localhost) | a program newly accepts connections | medium |
| Autostart (LaunchAgents/-Daemons outside `/System`) | a new entry appears | medium |
| Logins | a new **remote** login (e.g. SSH) appears | medium |
| Firewall, FileVault, Gatekeeper, SIP | a basic security setting is off – resolved automatically as soon as it is back on | medium/high |

The **first report only learns** (everything present counts as known). In the dashboard, the device detail shows a **Laptop** section.

## Setup

1. Install osquery: `brew install --cask osquery`
2. Create an agent on the Aluco server – the token is shown **only once**:
   ```sh
   docker compose exec aluco python -m aluco agent add "<device name or MAC>"
   ```
3. On the Mac (from the repo):
   ```sh
   sudo agent/install.sh http://<server>:8088 <TOKEN>
   ```
   This installs `/usr/local/libexec/aluco-agent` (root, read/execute only), the configuration `/usr/local/etc/aluco-agent.conf` (readable by root only) and the launchd job `dev.aluco.agent`. Log: `/var/log/aluco-agent.log`.

Removal: `sudo agent/uninstall.sh` and `aluco agent remove <device>`.

## Security and privacy

- Fixed queries in the script, no remote control: Aluco cannot command the agent.
- Token per device (stored in Aluco only as a hash), passed to curl via stdin – never in the process list.
- Report max. 1 MB, at most every 30 s, values sanitized and truncated.
- User names in paths are shortened to `~`; only the program, shortened path and port go to the AI pre-assessment.
- If you mark the device as **company**, Aluco deletes the agent and all entries and no longer accepts reports.
- Without HTTPS, the token travels unencrypted across the home network – as with the dashboard, a TLS reverse proxy is recommended.
