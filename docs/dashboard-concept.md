# Aluco – Dashboard concept

As of: 2026-11-18

## Pages

1. **Overview:** devices (online / new / unknown), open alarms, traffic of the last 24 h, sensor status.
2. **Devices ("Radar"):** inventory with MAC, vendor, IP, first/last seen, trust level (known / IoT / guest / unknown / company), "Disconnect" button.
3. **Device detail:** contacted domains and countries, data volume over time, typical behavior.
4. **DNS & traffic:** top domains, blocked queries, newly seen domains.
5. **Incidents:** log with status (new / investigating / ignored / disconnected) and note. **The heart of it.**
6. **Laptop:** processes with network connections, open ports, new autostart entries (LaunchAgents/-Daemons), logins. Private laptops only.
7. **Rules & actions:** definition of "unusual", blocked devices, lifting quarantine, protected list. Implemented: rule quality (see below).

## Detection rules (start, few false alarms)

- New device (unknown MAC) on the network.
- IoT device talks to other devices on the home network instead of only to the internet.
- Device contacts a country or domain it has never contacted before.
- Unusually high upload, especially at night.
- Port scans on the home network; Suricata alarms with high severity.
- Laptop: new process listens on a port; new LaunchAgent/LaunchDaemon.
- DNS queries to newly registered domains (< 14 days), severity medium – see [stage-0.md](stage-0.md#newly-registered-domains).

From the start: severities and a "known / ignore" button, otherwise you become desensitized.

### Rule quality ("Rules" page)

Whether you are becoming desensitized is shown on the **Rules** page (`/rules`): per rule, for 30 or 90 days

- **triggered:** new incidents, plus "+n" for resolved findings that occurred again;
- **ignored / resolved / disconnected:** manual decisions only. Automatically resolved incidents (security setting back on according to the agent) are shown next to them as "+n auto" and do not count. Per incident, only the last decision counts until the finding occurs again – an "ignore" that is taken back (reopened, then resolved) counts as resolved, one that is taken back and still open counts as nothing;
- **ignore rate:** ignored ÷ (ignored + resolved + disconnected). Above 70 % with at least 3 decisions, the rule is marked as "desensitized?" and collected at the top;
- **time to decision:** median from occurrence (or reoccurrence) to the first decision;
- **AI off the mark:** how often the AI said "suspicious" and the incident was ignored anyway, or "harmless" and the device was disconnected anyway.

It is based on a separate history (`incident_history`) with only rule, time, status and AI verdict – without device, domain or title. That is why it is kept for 400 days, even though resolved incidents are deleted after the retention period (30 days). When updating to schema v6, existing incidents are taken over as "triggered"; earlier decisions cannot be reconstructed. The MCP server provides the same numbers with `rule_quality`.

## Ways to disconnect

| Way | Assessment |
|---|---|
| Block at the router/firewall (OPNsense API, block list) | **Chosen** (from stage 1). Clean. |
| Block via DNS (AdGuard) | Simple, can be bypassed with fixed DNS or DNS-over-HTTPS. Interim solution in stage 0. |
| Quarantine VLAN | Cleanest separation, needs VLAN-capable access points (roadmap). |
| ARP spoofing | Fragile, not a permanent solution. |

Rule: disconnect only at the push of a button, with confirmation. The only automatic action is "unknown new device → quarantine". The protected list (infrastructure and marked devices) can never be blocked.

## Laptops

| Device | Handling |
|---|---|
| Private laptops | Small agent (osquery or own script) reports to the Aluco server; on the road via WireGuard. |
| Company devices | Install nothing (IT policies, EDR). In the dashboard "Company – observe only": online/offline, data volume. Never block automatically, no data to the AI. With a company VPN, only the tunnel is visible anyway. |

## Design V2 (in progress, as of 2026-11-27)

Dark theme only, inspired by the structure of a developer-conference style (stepped dark surfaces, lines instead of shadows, small radii, monospace labels). Colors keep their meaning: the accent stays blue, orange/red stay reserved for severity.

| Role | Value |
|---|---|
| Page / surfaces | `#13131a` / `#1b1b24`, `#20202b`, `#2c2c38` |
| Text / secondary / muted | `#f5f5f7` / `#c8c8d0` / `#9a9aa5` |
| Accent (default) | `#7ea2f7` – configurable with `ALUCO_UI_ACCENT` |
| OK | `#10b981` |
| Radius | 4 px (small 3 px), no shadows, max width 1100 px |

**Configurable accent:** `ALUCO_UI_ACCENT=#22d3ee` (hex). Aluco derives hover, tint and text-on-accent colors and serves them as `/theme.css` (the CSP forbids inline styles). A color with less than 4.5:1 contrast on the dark surface is rejected at startup. All color pairs in `aluco.css` are checked against WCAG AA by a test.

**Typography:** Geist for text, Geist Mono for labels (uppercase, letter-spacing 0.1 em), times and technical values (`.mono`: IP, MAC, hostname, domains, ports). Both are served from `static/fonts/` (variable fonts, SIL Open Font License) – no external requests.

Next step: components (navigation, section labels, rows instead of cards).

## Design V1 (as of 2026-11-19, light/dark – replaced by V2)

Implemented in `src/aluco/web/` (dashboard v2). This version is the reference for further pages.

**Pages:** Overview (situation, key figures, DNS chart 24 h/7 days, timeline, most active devices, most blocked domains) · Incidents (expandable cards with "Why it stands out", note, actions) · Devices (cards with online status, trust level, mini history, search/filter) · Device detail (activity 7 days, typical behavior, domains, settings, incidents, history).

**Colors (light / dark):**

| Role | Light | Dark |
|---|---|---|
| Accent | `#1d4ed8` | `#7ea2f7` |
| Accent dark | `#1e3a8a` | `#b3c8fb` |
| Accent background | `#dbe6fd` | `#1c2b4d` |
| Page / surface | `#f3f5f7` / `#ffffff` | `#0f1318` / `#171c22` |
| Text / secondary text | `#151a1f` / `#56606b` | `#e8edf2` / `#9aa5b1` |
| Chart allowed / blocked | `#3b6ee0` / `#d9822b` | `#6f95ef` / `#e39a4f` |

Color carries meaning only: orange/red = severity, green = online/resolved, gray = low/offline, teal = IoT, violet = AI. No emojis; the logo is the SVG owl.

**Technology:** server-side rendered (Jinja2), htmx bundled locally, charts as SVG attributes, no inline styles (strict CSP), colors as CSS variables in `static/aluco.css`.
