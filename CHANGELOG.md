# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- **Dashboard design V2, part 1:** dark theme only with new surfaces, smaller radii and no shadows; all color pairs meet WCAG AA (checked by a test). The accent stays blue and is configurable with `ALUCO_UI_ACCENT` ([docs/dashboard-concept.md](docs/dashboard-concept.md)).
- **Dashboard design V2, part 2:** fonts Geist and Geist Mono, served locally (SIL Open Font License, ~140 KB); labels, times and technical values (IP, MAC, domains, ports) in monospace.
- **Dashboard design V2, part 3:** navigation, buttons, filters and labels as uppercase monospace; numbered sections ("// 01"); incidents as rows in one frame with a severity bar; square tags; long hostnames wrap.
- **Laptop agent – fewer false alarms for open ports (#57):** new ports are only learned for 24 h after the first report (`ALUCO_AGENT_LEARN_HOURS`); random ports of macOS system programs (`/System/`, `/usr/libexec/`, `/usr/sbin/`, `/usr/bin/`) are not reported while SIP is on; allow list `ALUCO_AGENT_PORT_ALLOW` for programs or single entries ([docs/laptop-agent.md](docs/laptop-agent.md)). Autostart entries and remote logins are reported as before.

## [0.4.3] – 2026-11-27

Bug fix for the rule quality and dependency updates, including **AdGuard Home v1.0.0**. No change to the database schema.

### Fixed
- **Rule quality:** a decision that was taken back by hand (e.g. "ignored", then reopened and resolved) no longer counts as ignored. Per incident only the last decision counts until the finding occurs again; the time to decision runs until the first one. Previously a rule could be marked "desensitized?" by mistake.

### Changed
- **AdGuard Home v1.0.0** (from v0.107.80). AdGuard migrates its configuration automatically on first start (format 34 → 35); Aluco does not use any of the API fields removed in v1.0. `scripts/update.sh` backs up `data/` (including the AdGuard configuration) first; to go back, restore that backup with `scripts/restore.sh` rather than only switching the image back.
- Python dependencies (`anthropic` 2.11.0, `python-multipart` 0.0.34, `ruff` 0.17.6) and `setup-uv` in CI updated.

## [0.4.2] – 2026-11-25

Documentation release – no changes to the software or the database.

### Changed
- **Documentation in English:** all documents in `docs/`, `CHANGELOG.md`, `CONTRIBUTING.md` and `SECURITY.md` are now English. `README.de.md` remains as a German overview.

## [0.4.1] – 2026-11-24

Claude for the AI pre-assessment now also **via OpenRouter** – and measured for the first time: 100 % on the sample set, in German and in English.

### Added
- **AI via OpenRouter:** `ALUCO_AI_PROVIDER=openrouter` with `OPENROUTER_API_KEY` and e.g. `ALUCO_AI_MODEL=anthropic/claude-opus-5.5` (cheaper: `anthropic/claude-sonnet-5.5`, `anthropic/claude-haiku-5.5`). Same prompt, strict response schema, guard; OpenRouter only routes to providers that do not store requests or use them for training (`data_collection: deny`). Claude models get no `temperature` (Claude 5 rejects it). Also for `aluco ai-eval --provider openrouter` ([docs/ai.md](docs/ai.md#via-openrouter)).
- **Claude measured (#24):** Claude Opus 5.5 via OpenRouter scores 64/64 on the sample set – in German and in English, without the guard having to step in. Recommendation: Ollama if the data should not leave the home network; Claude for the best assessment ([docs/ai.md](docs/ai.md)).

### Note
- If you set `ALUCO_AI_PROVIDER=openrouter`, you need at least this version – older ones abort with a configuration error.

## [0.4.0] – 2026-11-24

**Aluco in English**, and an AI pre-assessment that sees connections per device and cannot be talked down by injected text. Still not tested in continuous operation on real hardware.

### Added
- **English version (#29):** `ALUCO_LANGUAGE=en` switches the dashboard, weekly report, ntfy alerts, titles of new incidents and events, MCP server and AI pre-assessment to English; German remains the default. Translation via `aluco.i18n` (German text as key, catalog in `aluco/locale_en.py`); tests report missing translations and hardcoded text in templates. Numbers and dates in the respective format. Titles already stored stay in their original language.
- **AI pre-assessment in English:** a separate English prompt with explained answer values; the German prompt stays unchanged character for character. `aluco ai-eval --language en`. qwen3:4b: English 91 %, German 88 % ([docs/ai.md](docs/ai.md)).
- **Guard against injected instructions:** If the incident data contains text that looks like an instruction to the AI (e.g. a domain name `ignore-previous-instructions…`), the assessment never falls below "beobachten / pruefen" (keep an eye on it / check) – regardless of language and model. Reason: the English prompt could be turned to "harmlos" (harmless) this way.
- **AI sees connections per device (#26):** The pre-assessment sees up to 5 other open incidents of the same device (±7 days) – only rule, offset, status, AI verdict, no identifiers. A new device that queries a malicious domain shortly afterwards now counts as "suspicious" instead of "keep an eye on it". Resolved and ignored incidents are deliberately left out (measured). Sample set: 32 cases.

### Changed
- Weekly report: a data source only counts as disrupted if it was down for at least 30 minutes at a time. Short interruptions no longer make a week look restless.
- Events carry language-neutral attributes (`tag`, `subject`); the weekly report and the timeline no longer evaluate the wording of titles. Database schema v7 – migrated automatically at startup, existing events are classified. Run `scripts/backup.sh` before updating.
- "Inventar übernommen: 1 Gerät" instead of "1 Geräte"; block rate in the dashboard with a decimal comma.

### Known limitations
- The documentation in `docs/` is still German.
- AI pre-assessment only measured with qwen3:4b; measurement with Claude pending (#24). In English, qwen3:4b does not recognize the combination "new device, malicious domain shortly afterwards".
- That the block rule stops real traffic has not yet been tested with a real device behind OPNsense; continuous operation on the Raspberry Pi not yet tested.

## [0.3.0] – 2026-11-24

More detection, less desensitization: a new rule for **newly registered domains**, an overview of **rule quality**, a **weekly report** and a sample set to measure the AI pre-assessment. Still not tested in continuous operation on real hardware.

### Added
- **Rule "newly registered domain" (#25):** queries to domains younger than 14 days (HaGeZi NRD, ~5 million domains), severity medium. Binary search directly in the file instead of in memory (below 30 MB), allowlist `ALUCO_NRD_ALLOW`, can be turned off with `ALUCO_NRD_FEEDS=off`. ~90 MB download per day ([docs/stage-0.md](docs/stage-0.md#newly-registered-domains)).
- **Sample set for the AI pre-assessment (#30):** `aluco ai-eval` measures a model's assessment quality ([docs/ai.md](docs/ai.md)).
- **Rule quality (#28):** new "Rules" page in the dashboard and MCP tool `rule_quality` – per rule triggered, ignored, resolved, disconnected, ignore rate and time to decision; rules with more than 70 % ignored incidents are highlighted. Database schema v6 (history without device identifiers, 400 days).
- **Weekly report (#27):** every Sunday at 6 pm via ntfy "Quiet week – all normal" or what happened – numbers only, no names. Day and time configurable (`ALUCO_REPORT_WEEKDAY`, `ALUCO_REPORT_HOUR`), can be turned off (`ALUCO_REPORT=off`). In the dashboard as a card on the overview.

### Changed
- **AI prompt v2 (#31):** explains what "sperren" (block) does, forbids outside knowledge and hardens against injected instructions; qwen3:4b from 75 % to 88 % hits ([docs/ai.md](docs/ai.md)).
- Database schema v6 (table `incident_history`) – migrated automatically at startup; existing incidents count as "triggered", earlier decisions cannot be reconstructed. Run `scripts/backup.sh` before updating.
- Wide tables no longer widen the whole page on the phone.

### Known limitations
- The NRD lists cost ~90 MB download per day (~2.6 GB per month); with a limited data plan, `ALUCO_NRD_FEEDS=off`.
- AI pre-assessment so far only measured with qwen3:4b (88 %); measurement with Claude pending (#24).
- That the block rule stops real traffic has not yet been tested with a real device behind OPNsense; continuous operation on the Raspberry Pi not yet tested.

## [0.2.0] – 2026-11-23

Stage 1 in the software: disconnect devices via **OPNsense**, AI pre-assessment also **locally with Ollama**, plus HTTPS, backup/update and an integration test of the whole stack. Still not tested in continuous operation on real hardware.

### Added
- **OPNsense (stage 1, optional):** **disconnect** the device of an incident from the internet with one click and **release** it again (IP in the firewall alias `aluco_quarantine`), always with confirmation; never for the protected list and company devices. On a DHCP change, the new IP is followed. The firewall's ARP table as an additional device source. Tested against OPNsense 26.7 with minimal privileges ([docs/opnsense.md](docs/opnsense.md)).
- **Local AI with Ollama (optional):** `ALUCO_AI_PROVIDER=ollama` – incident data does not leave the home network, no API costs ([docs/ai.md](docs/ai.md)).
- **HTTPS for the dashboard:** Caddy with a local certificate authority, Compose profile `https` ([docs/https.md](docs/https.md)).
- **Operations:** `scripts/backup.sh`, `restore.sh`, `update.sh`; warning when disk space is low ([docs/operations.md](docs/operations.md)).
- **README in English**, German version in `README.de.md`.

### Changed
- AI prompt: a random (private) MAC address alone no longer counts as suspicious; a domain from a threat list remains a strong indication, even if AdGuard blocked it.
- Database schema v5 (table `blocks` for disconnected devices) – migrated automatically at startup. Run `scripts/backup.sh` before updating.

### Fixed
- When an IP is blocked again, OPNsense may store it twice in the configuration but removes only one entry when deleting; Aluco now cleans up completely when releasing, otherwise the device would be blocked again after the next firewall reload.

### Internal
- CI: integration test of the whole stack (job `integration`), required check for `main` and `develop`.

### Known limitations
- Devices are cut off from the **internet**, not from the rest of the home network (that needs VLANs).
- That the block rule stops real traffic has not yet been tested with a real device behind OPNsense.
- No data volumes per device; NetAlertX scan and continuous operation on the Raspberry Pi not yet tested.

## [0.1.0] – 2026-11-19

First version: software for **stage 0** (inventory + DNS log without rebuilding the network) including dashboard, AI pre-assessment, MCP server and laptop agent. Not yet tested in continuous operation on real hardware.

### Added
- **Stage 0 with Docker Compose:** AdGuard Home + NetAlertX, hardened containers, setup script for AdGuard (`scripts/adguard-setup.sh`).
- **Core:** data model, incident workflow (aggregate, ignore permanently, reopen), protected list, company devices passive only.
- **Rules:** new device · new domain for IoT devices after the learning phase · **known malicious domain** (HaGeZi TIF, extensible).
- **Runner:** regular runs, learning mode on the first run, alerts via **ntfy**.
- **Dashboard (design V1):** situation, key figures, DNS chart, timeline, incidents as cards, device cards with mini history, device detail; light/dark; strict CSP.
- **AI pre-assessment (optional):** Claude assesses new incidents with minimal data (never names, IPs, MACs, company devices).
- **MCP server (optional):** Claude Desktop/Code queries the network **read-only** via stdio/SSH.
- **Laptop agent (osquery, optional):** open ports, autostart, remote logins, firewall/FileVault/Gatekeeper/SIP on private Macs.
- **Command line:** `aluco run|once|web|mcp`, `aluco device …`, `aluco agent …`.

### Security
- Independent security review, all findings (3 medium, 6 low) fixed: among others, no IPs/hostnames sent to the AI via local DNS names, safe attribution on DHCP changes, protection against DNS rebinding, secrets separated per container.
- Dependencies, images, actions and hooks pinned to versions/commits; 7-day waiting period for updates.

### Known limitations
- Without a firewall (stage 1): no "disconnect", no data volumes per device.
- Dashboard without built-in HTTPS – a reverse proxy with TLS is recommended.
- NetAlertX scan and continuous operation on the Raspberry Pi not yet tested.

[0.4.3]: https://github.com/rene404/aluco/releases/tag/v0.4.3
[0.4.2]: https://github.com/rene404/aluco/releases/tag/v0.4.2
[0.4.1]: https://github.com/rene404/aluco/releases/tag/v0.4.1
[0.4.0]: https://github.com/rene404/aluco/releases/tag/v0.4.0
[0.3.0]: https://github.com/rene404/aluco/releases/tag/v0.3.0
[0.2.0]: https://github.com/rene404/aluco/releases/tag/v0.2.0
[0.1.0]: https://github.com/rene404/aluco/releases/tag/v0.1.0
