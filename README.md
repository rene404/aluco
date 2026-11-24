# Aluco

**English** · [Deutsch](README.de.md)

> **Aluco – a home radar for your network.**
> Named after the tawny owl (*Strix aluco*), which keeps watch at night and notices every movement.

Monitoring for home networks and laptops: device inventory, detection of unusual activity, an incident log and one-click device disconnect, with AI pre-assessment and MCP access.

Aluco does not replace proven tools, it builds on them: OPNsense, AdGuard Home, NetAlertX and Suricata provide the data, Aluco brings it together and turns it into a workflow of *incident → assess → act*.

**Status:** v0.3.0 – software for stages 0 and 1 complete (dashboard, AI pre-assessment with Claude or local Ollama, MCP, laptop agent, disconnect via OPNsense, newly registered domains, rule quality, weekly report); deployment on the Raspberry Pi is pending. Changes: [CHANGELOG.md](CHANGELOG.md).

> Aluco is available in English: set `ALUCO_LANGUAGE=en` for the dashboard, ntfy alerts, the weekly report and the MCP server. The AI assessment and the documentation in `docs/` are still German for now.

## Documents

| File | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Target picture, principles, stages 0–4 |
| [docs/stage-0.md](docs/stage-0.md) | Stage 0: set up AdGuard Home + NetAlertX, rollback, acceptance |
| [docs/opnsense.md](docs/opnsense.md) | Stage 1: disconnect devices via OPNsense, ARP table |
| [docs/operations.md](docs/operations.md) | Operations: backup, restore, update, disk space |
| [docs/https.md](docs/https.md) | HTTPS for the dashboard with Caddy and a local certificate authority |
| [docs/laptop-agent.md](docs/laptop-agent.md) | Laptop agent (osquery): ports, autostart, security basics |
| [docs/mcp.md](docs/mcp.md) | MCP server: ask Claude Desktop/Code about your network |
| [docs/ai.md](docs/ai.md) | AI pre-assessment: what is sent, setup, cost, local models with Ollama |
| [docs/dashboard-concept.md](docs/dashboard-concept.md) | Pages, detection rules, ways to disconnect, handling laptops and company devices |
| [docs/roadmap.md](docs/roadmap.md) | Beyond stage 4: benefit/effort, priorities, risks |
| [docs/naming.md](docs/naming.md) | Origin of the name |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branches (Gitflow), development setup, checks |
| [SECURITY.md](SECURITY.md) | Reporting security vulnerabilities |

## License

[MIT](LICENSE)
