# MCP server

As of: 2026-11-19

With the MCP server you can ask Claude (Desktop, Code) or another MCP host directly about your network – e.g. *"What did the TV do last night?"*, *"Are there open incidents?"*, *"Which devices were offline today?"*.

## Properties

- **Read-only:** The database is opened read-only; incidents can still only be handled in the dashboard.
- **No open port:** The transport is stdio. The host starts the server via SSH on the Pi – so access requires your SSH key.
- **Company devices:** master data and online status only; Aluco stores no domains or DNS statistics for them.
- **Language:** `ALUCO_LANGUAGE=en` switches the response language and values (severity, status, trust level, explanations) to English. The tools' field names stay German – they are the interface.
- **Privacy:** Whatever a tool returns is seen by the model. With a cloud model (Claude), these responses go to its provider. Unlike the AI pre-assessment, they contain device names, IPs and domains – after all, that is what you are asking about.

## Tools

| Tool | Contents |
|---|---|
| `get_overview` | Situation: open incidents, devices online/offline, DNS of the last 24 h, data sources |
| `list_incidents` | Incidents by status (open, ignored, resolved, all) |
| `get_incident` | One incident with "Why it stands out", note and AI assessment |
| `list_devices` | Inventory, optionally with search and trust level |
| `get_device` | Device with activity (7 days), most-used domains, incidents, history |
| `device_activity` | Time range (e.g. last night): queries per hour, domains of the days, events |
| `timeline` | Timeline of the last hours |
| `dns_top` | Most active devices, most blocked domains |
| `rule_quality` | Rule quality: triggered, ignored, resolved, disconnected, ignore rate per rule (30–400 days) |

Precision: DNS data is stored as counts per hour and per main domain per day – not as individual queries with timestamps.

## Setup

Prerequisite: SSH with a key from the Mac to the server (`ssh aluco-pi` works without a password prompt) and the Aluco service is running.

**Claude Code:**

```sh
claude mcp add aluco -- ssh aluco-pi docker exec -i aluco python -m aluco mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aluco": {
      "command": "ssh",
      "args": ["aluco-pi", "docker", "exec", "-i", "aluco", "python", "-m", "aluco", "mcp"]
    }
  }
}
```

`aluco-pi` is an entry in `~/.ssh/config` (host, user, key). Locally on the server itself, `docker exec -i aluco python -m aluco mcp` is enough.

## Trying it without a host

```sh
npx @modelcontextprotocol/inspector docker exec -i aluco python -m aluco mcp
```
