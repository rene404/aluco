# Aluco – Architecture

As of: 2026-11-18 · Status: concept

## Target picture

```
Internet
   │
ISP router          (bridge mode, if possible)
   │
Firewall: OPNsense  firewall, DHCP, Suricata, traffic per device, WireGuard, blocking via API
   │
Wi-Fi / mesh        access point only
   │
Devices  +  server (e.g. Raspberry Pi): AdGuard Home, NetAlertX, Aluco dashboard, MCP server
```

**Limit:** Traffic between devices on the home network bypasses the firewall. A quarantine cuts a device off from the internet, not from the rest of the home network. Real isolation needs VLAN-capable access points (see [roadmap.md](roadmap.md)).

## Principles

- **Adapter architecture:** Data sources (AdGuard Home, NetAlertX, OPNsense, Suricata, endpoint agent) and actions (blocking) sit behind interfaces. Other systems such as UniFi, OpenWrt or MikroTik can be plugged in.
- **Don't rebuild detection:** Proven tools provide the data; Aluco provides the aggregation, the incident workflow, actions and AI pre-assessment.
- **Disconnect only manually, with confirmation.** The only automatic action: unknown new device → quarantine.
- **Protected list:** Infrastructure (firewall, Aluco server) and marked devices can never be blocked.
- **Company devices passive only:** online/offline and data volume. No agents, no automatic rules, no data to the AI.
- **Privacy:** Logs kept for 30 days by default; data sent to the AI is minimized/anonymized, or a local model is used.
- **Dashboard security:** Access only from the home network or via VPN, with login; the firewall API key is only authorized for the block list.
- No secrets in the repo (`.env`). Deployment with Docker Compose.

## Stages

| Stage | Contents | Network changes? |
|---|---|---|
| 0 | AdGuard Home + NetAlertX on the server, the router hands it out as DNS | no |
| 1 | OPNsense as firewall, mesh → access point, Suricata, traffic data, blocking via API | yes |
| 2 | Agent on private laptops, WireGuard on the road | no |
| 3 | Aluco dashboard + incident workflow + MCP layer | no |
| 4 | Learn normal behavior per device, report deviations | no |

### Stage 0 – Procedure

1. Server: 64-bit Linux, SSH key, Docker + Compose, fixed IP via DHCP reservation.
2. AdGuard Home as a container, encrypted upstream DNS (DoH/DoT).
3. Router: primary DNS = server. **No public secondary DNS** (otherwise it can be bypassed). Server off = no DNS → document and test the way back.
4. NetAlertX as a container (host network for ARP scan), alert on new devices.
5. One week of baseline: name all devices, mark company devices, note false alarms.

**Acceptance:** every device in the inventory is named · DNS log visible per device · alert on new device works · way back tested.
