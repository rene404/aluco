# Aluco – Roadmap beyond stage 4

As of: 2026-11-18 · Rating: benefit ⭐–⭐⭐⭐

## A. Network infrastructure

| Extension | What it brings | Benefit | Effort |
|---|---|---|---|
| Access points with VLANs (e.g. Omada/UniFi instead of consumer mesh) | Separate networks: household, IoT, guests, quarantine; real isolation inside the home network too | ⭐⭐⭐ | medium, new hardware |
| Managed switch + port mirror + Zeek | Traffic between devices visible, protocol logs (TLS fingerprints, certificates) | ⭐⭐ | medium |
| Prevent DNS bypass | Redirect port 53 to AdGuard, block known DoH/DoT servers | ⭐⭐⭐ | low |
| Resilience | UPS, automatic OPNsense backup, emergency plan "firewall out, old router back" | ⭐⭐⭐ | low |

## B. Detection

| Extension | What it brings | Benefit | Effort |
|---|---|---|---|
| Honeypot & canary tokens (OpenCanary) | Every access is a real alarm; best signal per effort | ⭐⭐⭐ | low |
| Lists of known attackers (CrowdSec, abuse.ch, Spamhaus DROP) | Block and report known malicious IPs/domains – **domains implemented** (HaGeZi TIF, extensible) | ⭐⭐⭐ | low |
| Scan your own devices for vulnerabilities (nmap, Greenbone) | New ports, outdated firmware | ⭐⭐ | medium |
| Attack surface from outside | Scan the public IP, Shodan, UPnP forwards (turn UPnP off) | ⭐⭐ | low |
| CVE matching | Vendor/model → known vulnerabilities | ⭐⭐ | medium |
| Harden the Mac (Santa, KnockKnock, file integrity) | Only approved programs on private laptops – **partly implemented:** the laptop agent checks autostart, ports, firewall/FileVault/Gatekeeper/SIP | ⭐⭐ | medium |

## C. AI and usability

| Extension | What it brings | Benefit | Effort |
|---|---|---|---|
| AI pre-assessment of incidents | Summary, explanation, suggestion; daily report – **pre-assessment implemented** | ⭐⭐⭐ | low–medium |
| MCP server for the network | "What did the TV do last night?" – **implemented** (read-only, stdio over SSH) | ⭐⭐ | medium |
| Push notifications (ntfy, Telegram, Pushover) | Alarm on the phone, evening summary | ⭐⭐⭐ | low |
| "Disconnect" directly from the notification | Only with confirmation/login (attack surface) | ⭐⭐ | low |
| Dashboard as a PWA | App feel on the phone | ⭐ | low |

Privacy: thin out/anonymize data sent to the AI, or use a local model on your own hardware.

## D. Comfort and household

| Extension | What it brings | Benefit | Effort |
|---|---|---|---|
| Home Assistant | Presence, automations | ⭐⭐ | medium |
| Time rules per device | Kids/console times, IoT offline at night | ⭐⭐ | low |
| Privacy view | Trackers/telemetry per device, block selectively | ⭐⭐ | low |
| Connection quality | Speed test, latency, ISP outages, Wi-Fi per access point | ⭐⭐ | low |

## E. Larger extensions

| Extension | What it brings | Benefit | Effort |
|---|---|---|---|
| Packet capture (Arkime, rolling) | Forensics after incidents | ⭐ | high, privacy-sensitive |
| SIEM (Wazuh, Grafana Loki) | All logs in one place | ⭐ | high, usually oversized |
| Second site | Another server (e.g. at family) via WireGuard | ⭐⭐ | medium |
| Fixed incident playbooks | e.g. new device → quarantine → push → release | ⭐⭐ | medium |

## Priorities after stage 4

1. Prevent DNS bypass + resilience
2. Honeypot + lists of known attackers
3. Push notifications + AI pre-assessment
4. Access points with VLANs
5. The rest only when there is a concrete need

## Risks

- **Too many alarms** is the biggest risk: severities and "ignore" from the start.
- **Firewall = single point of failure:** if it fails, the internet is gone (including for working from home). Keep the way back simple.
- **Maintenance:** every component needs updates. Run a few tools well rather than many halfway.
- **Household:** logs show what others do. Be open about it, keep them briefly (7–30 days).
- **Company devices** stay excluded at every stage.
