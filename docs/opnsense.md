# OPNsense: disconnecting devices (stage 1)

As of: 2026-11-23 · tested with OPNsense 26.7 · Prerequisite: OPNsense as the firewall between the ISP router and the home network

With OPNsense, Aluco can **cut a device off from the internet** – always manually, with confirmation, never for devices on the protected list or company devices. Technically, Aluco adds the device's IP address to a firewall alias; a rule blocks this alias towards the internet. In addition, the firewall's ARP table provides the devices on the network.

> Limit: The device is cut off from the **internet**, not from the rest of the home network – traffic between devices on the same network bypasses the firewall. Real isolation needs VLANs (roadmap).

## Setup in OPNsense

1. Create an **alias**: *Firewall → Aliases → +* · name `aluco_quarantine` · type **Host(s)** · content empty.
2. **Rule** at the very top of the LAN interface: *Firewall → Rules → LAN → +* · action **Block** · source: alias `aluco_quarantine` · destination: **any** except the Aluco server (otherwise Aluco no longer sees the device) · description "Aluco quarantine". Optionally a second rule before it that allows DNS to the Aluco server.
3. **User for Aluco** with minimal privileges: *System → Access → Users → +* · name `aluco` · privileges (*Effective Privileges*): **Diagnostics: PF Table IP addresses** (add and remove entries in the alias), **Firewall: Aliases** (read the alias) and – for the ARP table – **Diagnostics: ARP Table**. *Firewall: Alias: Edit* is **not** needed. Then, for the user, under *API keys* **+** → the file with key and secret is downloaded.
4. **Fingerprint** of the firewall certificate (OPNsense usually uses a self-signed one):
   ```sh
   echo | openssl s_client -connect <firewall>:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

## Configure Aluco (`.env`)

```sh
OPNSENSE_URL=https://192.0.2.1
OPNSENSE_API_KEY=…
OPNSENSE_API_SECRET=…
OPNSENSE_CERT_SHA256=AB:CD:…        # or OPNSENSE_CA_FILE=/path/ca.pem
OPNSENSE_ALIAS=aluco_quarantine
OPNSENSE_ARP=true                   # ARP table as device source
```

Then `docker compose up -d aluco aluco-web`. In the dashboard, **Disconnect** becomes active (with confirmation); disconnected devices show **Release** in the device detail.

## Behavior

- **Firewall first, then status:** If the entry in OPNsense fails, the incident stays unchanged.
- **Protected list and company devices** are never disconnected – the button is disabled there, and the server checks it as well.
- **IP change (DHCP):** If a disconnected device gets a new IP, Aluco blocks that one too on the next run and releases the old one. Better: a static DHCP mapping in OPNsense.
- **Duplicate entries:** When an IP is added again, OPNsense may store it twice in the configuration, but removes only one entry when deleting. Aluco therefore only adds an IP that is not blocked yet, and when releasing it keeps deleting until the IP is also gone from the saved configuration – otherwise the device would be blocked again after the next firewall reload.
- **TLS:** Aluco aborts before sending credentials if the certificate does not match the fingerprint.
- The API key is used by the runner (ARP) and the dashboard (disconnect/release) – with the privileges above it can only set entries in alias tables, read aliases and read the ARP table; it cannot create rules or aliases. OPNsense does not allow restricting it to the one alias: the privilege applies to the entries of all alias tables.
