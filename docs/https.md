# HTTPS for the dashboard (Caddy)

As of: 2026-11-19 · optional, **recommended**

Without HTTPS, the dashboard password, the session and the laptop agent's token travel unencrypted across the home network – on Wi-Fi, any device that places itself in between can read them. Caddy sits in front of the dashboard and encrypts with its **own local certificate authority** (no internet, no domain needed).

## Setup

1. In `.env`:
   ```sh
   ALUCO_HTTPS_SITES=https://aluco.lan:8443, https://192.0.2.2:8443   # name and/or IP of the server
   ALUCO_WEB_ALLOWED_HOSTS=aluco.lan
   ALUCO_WEB_HOST=127.0.0.1          # dashboard reachable only through Caddy
   ALUCO_WEB_TRUST_PROXY=true        # take the real client IP from Caddy
   ALUCO_WEB_SECURE_COOKIES=true     # session cookie over HTTPS only
   ```
2. Create the folders and start:
   ```sh
   mkdir -p data/caddy/data data/caddy/config && sudo chown -R 10001:10001 data/caddy
   docker compose --profile https up -d
   ```
3. Install the **root certificate** on the devices that open the dashboard. It is at `data/caddy/data/caddy/pki/authorities/local/root.crt` (valid for 10 years).
   - **macOS:** open the file → Keychain Access → "System" → double-click the certificate → *Trust: Always Trust*.
   - **iPhone/iPad:** open the file via AirDrop/mail → install the profile → *Settings → General → About → Certificate Trust Settings* → turn it on.
   - **Android:** *Settings → Security → Encryption → Install a certificate → CA certificate*.
   - **Windows:** open the file → Install Certificate → "Trusted Root Certification Authorities".
4. Dashboard: `https://aluco.lan:8443`.

Laptop agent over HTTPS: `sudo agent/install.sh https://aluco.lan:8443 <TOKEN> data/caddy/…/root.crt` (copy the certificate to the Mac first).

## Notes

- The root certificate lets the server issue certificates that your devices trust. Its **private key** is in `data/caddy/data/…/root.key` – never share it, back it up with `data/`.
- Caddy keeps no access log (errors only), sends HSTS and no Server header.
- A custom domain name with a public certificate (e.g. via DNS challenge) is possible, but not preconfigured.
