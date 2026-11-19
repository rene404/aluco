# HTTPS für das Dashboard (Caddy)

Stand: 2026-11-19 · optional, **empfohlen**

Ohne HTTPS gehen Dashboard-Passwort, Sitzung und das Token des Laptop-Agenten im Heimnetz unverschlüsselt über die Leitung – im WLAN kann sie jedes Gerät mitlesen, das sich dazwischenschaltet. Caddy setzt sich vor das Dashboard und verschlüsselt mit einer **eigenen, lokalen Zertifizierungsstelle** (kein Internet, keine Domain nötig).

## Einrichten

1. In `.env`:
   ```sh
   ALUCO_HTTPS_SITES=https://aluco.lan:8443, https://192.0.2.2:8443   # Name und/oder IP des Servers
   ALUCO_WEB_ALLOWED_HOSTS=aluco.lan
   ALUCO_WEB_HOST=127.0.0.1          # Dashboard nur noch über Caddy erreichbar
   ALUCO_WEB_TRUST_PROXY=true        # echte Client-IP von Caddy übernehmen
   ALUCO_WEB_SECURE_COOKIES=true     # Sitzungs-Cookie nur über HTTPS
   ```
2. Ordner anlegen und starten:
   ```sh
   mkdir -p data/caddy/data data/caddy/config && sudo chown -R 10001:10001 data/caddy
   docker compose --profile https up -d
   ```
3. **Stammzertifikat** auf den Geräten eintragen, die das Dashboard öffnen. Es liegt unter `data/caddy/data/caddy/pki/authorities/local/root.crt` (10 Jahre gültig).
   - **macOS:** Datei öffnen → Schlüsselbundverwaltung → „System“ → Zertifikat doppelklicken → *Vertrauen: Immer vertrauen*.
   - **iPhone/iPad:** Datei per AirDrop/Mail öffnen → Profil installieren → *Einstellungen → Allgemein → Info → Zertifikatsvertrauenseinstellungen* → einschalten.
   - **Android:** *Einstellungen → Sicherheit → Verschlüsselung → Zertifikat installieren → CA-Zertifikat*.
   - **Windows:** Datei öffnen → Zertifikat installieren → „Vertrauenswürdige Stammzertifizierungsstellen“.
4. Dashboard: `https://aluco.lan:8443`.

Laptop-Agent über HTTPS: `sudo agent/install.sh https://aluco.lan:8443 <TOKEN> data/caddy/…/root.crt` (das Zertifikat vorher auf den Mac kopieren).

## Hinweise

- Das Stammzertifikat erlaubt dem Server, Zertifikate auszustellen, denen deine Geräte vertrauen. Der **private Schlüssel** dazu liegt in `data/caddy/data/…/root.key` – nie weitergeben, mit `data/` sichern.
- Caddy führt kein Zugriffsprotokoll (nur Fehler), sendet HSTS und keinen Server-Header.
- Eigener Domainname mit öffentlichem Zertifikat (z. B. per DNS-Challenge) ist möglich, aber nicht vorkonfiguriert.
