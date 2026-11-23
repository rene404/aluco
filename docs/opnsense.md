# OPNsense: Geräte trennen (Stufe 1)

Stand: 2026-11-23 · geprüft mit OPNsense 26.7 · Voraussetzung: OPNsense als Firewall zwischen Provider-Router und Heimnetz

Mit OPNsense kann Aluco ein Gerät **vom Internet trennen** – immer nur von Hand, mit Rückfrage, nie bei Geräten auf der Schutzliste oder Firmengeräten. Technisch trägt Aluco die IP-Adresse des Geräts in einen Firewall-Alias ein; eine Regel blockiert diesen Alias Richtung Internet. Zusätzlich liefert die ARP-Tabelle der Firewall die Geräte im Netz.

> Grenze: Getrennt wird vom **Internet**, nicht vom restlichen Heimnetz – Verkehr zwischen Geräten im selben Netz läuft an der Firewall vorbei. Echte Isolation braucht VLANs (Roadmap).

## In OPNsense einrichten

1. **Alias** anlegen: *Firewall → Aliases → +* · Name `aluco_quarantine` · Typ **Host(s)** · Inhalt leer.
2. **Regel** auf dem LAN-Interface ganz oben: *Firewall → Rules → LAN → +* · Aktion **Block** · Quelle: Alias `aluco_quarantine` · Ziel: **any** außer dem Aluco-Server (sonst sieht Aluco das Gerät nicht mehr) · Beschreibung „Aluco Quarantäne“. Optional eine zweite Regel davor, die DNS zum Aluco-Server erlaubt.
3. **Benutzer für Aluco** mit minimalen Rechten: *System → Access → Users → +* · Name `aluco` · Rechte (*Effective Privileges*): **Diagnostics: PF Table IP addresses** (Einträge im Alias setzen und entfernen), **Firewall: Aliases** (Alias lesen) und – für die ARP-Tabelle – **Diagnostics: ARP Table**. *Firewall: Alias: Edit* ist **nicht** nötig. Dann beim Benutzer unter *API keys* **+** → die Datei mit Key und Secret wird heruntergeladen.
4. **Fingerprint** des Firewall-Zertifikats (OPNsense nutzt meist ein selbstsigniertes):
   ```sh
   echo | openssl s_client -connect <firewall>:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

## In Aluco eintragen (`.env`)

```sh
OPNSENSE_URL=https://192.0.2.1
OPNSENSE_API_KEY=…
OPNSENSE_API_SECRET=…
OPNSENSE_CERT_SHA256=AB:CD:…        # oder OPNSENSE_CA_FILE=/pfad/ca.pem
OPNSENSE_ALIAS=aluco_quarantine
OPNSENSE_ARP=true                   # ARP-Tabelle als Geräte-Quelle
```

Dann `docker compose up -d aluco aluco-web`. Im Dashboard wird **Trennen** aktiv (mit Rückfrage); getrennte Geräte zeigen im Gerätedetail **Freigeben**.

## Verhalten

- **Erst Firewall, dann Status:** Schlägt der Eintrag in OPNsense fehl, bleibt der Vorfall unverändert.
- **Schutzliste und Firmengeräte** werden nie getrennt – der Knopf ist dort deaktiviert, der Server prüft es zusätzlich.
- **IP-Wechsel (DHCP):** Bekommt ein getrenntes Gerät eine neue IP, sperrt Aluco beim nächsten Lauf auch diese und gibt die alte frei. Besser: feste DHCP-Zuordnung in OPNsense.
- **Doppelte Einträge:** OPNsense legt eine IP bei erneutem Hinzufügen unter Umständen doppelt in der Konfiguration ab, entfernt beim Löschen aber nur einen Eintrag. Aluco fügt deshalb nur hinzu, wenn die IP noch nicht gesperrt ist, und löscht beim Freigeben so lange, bis sie auch aus der gespeicherten Konfiguration verschwunden ist – sonst wäre das Gerät nach dem nächsten Neuladen der Firewall wieder gesperrt.
- **TLS:** Aluco bricht ab, bevor Zugangsdaten gesendet werden, wenn das Zertifikat nicht zum Fingerprint passt.
- Der API-Schlüssel steckt im Runner (ARP) und im Dashboard (Trennen/Freigeben) – mit den Rechten oben kann er nur Einträge in Alias-Tabellen setzen, Aliase lesen und die ARP-Tabelle lesen; Regeln oder Aliase anlegen kann er nicht. Einschränken auf den einen Alias lässt OPNsense nicht zu: Das Recht gilt für die Einträge aller Alias-Tabellen.
