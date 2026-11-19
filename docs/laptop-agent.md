# Laptop-Agent (osquery)

Stand: 2026-11-19 · nur für **private** Macs – nie auf Firmengeräten installieren

Der Agent führt alle 10 Minuten feste, **nur lesende** [osquery](https://osquery.io)-Abfragen aus und schickt das Ergebnis an Aluco. Aluco merkt sich, was es kennt, und meldet Neues als Vorfall.

| Was | Vorfall, wenn … | Schwere |
|---|---|---|
| Offene Ports (nach außen, nicht nur localhost) | ein Programm neu Verbindungen annimmt | mittel |
| Autostart (LaunchAgents/-Daemons außerhalb von `/System`) | ein neuer Eintrag dazukommt | mittel |
| Anmeldungen | eine **Fern**-Anmeldung (z. B. SSH) neu auftaucht | mittel |
| Firewall, FileVault, Gatekeeper, SIP | eine Sicherheitsgrundlage aus ist – wird automatisch erledigt, sobald sie wieder an ist | mittel/hoch |

Der **erste Bericht lernt nur** (alles Vorhandene gilt als bekannt). Im Dashboard zeigt das Gerätedetail einen Abschnitt **Laptop**.

## Einrichten

1. osquery installieren: `brew install --cask osquery`
2. Am Aluco-Server einen Agenten anlegen – das Token wird **nur einmal** angezeigt:
   ```sh
   docker compose exec aluco python -m aluco agent add "<Gerätename oder MAC>"
   ```
3. Auf dem Mac (aus dem Repo):
   ```sh
   sudo agent/install.sh http://<server>:8088 <TOKEN>
   ```
   Das installiert `/usr/local/libexec/aluco-agent` (root, nur lesbar/ausführbar), die Konfiguration `/usr/local/etc/aluco-agent.conf` (nur root lesbar) und den launchd-Job `dev.aluco.agent`. Log: `/var/log/aluco-agent.log`.

Entfernen: `sudo agent/uninstall.sh` und `aluco agent remove <Gerät>`.

## Sicherheit und Datenschutz

- Feste Abfragen im Skript, keine Fernsteuerung: Aluco kann dem Agenten nichts befehlen.
- Token pro Gerät (in Aluco nur als Hash gespeichert), an curl über stdin übergeben – nie in der Prozessliste.
- Bericht max. 1 MB, höchstens alle 30 s, Werte bereinigt und gekürzt.
- Benutzernamen in Pfaden werden zu `~` gekürzt; an die KI-Vorbewertung gehen nur Programm, gekürzter Pfad und Port.
- Markiert man das Gerät als **Firma**, löscht Aluco Agent und alle Einträge und nimmt keine Berichte mehr an.
- Ohne HTTPS geht das Token im Heimnetz unverschlüsselt über die Leitung – wie beim Dashboard wird ein TLS-Reverse-Proxy empfohlen.
