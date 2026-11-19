# Aluco – Roadmap nach Stufe 4

Stand: 2026-11-18 · Bewertung: Nutzen ⭐–⭐⭐⭐

## A. Netz-Infrastruktur

| Ausbau | Was er bringt | Nutzen | Aufwand |
|---|---|---|---|
| Access Points mit VLANs (z. B. Omada/UniFi statt Consumer-Mesh) | Getrennte Netze: Haushalt, IoT, Gäste, Quarantäne; echte Trennung auch im Heimnetz | ⭐⭐⭐ | mittel, neue Hardware |
| Managed Switch + Port-Mirror + Zeek | Verkehr zwischen Geräten sichtbar, Protokoll-Logs (TLS-Fingerprints, Zertifikate) | ⭐⭐ | mittel |
| DNS-Umgehung verhindern | Port 53 auf AdGuard umleiten, bekannte DoH/DoT-Server sperren | ⭐⭐⭐ | gering |
| Ausfallsicherheit | USV, automatisches OPNsense-Backup, Notfallplan „Firewall raus, alter Router zurück“ | ⭐⭐⭐ | gering |

## B. Erkennung

| Ausbau | Was er bringt | Nutzen | Aufwand |
|---|---|---|---|
| Honeypot & Canary-Tokens (OpenCanary) | Jeder Zugriff ist ein echter Alarm; bestes Signal pro Aufwand | ⭐⭐⭐ | gering |
| Listen bekannter Angreifer (CrowdSec, abuse.ch, Spamhaus DROP) | Bekannte bösartige IPs/Domains sperren und melden – **Domains umgesetzt** (HaGeZi TIF, erweiterbar) | ⭐⭐⭐ | gering |
| Eigene Geräte auf Schwachstellen scannen (nmap, Greenbone) | Neue Ports, veraltete Firmware | ⭐⭐ | mittel |
| Angriffsfläche von außen | Öffentliche IP scannen, Shodan, UPnP-Freigaben (UPnP abschalten) | ⭐⭐ | gering |
| CVE-Abgleich | Hersteller/Modell → bekannte Lücken | ⭐⭐ | mittel |
| Mac härten (Santa, KnockKnock, Datei-Integrität) | Nur freigegebene Programme auf privaten Laptops – **Teil umgesetzt:** Laptop-Agent prüft Autostart, Ports, Firewall/FileVault/Gatekeeper/SIP | ⭐⭐ | mittel |

## C. KI und Bedienung

| Ausbau | Was er bringt | Nutzen | Aufwand |
|---|---|---|---|
| KI-Vorbewertung von Vorfällen | Zusammenfassung, Erklärung, Vorschlag; Tagesbericht – **Vorbewertung umgesetzt** | ⭐⭐⭐ | gering–mittel |
| MCP-Server für das Netz | „Was hat der Fernseher letzte Nacht gemacht?“ – **umgesetzt** (nur lesend, stdio über SSH) | ⭐⭐ | mittel |
| Push-Meldungen (ntfy, Telegram, Pushover) | Alarm aufs Handy, Abendzusammenfassung | ⭐⭐⭐ | gering |
| „Trennen“ direkt aus der Meldung | Nur mit Bestätigung/Login (Angriffspunkt) | ⭐⭐ | gering |
| Dashboard als PWA | App-Gefühl am Handy | ⭐ | gering |

Datenschutz: Daten an die KI ausdünnen/anonymisieren oder lokales Modell auf eigener Hardware.

## D. Komfort und Haushalt

| Ausbau | Was er bringt | Nutzen | Aufwand |
|---|---|---|---|
| Home Assistant | Anwesenheit, Automationen | ⭐⭐ | mittel |
| Zeitregeln pro Gerät | Kinder-/Konsolenzeiten, IoT nachts offline | ⭐⭐ | gering |
| Datenschutz-Ansicht | Tracker/Telemetrie pro Gerät, gezielt sperren | ⭐⭐ | gering |
| Verbindungsqualität | Speedtest, Latenz, Provider-Ausfälle, WLAN pro Access Point | ⭐⭐ | gering |

## E. Größere Ausbauten

| Ausbau | Was er bringt | Nutzen | Aufwand |
|---|---|---|---|
| Paketaufzeichnung (Arkime, rollierend) | Forensik nach Vorfällen | ⭐ | hoch, Datenschutz heikel |
| SIEM (Wazuh, Grafana Loki) | Alle Logs an einer Stelle | ⭐ | hoch, meist überdimensioniert |
| Zweiter Standort | Weiterer Server (z. B. bei der Familie) per WireGuard | ⭐⭐ | mittel |
| Feste Abläufe für Vorfälle | z. B. neues Gerät → Quarantäne → Push → Freigabe | ⭐⭐ | mittel |

## Prioritäten nach Stufe 4

1. DNS-Umgehung verhindern + Ausfallsicherheit
2. Honeypot + Listen bekannter Angreifer
3. Push-Meldungen + KI-Vorbewertung
4. Access Points mit VLANs
5. Rest nur bei konkretem Bedarf

## Risiken

- **Zu viele Alarme** ist das größte Risiko: Schweregrade und „ignorieren“ von Anfang an.
- **Firewall = Single Point of Failure:** fällt sie aus, ist das Internet weg (auch fürs Homeoffice). Rückweg einfach halten.
- **Wartung:** jede Komponente braucht Updates. Wenige Werkzeuge gut betreiben statt viele halb.
- **Haushalt:** Protokolle zeigen, was andere tun. Offen sagen, kurz aufbewahren (7–30 Tage).
- **Firmengeräte** bleiben in jeder Stufe ausgenommen.
