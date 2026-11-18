# Aluco – Dashboard-Konzept

Stand: 2026-11-18

## Unterseiten

1. **Übersicht:** Geräte (online / neu / unbekannt), offene Alarme, Traffic der letzten 24 h, Status der Sensoren.
2. **Geräte („Radar“):** Inventar mit MAC, Hersteller, IP, zuerst/zuletzt gesehen, Vertrauensstufe (bekannt / IoT / Gast / unbekannt / Firma), Button „Trennen“.
3. **Gerätedetail:** kontaktierte Domains und Länder, Datenmenge im Zeitverlauf, typisches Verhalten.
4. **DNS & Traffic:** Top-Domains, blockierte Anfragen, neu gesehene Domains.
5. **Vorfälle:** Protokoll mit Status (neu / untersucht / ignoriert / getrennt) und Notiz. **Das Herzstück.**
6. **Laptop:** Prozesse mit Netzwerkverbindungen, offene Ports, neue Autostart-Einträge (LaunchAgents/-Daemons), Anmeldungen. Nur private Laptops.
7. **Regeln & Aktionen:** Definition „ungewöhnlich“, gesperrte Geräte, Quarantäne aufheben, Schutzliste.

## Erkennungsregeln (Start, wenig Fehlalarme)

- Neues Gerät (unbekannte MAC) im Netz.
- IoT-Gerät spricht andere Geräte im Heimnetz an statt nur ins Internet.
- Gerät kontaktiert ein Land oder eine Domain, die es noch nie kontaktiert hat.
- Ungewöhnlich viel Upload, besonders nachts.
- Port-Scans im Heimnetz; Suricata-Alarme mit hoher Schwere.
- Laptop: neuer Prozess lauscht auf einem Port; neuer LaunchAgent/LaunchDaemon.
- Später: DNS-Anfragen an neu registrierte Domains (< 14 Tage).

Von Anfang an: Schweregrade und ein Knopf „bekannt / ignorieren“, sonst stumpft man ab.

## Optionen zum Trennen

| Weg | Bewertung |
|---|---|
| Am Router/an der Firewall sperren (OPNsense-API, Sperrliste) | **Gewählt** (ab Stufe 1). Sauber. |
| Per DNS sperren (AdGuard) | Einfach, umgehbar durch festen DNS oder DNS-over-HTTPS. Übergangslösung in Stufe 0. |
| Quarantäne-VLAN | Sauberste Trennung, braucht VLAN-fähige Access Points (Roadmap). |
| ARP-Spoofing | Fragil, nicht als Dauerlösung. |

Regel: Trennen nur auf Knopfdruck mit Bestätigung. Automatisch nur „unbekanntes neues Gerät → Quarantäne“. Schutzliste (Infrastruktur und markierte Geräte) nie sperrbar.

## Laptops

| Gerät | Umgang |
|---|---|
| Private Laptops | Kleiner Agent (osquery oder eigenes Skript) meldet an den Aluco-Server; unterwegs per WireGuard. |
| Firmengeräte | Nichts installieren (IT-Richtlinien, EDR). Im Dashboard „Firma – nur beobachten“: online/offline, Datenmenge. Nie automatisch sperren, keine Daten an die KI. Mit Firmen-VPN ist ohnehin nur der Tunnel sichtbar. |
