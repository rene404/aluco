# Aluco – Architektur

Stand: 2026-11-18 · Status: Konzept

## Zielbild

```
Internet
   │
Provider-Router     (Bridge-Modus, falls möglich)
   │
Firewall: OPNsense  Firewall, DHCP, Suricata, Traffic pro Gerät, WireGuard, Sperren per API
   │
WLAN / Mesh         nur Access Point
   │
Geräte  +  Server (z. B. Raspberry Pi): AdGuard Home, NetAlertX, Aluco-Dashboard, MCP-Server
```

**Grenze:** Verkehr zwischen Geräten im Heimnetz läuft an der Firewall vorbei. Eine Quarantäne trennt vom Internet, nicht vom restlichen Heimnetz. Für echte Trennung braucht es VLAN-fähige Access Points (siehe [roadmap.md](roadmap.md)).

## Grundsätze

- **Adapter-Architektur:** Datenquellen (AdGuard Home, NetAlertX, OPNsense, Suricata, Endgeräte-Agent) und Aktionen (Sperren) liegen hinter Schnittstellen. Weitere Systeme wie UniFi, OpenWrt oder MikroTik lassen sich andocken.
- **Erkennung nicht neu bauen:** Bewährte Tools liefern die Daten; Aluco liefert Zusammenführung, Ablauf für Vorfälle, Aktionen und KI-Vorbewertung.
- **Trennen nur manuell mit Bestätigung.** Einzige Automatik: unbekanntes neues Gerät → Quarantäne.
- **Schutzliste:** Infrastruktur (Firewall, Aluco-Server) und markierte Geräte sind nie sperrbar.
- **Firmengeräte nur passiv:** online/offline und Datenmenge. Keine Agenten, keine automatischen Regeln, keine Daten an die KI.
- **Datenschutz:** Protokolle standardmäßig 30 Tage; Daten an die KI minimiert/anonymisiert oder lokales Modell.
- **Sicherheit des Dashboards:** Zugriff nur aus dem Heimnetz oder per VPN, mit Login; API-Schlüssel der Firewall nur für die Sperrliste berechtigt.
- Keine Secrets im Repo (`.env`). Deployment per Docker Compose.

## Ausbaustufen

| Stufe | Inhalt | Netz umbauen? |
|---|---|---|
| 0 | AdGuard Home + NetAlertX auf dem Server, Router verteilt ihn als DNS | nein |
| 1 | OPNsense als Firewall, Mesh → Access Point, Suricata, Traffic-Daten, Sperren per API | ja |
| 2 | Agent auf privaten Laptops, WireGuard für unterwegs | nein |
| 3 | Aluco-Dashboard + Ablauf für Vorfälle + MCP-Ebene | nein |
| 4 | Normalverhalten pro Gerät lernen, Abweichungen melden | nein |

### Stufe 0 – Ablauf

1. Server: 64-bit-Linux, SSH-Key, Docker + Compose, feste IP per DHCP-Reservierung.
2. AdGuard Home als Container, Upstream-DNS verschlüsselt (DoH/DoT).
3. Router: primärer DNS = Server. **Kein öffentlicher Zweit-DNS** (sonst Umgehung). Server aus = kein DNS → Rückweg dokumentieren und testen.
4. NetAlertX als Container (Host-Netzwerk für ARP-Scan), Meldung bei neuen Geräten.
5. Eine Woche Baseline: alle Geräte benennen, Firmengeräte markieren, Fehlalarme notieren.

**Abnahme:** jedes Gerät im Inventar benannt · DNS-Protokoll pro Gerät sichtbar · Meldung bei neuem Gerät funktioniert · Rückweg getestet.
