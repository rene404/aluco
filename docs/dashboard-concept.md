# Aluco – Dashboard-Konzept

Stand: 2026-11-18

## Unterseiten

1. **Übersicht:** Geräte (online / neu / unbekannt), offene Alarme, Traffic der letzten 24 h, Status der Sensoren.
2. **Geräte („Radar“):** Inventar mit MAC, Hersteller, IP, zuerst/zuletzt gesehen, Vertrauensstufe (bekannt / IoT / Gast / unbekannt / Firma), Button „Trennen“.
3. **Gerätedetail:** kontaktierte Domains und Länder, Datenmenge im Zeitverlauf, typisches Verhalten.
4. **DNS & Traffic:** Top-Domains, blockierte Anfragen, neu gesehene Domains.
5. **Vorfälle:** Protokoll mit Status (neu / untersucht / ignoriert / getrennt) und Notiz. **Das Herzstück.**
6. **Laptop:** Prozesse mit Netzwerkverbindungen, offene Ports, neue Autostart-Einträge (LaunchAgents/-Daemons), Anmeldungen. Nur private Laptops.
7. **Regeln & Aktionen:** Definition „ungewöhnlich“, gesperrte Geräte, Quarantäne aufheben, Schutzliste. Umgesetzt: Regel-Qualität (siehe unten).

## Erkennungsregeln (Start, wenig Fehlalarme)

- Neues Gerät (unbekannte MAC) im Netz.
- IoT-Gerät spricht andere Geräte im Heimnetz an statt nur ins Internet.
- Gerät kontaktiert ein Land oder eine Domain, die es noch nie kontaktiert hat.
- Ungewöhnlich viel Upload, besonders nachts.
- Port-Scans im Heimnetz; Suricata-Alarme mit hoher Schwere.
- Laptop: neuer Prozess lauscht auf einem Port; neuer LaunchAgent/LaunchDaemon.
- DNS-Anfragen an neu registrierte Domains (< 14 Tage), Schweregrad mittel – siehe [stage-0.md](stage-0.md#neu-registrierte-domains).

Von Anfang an: Schweregrade und ein Knopf „bekannt / ignorieren“, sonst stumpft man ab.

### Regel-Qualität (Seite „Regeln“)

Ob man abstumpft, zeigt die Seite **Regeln** (`/rules`): je Regel für 30 oder 90 Tage

- **ausgelöst:** neue Vorfälle, dazu „+n“ für erledigte Befunde, die erneut aufgetreten sind;
- **ignoriert / erledigt / getrennt:** nur Entscheidungen von Hand. Automatisch erledigte Vorfälle (Sicherheitsgrundlage laut Agent wieder an) stehen als „+n auto“ daneben und zählen nicht;
- **Ignorier-Quote:** ignoriert ÷ (ignoriert + erledigt + getrennt). Über 70 % bei mindestens 3 Entscheidungen ist die Regel als „abgestumpft?“ markiert und oben gesammelt;
- **Zeit bis Entscheidung:** Median vom Auftreten (oder Wiederöffnen) bis zur Entscheidung;
- **KI daneben:** wie oft die KI „verdächtig“ sagte und trotzdem ignoriert wurde, oder „harmlos“ und trotzdem getrennt.

Grundlage ist ein eigener Verlauf (`incident_history`) mit nur Regel, Zeitpunkt, Status und KI-Einstufung – ohne Gerät, Domain oder Titel. Darum bleibt er 400 Tage, auch wenn erledigte Vorfälle nach der Aufbewahrungsfrist (30 Tage) gelöscht werden. Beim Update auf Schema v6 werden vorhandene Vorfälle als „ausgelöst“ übernommen; frühere Entscheidungen lassen sich nicht rekonstruieren. Dieselben Zahlen liefert der MCP-Server mit `rule_quality`.

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

## Design V1 (Stand 2026-11-19)

Umgesetzt in `src/aluco/web/` (Dashboard v2). Diese Fassung ist die Referenz für weitere Seiten.

**Seiten:** Übersicht (Lagebild, Kennzahlen, DNS-Diagramm 24 h/7 Tage, Chronik, aktivste Geräte, meistblockierte Domains) · Vorfälle (aufklappbare Karten mit „Warum auffällig“, Notiz, Aktionen) · Geräte (Karten mit Online-Status, Stufe, Mini-Verlauf, Suche/Filter) · Gerätedetail (Aktivität 7 Tage, typisches Verhalten, Domains, Einstellungen, Vorfälle, Verlauf).

**Farben (hell / dunkel):**

| Rolle | Hell | Dunkel |
|---|---|---|
| Akzent | `#1d4ed8` | `#7ea2f7` |
| Akzent dunkel | `#1e3a8a` | `#b3c8fb` |
| Akzent-Hintergrund | `#dbe6fd` | `#1c2b4d` |
| Seite / Fläche | `#f3f5f7` / `#ffffff` | `#0f1318` / `#171c22` |
| Text / Nebentext | `#151a1f` / `#56606b` | `#e8edf2` / `#9aa5b1` |
| Diagramm erlaubt / blockiert | `#3b6ee0` / `#d9822b` | `#6f95ef` / `#e39a4f` |

Farbe trägt nur Bedeutung: Orange/Rot = Schwere, Grün = online/erledigt, Grau = niedrig/offline, Türkis = IoT, Violett = KI. Keine Emojis, Logo ist die SVG-Eule.

**Technik:** serverseitig gerendert (Jinja2), htmx lokal eingebunden, Diagramme als SVG-Attribute, keine Inline-Styles (strikte CSP), Farben als CSS-Variablen in `static/aluco.css`.
