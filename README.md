# Aluco

> **Aluco – Hausradar für dein Netz.**
> Benannt nach dem Waldkauz (*Strix aluco*), der nachts wacht und jede Bewegung bemerkt.

Monitoring für Heimnetz und Laptops: Geräteinventar, Erkennung ungewöhnlicher Vorgänge, Vorfall-Protokoll und Trennen von Geräten per Klick, mit KI-Vorbewertung und MCP-Zugang.

Aluco ersetzt keine bewährten Tools, sondern setzt auf ihnen auf: OPNsense, AdGuard Home, NetAlertX und Suricata liefern die Daten, Aluco führt sie zusammen und macht daraus einen Ablauf von *Vorfall → bewerten → handeln*.

**Status:** Grundgerüst steht, Umsetzung von Stufe 0 läuft (Branch `develop`).

## Dokumente

| Datei | Inhalt |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Zielbild, Grundsätze, Ausbaustufen 0–4 |
| [docs/stage-0.md](docs/stage-0.md) | Stufe 0: AdGuard Home + NetAlertX einrichten, Rückweg, Abnahme |
| [docs/dashboard-concept.md](docs/dashboard-concept.md) | Unterseiten, Erkennungsregeln, Wege zum Trennen, Umgang mit Laptops und Firmengeräten |
| [docs/roadmap.md](docs/roadmap.md) | Ausbau nach Stufe 4 mit Nutzen/Aufwand, Prioritäten, Risiken |
| [docs/naming.md](docs/naming.md) | Herkunft des Namens |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branches (Gitflow), Entwicklungsumgebung, Prüfungen |
| [SECURITY.md](SECURITY.md) | Sicherheitslücken melden |

## Lizenz

[MIT](LICENSE)
