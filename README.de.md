# Aluco

[English](README.md) · **Deutsch**

> **Aluco – Hausradar für dein Netz.**
> Benannt nach dem Waldkauz (*Strix aluco*), der nachts wacht und jede Bewegung bemerkt.

Monitoring für Heimnetz und Laptops: Geräteinventar, Erkennung ungewöhnlicher Vorgänge, Vorfall-Protokoll und Trennen von Geräten per Klick, mit KI-Vorbewertung und MCP-Zugang.

Aluco ersetzt keine bewährten Tools, sondern setzt auf ihnen auf: OPNsense, AdGuard Home, NetAlertX und Suricata liefern die Daten, Aluco führt sie zusammen und macht daraus einen Ablauf von *Vorfall → bewerten → handeln*.

**Status:** v0.4.1 – Software für Stufe 0 und 1 fertig (Dashboard, KI-Vorbewertung mit Claude – direkt oder über OpenRouter – oder lokal mit Ollama, MCP, Laptop-Agent, Trennen über OPNsense, neu registrierte Domains, Regel-Qualität, Wochenbericht, Deutsch und Englisch); Inbetriebnahme auf dem Raspberry Pi steht aus. Änderungen: [CHANGELOG.md](CHANGELOG.md).

## Dokumente

| Datei | Inhalt |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Zielbild, Grundsätze, Ausbaustufen 0–4 |
| [docs/stage-0.md](docs/stage-0.md) | Stufe 0: AdGuard Home + NetAlertX einrichten, Rückweg, Abnahme |
| [docs/opnsense.md](docs/opnsense.md) | Stufe 1: Geräte über OPNsense trennen, ARP-Tabelle |
| [docs/operations.md](docs/operations.md) | Betrieb: Sicherung, Wiederherstellung, Update, Speicherplatz |
| [docs/https.md](docs/https.md) | HTTPS fürs Dashboard mit Caddy und lokaler Zertifizierungsstelle |
| [docs/laptop-agent.md](docs/laptop-agent.md) | Laptop-Agent (osquery): Ports, Autostart, Sicherheitsgrundlagen |
| [docs/mcp.md](docs/mcp.md) | MCP-Server: Claude Desktop/Code nach dem Netz fragen |
| [docs/ai.md](docs/ai.md) | KI-Vorbewertung: was gesendet wird, Einrichtung, Kosten, lokale Modelle mit Ollama |
| [docs/dashboard-concept.md](docs/dashboard-concept.md) | Unterseiten, Erkennungsregeln, Wege zum Trennen, Umgang mit Laptops und Firmengeräten |
| [docs/roadmap.md](docs/roadmap.md) | Ausbau nach Stufe 4 mit Nutzen/Aufwand, Prioritäten, Risiken |
| [docs/naming.md](docs/naming.md) | Herkunft des Namens |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branches (Gitflow), Entwicklungsumgebung, Prüfungen |
| [SECURITY.md](SECURITY.md) | Sicherheitslücken melden |

## Lizenz

[MIT](LICENSE)
