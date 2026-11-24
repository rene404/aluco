# MCP-Server

Stand: 2026-11-19

Mit dem MCP-Server kannst du Claude (Desktop, Code) oder einen anderen MCP-Host direkt nach deinem Netz fragen – z. B. *„Was hat der Fernseher letzte Nacht gemacht?“*, *„Gibt es offene Vorfälle?“*, *„Welche Geräte waren heute offline?“*.

## Eigenschaften

- **Nur lesend:** Die Datenbank wird schreibgeschützt geöffnet; Vorfälle bearbeiten geht weiter nur im Dashboard.
- **Kein offener Port:** Transport ist stdio. Der Host startet den Server per SSH auf dem Pi – Zugang also nur mit deinem SSH-Schlüssel.
- **Firmengeräte:** nur Stammdaten und Online-Status; Aluco speichert zu ihnen keine Domains oder DNS-Statistik.
- **Datenschutz:** Was ein Werkzeug zurückgibt, sieht das Modell. Bei einem Cloud-Modell (Claude) gehen diese Antworten an dessen Anbieter. Anders als bei der KI-Vorbewertung enthalten sie Gerätenamen, IPs und Domains – du fragst ja gezielt danach.

## Werkzeuge

| Werkzeug | Inhalt |
|---|---|
| `get_overview` | Lagebild: offene Vorfälle, Geräte online/offline, DNS der letzten 24 h, Datenquellen |
| `list_incidents` | Vorfälle nach Status (offen, ignoriert, erledigt, alle) |
| `get_incident` | Ein Vorfall mit „Warum auffällig“, Notiz und KI-Einschätzung |
| `list_devices` | Inventar, optional mit Suche und Stufe |
| `get_device` | Gerät mit Aktivität (7 Tage), meistgenutzten Domains, Vorfällen, Verlauf |
| `device_activity` | Zeitraum (z. B. letzte Nacht): Anfragen pro Stunde, Domains der Tage, Ereignisse |
| `timeline` | Chronik der letzten Stunden |
| `dns_top` | Aktivste Geräte, meistblockierte Domains |
| `rule_quality` | Regel-Qualität: ausgelöst, ignoriert, erledigt, getrennt, Ignorier-Quote je Regel (30–400 Tage) |

Genauigkeit: DNS-Daten liegen pro Stunde als Anzahl und pro Tag je Hauptdomain vor – nicht als einzelne Anfragen mit Uhrzeit.

## Einrichten

Voraussetzung: SSH mit Schlüssel vom Mac auf den Server (`ssh aluco-pi` funktioniert ohne Passwort-Abfrage) und der Aluco-Dienst läuft.

**Claude Code:**

```sh
claude mcp add aluco -- ssh aluco-pi docker exec -i aluco python -m aluco mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aluco": {
      "command": "ssh",
      "args": ["aluco-pi", "docker", "exec", "-i", "aluco", "python", "-m", "aluco", "mcp"]
    }
  }
}
```

`aluco-pi` ist ein Eintrag in `~/.ssh/config` (Host, Benutzer, Schlüssel). Lokal am Server selbst genügt `docker exec -i aluco python -m aluco mcp`.

## Ausprobieren ohne Host

```sh
npx @modelcontextprotocol/inspector docker exec -i aluco python -m aluco mcp
```
