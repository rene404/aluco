# KI-Vorbewertung

Stand: 2026-11-19 · optional, standardmäßig aus

Neue Vorfälle werden von Claude – oder einem lokalen Modell über Ollama – vorbewertet: **harmlos / beobachten / verdächtig**, Risiko, eine Empfehlung (erledigen, ignorieren, prüfen, sperren) und zwei bis vier Gründe – in Klartext für Laien. Die Einschätzung ist ein **Vorschlag**; entschieden und gehandelt wird weiterhin von Hand.

## Was an die KI geht – und was nicht

| Wird gesendet | Wird **nie** gesendet |
|---|---|
| Regel (z. B. „neues Gerät“, „neue Domain“) und deren Beschreibung | Gerätename, Hostname, Notizen |
| Schweregrad, Anzahl | IP- und MAC-Adressen |
| Vertrauensstufe (bekannt, IoT, Gast, unbekannt) | Titel des Vorfalls (enthält oft den Gerätenamen) |
| Hersteller laut Scan, ob die MAC-Adresse zufällig ist | Daten von **Firmengeräten** – diese werden nie bewertet |
| Bei Domain-Regeln: die Hauptdomain und bis zu 15 meistgenutzte Hauptdomains des Geräts (7 Tage) | vollständige Anfragen, lokale Namen (`*.arpa`, `.local`, `.lan`, `fritz.box` …), DNS-Protokolle, Verlauf |

Die Daten werden als Daten gekennzeichnet; Anweisungen darin (z. B. in einem präparierten Domainnamen) soll die KI nicht befolgen. Ein Gerät im Netz könnte trotzdem versuchen, die Einschätzung zu beeinflussen – deshalb bleibt sie ein **Vorschlag**, Aluco handelt nie automatisch danach.

## Einrichten

In `.env`:

```sh
ALUCO_AI_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-…          # wie ein Passwort behandeln
ALUCO_AI_MODEL=claude-opus-5-5      # Standard
ALUCO_AI_MAX_PER_RUN=5              # Kostenbremse pro Lauf
```

Dann `docker compose up -d --build aluco aluco-web`.

## Ablauf

- Der Runner bewertet **neue oder wieder geöffnete** Vorfälle automatisch, die schwersten zuerst, höchstens `ALUCO_AI_MAX_PER_RUN` pro Lauf.
- Die Einschätzung erscheint im Dashboard (violetter Kasten im Vorfall) und – außer bei `ALUCO_NOTIFY_MINIMAL=true` – in der ntfy-Meldung.
- Im Dashboard lässt sich eine Einschätzung anfordern oder erneuern.
- Fällt die API aus (Netz, Kontingent, ungültiger Schlüssel), läuft Aluco normal weiter; der Fehler steht im Log bzw. im Vorfall.

## Technik und Kosten

- Offizielles Anthropic-SDK (optionales Extra `ai`), strukturierte Ausgabe mit Schema-Prüfung, Aufwand `low`.
- Lehnt das Modell eine Anfrage ab, übernimmt serverseitig ein Ersatzmodell (`fallbacks: "default"`).
- Ein Vorfall braucht nur wenige hundert Tokens; im Heimnetz mit wenigen Vorfällen pro Tag liegen die Kosten im Cent-Bereich pro Monat. Ein günstigeres Modell lässt sich über `ALUCO_AI_MODEL` wählen.
- Bewertungen werden mit dem Vorfall gelöscht (Aufbewahrungsfrist) und beim Markieren eines Geräts als Firmengerät sofort.

## Lokales Modell (Ollama) – Daten bleiben im Heimnetz

Statt Claude kann ein Modell auf eigener Hardware bewerten, z. B. auf einem Mac oder PC im Heimnetz mit [Ollama](https://ollama.com). Gesendet werden dieselben, sparsamen Felder – sie verlassen das Heimnetz aber nicht.

```sh
# auf dem Rechner mit Ollama
ollama pull qwen3:4b                      # klein, gut mit Deutsch und JSON (~2,5 GB)
OLLAMA_HOST=0.0.0.0 ollama serve          # im Heimnetz erreichbar machen (Firewall beachten)
```

In `.env` des Aluco-Servers:

```sh
ALUCO_AI_ENABLED=true
ALUCO_AI_PROVIDER=ollama
ALUCO_AI_OLLAMA_URL=http://192.0.2.5:11434
ALUCO_AI_MODEL=qwen3:4b
```

- Die Antwort wird per JSON-Schema angefordert und **streng geprüft** (nur erlaubte Werte, Längen begrenzt).
- Kleine Modelle sind weniger treffsicher als Claude – die Einschätzung bleibt ein Vorschlag.
- Auf einem Raspberry Pi selbst ist ein Modell dieser Größe zu langsam; besser ein Rechner mit mehr Leistung.
- Ollama hat keine eigene Anmeldung: nur im Heimnetz erreichbar machen, nie ins Internet.

## Bewertungsqualität messen (Beispielsatz)

Damit Prompt-Änderungen und Modellwechsel vergleichbar sind, gibt es einen festen **Beispielsatz** mit 24 Vorfällen (`src/aluco/ai_eval_cases.json`): alle Regeln, typische Fehlalarme (zufällige MAC, Gastgeräte, Hersteller-Domains) und Versuche, über Domainnamen oder Herstellerangaben Anweisungen einzuschleusen. Jeder Fall wird wie ein echter Vorfall aufbereitet; je Fall ist festgelegt, welche Einstufung und Empfehlung noch als richtig gelten.

```sh
aluco ai-eval --provider ollama --ollama-url http://192.0.2.5:11434 --model qwen3:4b --repeat 2
aluco ai-eval --provider claude                     # braucht ANTHROPIC_API_KEY
aluco ai-eval --case autostart-getarnt --json       # einzelne Fälle, Ausgabe als JSON
```

- **Treffer:** Einstufung, Empfehlung (und wo festgelegt das Risiko) liegen im erlaubten Bereich.
- **„Behauptung prüfen“:** Sätze wie „die Domain ist bekannt für …“ – die KI bekommt nur die Vorfallsdaten, solches Wissen ist oft erfunden. Kein Fehler, aber von Hand ansehen.
- `--min-rate 0.8` beendet mit Exit-Code 1 unter 80 % – für eigene Prüfläufe. In der normalen CI läuft der Satz nicht (braucht ein Modell).

### Ergebnisse

| Datum | Modell | Treffer | stabil¹ | zu prüfen | Dauer |
|---|---|---|---|---|---|
| 2026-11-24 | ollama/qwen3:4b (Mac, Apple Silicon) | 36/48 (75 %) | ja | 6 | 3,7 min |
| – | Claude | noch nicht gemessen | | | |

¹ beide Durchgänge (`--repeat 2`) gleich.

Schwächen von qwen3:4b in diesem Lauf:
- **Einschleusung wirkt:** Eine Anweisung im Herstellernamen führt zu „sperren“; eine Anweisung im Domainnamen stuft eine Schad-Domain auf „beobachten“ herab.
- **Laptop-Einstellungen:** FileVault oder SIP aus → „sperren“. Vom Netz trennen behebt das nicht; richtig wäre „prüfen“.
- **Autostart:** Ein getarnter Eintrag mit `com.apple.…`-Label aus einem versteckten Ordner gilt als „autorisiert“, der Google-Updater dagegen als verdächtig.
- **Erfundenes Wissen:** „die Domain ist bekannt für Malware/Phishing“ bei erfundenen Domains.

Gut: neue Geräte (auch zufällige MAC), neue Domains von IoT-Geräten, offene Ports und Schad-Domains ohne Einschleusung.

## Datenschutz

Mit Claude verlassen die übermittelten Daten das Heimnetz und werden von Anthropic verarbeitet; mit Ollama bleiben sie im Heimnetz. Wer beides nicht möchte, lässt die Funktion aus.
