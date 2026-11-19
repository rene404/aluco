# KI-Vorbewertung

Stand: 2026-11-19 · optional, standardmäßig aus

Neue Vorfälle werden von Claude vorbewertet: **harmlos / beobachten / verdächtig**, Risiko, eine Empfehlung (erledigen, ignorieren, prüfen, sperren) und zwei bis vier Gründe – in Klartext für Laien. Die Einschätzung ist ein **Vorschlag**; entschieden und gehandelt wird weiterhin von Hand.

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

## Datenschutz

Die übermittelten Daten verlassen das Heimnetz und werden von Anthropic verarbeitet. Wer das nicht möchte, lässt die Funktion aus. Eine lokale Variante (eigenes Modell auf eigener Hardware) steht auf der Roadmap.
