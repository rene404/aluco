# Mitarbeiten an Aluco

## Branches (Gitflow)

| Branch | Zweck | Abzweig von | Merge nach |
|---|---|---|---|
| `main` | Nur Releases, jeder Stand ist getaggt (`vX.Y.Z`) | – | – |
| `develop` | Integrationsstand, Standard-Branch | – | – |
| `feature/<kurzname>` | Neue Funktionen | `develop` | `develop` |
| `bugfix/<kurzname>` | Fehler im Entwicklungsstand | `develop` | `develop` |
| `release/<version>` | Release vorbereiten | `develop` | `main` + `develop` |
| `hotfix/<version>` | Dringende Korrektur am Release | `main` | `main` + `develop` |

Änderungen kommen per Pull Request; `main` ist geschützt.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`.

## Entwicklungsumgebung

Voraussetzungen: [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/).

```sh
uv sync                 # Abhängigkeiten installieren (aus uv.lock)
pre-commit install      # Prüfungen vor jedem Commit
uv run pytest           # Tests
uv run ruff check .     # Linter
uv run ruff format .    # Formatierung
```

## Prüfungen vor jedem Commit

- **Secrets:** gitleaks und `detect-private-key`.
- **Private Begriffe:** `scripts/check-private-terms.sh` liest eine lokale, nicht versionierte Liste (`private/forbidden-terms.txt`) und blockiert Commits, die diese Begriffe enthalten. Ohne Liste wird die Prüfung übersprungen.
- **Kein direkter Commit auf `main`.**
- Linter und Formatierung (ruff).

## Abhängigkeiten

- Jede neue Abhängigkeit braucht einen Grund; weniger ist mehr.
- Versionen sind über `uv.lock` festgelegt, GitHub Actions und pre-commit-Hooks über Commit-SHAs.
- Updates kommen über Dependabot mit 7 Tagen Wartezeit (Schutz vor frisch kompromittierten Paketen).

## Grundsätze

- Keine Secrets im Repo; Einstellungen über `.env` (Vorlage: `.env.example`).
- Keine echten Netzdaten (IP-Bereiche, MAC-Adressen, Gerätenamen) in Code, Tests oder Doku – nur Beispielwerte (`192.0.2.0/24`, `02:00:00:00:00:01`).
