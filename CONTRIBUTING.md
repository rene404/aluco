# Contributing to Aluco

## Branches (Gitflow)

| Branch | Purpose | Branched from | Merged into |
|---|---|---|---|
| `main` | Releases only, every state is tagged (`vX.Y.Z`) | – | – |
| `develop` | Integration state, default branch | – | – |
| `feature/<short-name>` | New features | `develop` | `develop` |
| `bugfix/<short-name>` | Bugs in the development state | `develop` | `develop` |
| `release/<version>` | Prepare a release | `develop` | `main` + `develop` |
| `hotfix/<version>` | Urgent fix to a release | `main` | `main` + `develop` |

Changes come in via pull request; `main` is protected.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`.

## Development environment

Prerequisites: [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/).

```sh
uv sync                 # install dependencies (from uv.lock)
pre-commit install      # checks before every commit
uv run pytest           # tests
uv run ruff check .     # linter
uv run ruff format .    # formatting
```

## Checks before every commit

- **Secrets:** gitleaks and `detect-private-key`.
- **Private terms:** `scripts/check-private-terms.sh` reads a local, unversioned list (`private/forbidden-terms.txt`) and blocks commits that contain these terms. Without the list, the check is skipped.
- **No direct commit to `main`.**
- Linter and formatting (ruff).

## Dependencies

- Every new dependency needs a reason; less is more.
- Versions are pinned via `uv.lock`, GitHub Actions and pre-commit hooks via commit SHAs.
- Updates come via Dependabot with a 7-day waiting period (protection against freshly compromised packages).

## Principles

- No secrets in the repo; settings via `.env` (template: `.env.example`).
- No real network data (IP ranges, MAC addresses, device names) in code, tests or docs – only example values (`192.0.2.0/24`, `02:00:00:00:00:01`).
- User-facing text is written in German and translated in `src/aluco/locale_en.py` (`ALUCO_LANGUAGE=en`); `tests/test_i18n.py` reports missing translations. Documentation is written in English.
