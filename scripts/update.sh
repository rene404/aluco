#!/usr/bin/env bash
# Aluco aktualisieren: sichern → neuen Stand holen → Images ziehen/bauen → neu starten → prüfen.
#   scripts/update.sh            neuester Release-Stand von main
#   scripts/update.sh v0.2.0     bestimmte Version (Tag)
# Bei Problemen zurück: git checkout <vorheriger Tag> && docker compose up -d --build
#                       bzw. scripts/restore.sh backups/<letzte Sicherung>
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="${1:-main}"
[[ "$TARGET" =~ ^(main|v[0-9]+\.[0-9]+\.[0-9]+)$ ]] || { echo "Ziel: main oder vX.Y.Z" >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=no)" ]] \
  || { echo "update: lokale Änderungen im Repo – erst klären (git status)" >&2; exit 1; }

before=$(git describe --tags --always)
profiles=()
docker compose --profile https ps --services --status running 2>/dev/null | grep -qx caddy \
  && profiles=(--profile https)

echo "1/5 Sicherung …"
scripts/backup.sh

echo "2/5 Neuen Stand holen ($TARGET) …"
git fetch --tags --quiet origin
if [[ "$TARGET" == main ]]; then
  git checkout --quiet main
  git merge --ff-only --quiet origin/main
else
  git checkout --quiet "$TARGET"
fi
after=$(git describe --tags --always)
echo "    $before → $after"
if [[ "$before" == "$after" ]]; then
  echo "    Bereits aktuell."
fi

echo "3/5 Images aktualisieren …"
docker compose "${profiles[@]}" pull --quiet --ignore-buildable
docker compose build --quiet aluco

echo "4/5 Neu starten …"
docker compose "${profiles[@]}" up -d --remove-orphans

echo "5/5 Prüfen …"
for _ in $(seq 1 30); do
  state=$(docker inspect -f '{{.State.Health.Status}}' aluco-web 2>/dev/null || echo unbekannt)
  [[ "$state" == healthy ]] && break
  sleep 2
done
docker compose "${profiles[@]}" ps --format 'table {{.Name}}\t{{.Status}}'
if [[ "${state:-}" != healthy ]]; then
  echo "update: Dashboard nicht gesund ($state) – Logs: docker compose logs aluco-web" >&2
  exit 1
fi
docker image prune -f >/dev/null
echo "Fertig: $after"
