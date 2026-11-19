#!/usr/bin/env bash
# Blockiert Commits, deren hinzugefügte Zeilen oder Dateinamen private Begriffe enthalten.
# Geprüft werden ganze Wörter: der Begriff "Code" löst bei "Encoder" nicht aus.
# Die Begriffe stehen lokal in private/forbidden-terms.txt (gitignored, ein Begriff pro Zeile,
# '#' für Kommentare, Groß-/Kleinschreibung egal). Fehlt die Datei, wird nur gewarnt.
set -euo pipefail

terms_file="${ALUCO_TERMS_FILE:-private/forbidden-terms.txt}"

if [[ ! -f "$terms_file" ]]; then
  echo "check-private-terms: $terms_file fehlt – Prüfung übersprungen." >&2
  exit 0
fi

patterns="$(grep -vE '^\s*(#|$)' "$terms_file" || true)"
[[ -z "$patterns" ]] && exit 0

# Nur hinzugefügte Zeilen aus dem Staging-Bereich; LICENSE enthält bewusst den Namen.
added="$(git diff --cached -U0 --no-color -- . ':(exclude)LICENSE' \
  | grep -E '^\+' | grep -vE '^\+\+\+ ' || true)"
names="$(git diff --cached --name-only --diff-filter=ACR)"

found=0
while IFS= read -r term; do
  if grep -qiwF -- "$term" <<<"$added"; then
    echo "check-private-terms: privater Begriff im Diff gefunden (Zeile $(grep -niF -- "$term" "$terms_file" | head -1 | cut -d: -f1) in $terms_file)" >&2
    found=1
  fi
  if grep -qiwF -- "$term" <<<"$names"; then
    echo "check-private-terms: privater Begriff in einem Dateinamen gefunden (Zeile $(grep -niF -- "$term" "$terms_file" | head -1 | cut -d: -f1) in $terms_file)" >&2
    found=1
  fi
done <<<"$patterns"

if [[ $found -ne 0 ]]; then
  echo "Commit abgebrochen. Stellen mit 'git diff --cached' prüfen und neutral formulieren." >&2
  exit 1
fi
