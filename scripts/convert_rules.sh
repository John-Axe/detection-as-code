#!/usr/bin/env bash
# Convert every Sigma rule to each supported SIEM query language and write
# the result to build/<backend>/<rule-stem>.<ext>. Acts as the CI conversion
# gate: if a rule can't be translated to a target SIEM, this fails before
# merge.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build"

# subdir:extension:sigma-cli-target
BACKENDS=(
  "elastic:lucene:lucene"
  "splunk:spl:splunk"
  "sentinel:kql:kusto"
)

for backend in "${BACKENDS[@]}"; do
  IFS=':' read -r subdir ext target <<< "$backend"
  mkdir -p "$OUT_DIR/$subdir"

  for rule in "$REPO_ROOT"/rules/*.yml; do
    stem="$(basename "$rule" .yml)"
    # The ecs_windows field-mapping pipeline is only defined for the
    # Elasticsearch target; other backends consume raw Sigma field names.
    if [[ "$target" == "lucene" && "$rule" == *windows* ]]; then
      pipeline=(-p ecs_windows)
    else
      pipeline=(--without-pipeline)
    fi
    echo "Converting $stem -> build/$subdir/$stem.$ext"
    sigma convert -t "$target" "${pipeline[@]}" "$rule" > "$OUT_DIR/$subdir/$stem.$ext"
  done

  echo "Wrote $(ls "$OUT_DIR/$subdir"/*."$ext" | wc -l) converted queries to $OUT_DIR/$subdir/"
done
