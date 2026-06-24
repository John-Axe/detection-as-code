#!/usr/bin/env bash
# Convert every Sigma rule to an Elasticsearch Lucene query and write the
# result to build/<rule-stem>.lucene. Acts as the CI conversion gate: if a
# rule can't be translated to the target SIEM, this fails before merge.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build"
mkdir -p "$OUT_DIR"

for rule in "$REPO_ROOT"/rules/*.yml; do
  stem="$(basename "$rule" .yml)"
  case "$rule" in
    *windows*) pipeline=(-p ecs_windows) ;;
    *)         pipeline=(--without-pipeline) ;;
  esac
  echo "Converting $stem -> build/$stem.lucene"
  sigma convert -t lucene "${pipeline[@]}" "$rule" > "$OUT_DIR/$stem.lucene"
done

echo "Wrote $(ls "$OUT_DIR"/*.lucene | wc -l) converted queries to $OUT_DIR/"
