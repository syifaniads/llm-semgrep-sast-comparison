#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-vulnerable-samples}"
OUTPUT="${2:-results/semgrep_results.json}"

mkdir -p "$(dirname "$OUTPUT")"

semgrep \
  --config p/owasp-top-ten \
  --config semgrep-sast/rules \
  --json \
  --metrics=off \
  --output "$OUTPUT" \
  "$TARGET"

echo "Semgrep results written to $OUTPUT"
