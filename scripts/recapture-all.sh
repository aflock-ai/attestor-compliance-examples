#!/usr/bin/env bash
# Top-level recapture orchestrator. Runs the two recapture stages in order,
# then re-runs every verify-recipe.sh so the operator sees end-to-end
# pass/fail against the freshly captured envelopes.
#
# Run this from the repo root after merging the v0.3 cutover PRs and
# building a v0.3 cilock binary.
#
#   $ ./scripts/recapture-all.sh
#
# Exits non-zero on the first hard error. Tool-skip events (a missing
# scanner binary) are logged but do not abort the run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "=== 1/3: recapture tool envelopes (needs each tool's CLI on PATH) ==="
bash "$SCRIPT_DIR/recapture-tool-envelopes.sh"
echo

echo "=== 2/3: re-sign every policy.json -> policy-signed.json ==="
bash "$SCRIPT_DIR/recapture-policy-signatures.sh"
echo

echo "=== 3/3: re-run every verify-recipe.sh ==="
shopt -s nullglob
failures=0
recipes_run=0
for recipe in */policy/verify-recipe.sh; do
  recipes_run=$((recipes_run+1))
  echo "--- $recipe ---"
  if bash "$recipe"; then
    echo "PASS: $recipe"
  else
    echo "FAIL: $recipe" >&2
    failures=$((failures+1))
  fi
done

echo
echo "summary: $recipes_run recipes run, $failures failed"
[ "$failures" -eq 0 ]
