#!/usr/bin/env bash
# Run validate-example.sh against every example, then emit a top-level
# status table. Intended as both a CI smoke test and a maintainer-side
# "did anything break" sanity check.
#
# Usage: ./scripts/validate-all-examples.sh
#
# Exits 0 if every example either passes or has a non-failure skip
# reason. Exits non-zero if any example status starts with "fail:".

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Discover every example dir. Portable to bash 3 on macOS — no mapfile.
EXAMPLES=$(ls -d [0-9]* tool-* signer-examples/aws-kms multi-step-attestationsFrom 2>/dev/null)

failures=()
oks=0
skips=0
fails=0

for ex in $EXAMPLES; do
  [ -d "$ex" ] || continue
  status=$(bash "$SCRIPT_DIR/validate-example.sh" "$ex" 2>&1 | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['status'])" 2>/dev/null || echo "PARSE_FAIL")
  printf "%-40s %s\n" "$ex" "$status"
  case "$status" in
    ok) oks=$((oks+1)) ;;
    skip:*) skips=$((skips+1)) ;;
    *) fails=$((fails+1)); failures+=("$ex: $status") ;;
  esac
done

echo
echo "summary: $oks ok, $skips skipped, $fails failed"
if [ "${#failures[@]}" -gt 0 ]; then
  echo
  echo "failures:"
  for f in "${failures[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
