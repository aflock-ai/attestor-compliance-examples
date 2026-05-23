#!/usr/bin/env bash
# Capture a testssl.sh TLS scan under cilock against a target you control.
#
# Prereqs:
#   - testssl.sh on PATH (brew install testssl)
#   - cilock on PATH (any rookery main build)
#   - openssl, jq
#
# Usage:
#   ./reproduce.sh <target>            # e.g. ./reproduce.sh https://cilock.aflock.ai
#   ./reproduce.sh --fips <target>     # FIPS 140-2/3 mode
#   ./reproduce.sh                      # defaults to https://cilock.aflock.ai
#
# IMPORTANT: testssl.sh probes a live service on the wire. Only scan targets
# you own or have written authorization to scan. See README.md.
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"
command -v "$CILOCK" >/dev/null || { echo "cilock not found"; exit 1; }
command -v testssl.sh >/dev/null || { echo "testssl.sh not found (brew install testssl)"; exit 1; }

FIPS_FLAG=""
if [[ "${1:-}" == "--fips" ]]; then
  FIPS_FLAG="--fips"
  shift
fi

TARGET="${1:-https://cilock.aflock.ai}"
SLUG="$(echo "$TARGET" | sed -E 's|^https?://||; s|[^a-zA-Z0-9.-]|-|g; s|\.|-|g')"
OUT="${SLUG}${FIPS_FLAG:+-fips}"

[ -f key.pem ] || openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null

echo "[*] scanning $TARGET ${FIPS_FLAG} -> $OUT.json"
$CILOCK run --step testssl-scan \
  --signer-file-key-path key.pem \
  --outfile "$OUT.attestation.json" \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- testssl.sh ${FIPS_FLAG} --jsonfile-pretty "$OUT.json" --quiet "$TARGET"

echo
echo "=== Predicate types ==="
jq -r '.payload' "$OUT.attestation.json" | base64 -d | jq '.predicate.attestations | map(.type)'

echo
echo "=== Findings (severity != OK,INFO) ==="
jq '[.scanResult[0].protocols[]?, .scanResult[0].ciphers[]?, .scanResult[0].fs[]?]
    | map(select(.severity != "OK" and .severity != "INFO"))
    | .[:20]' "$OUT.json" 2>/dev/null || echo "(no findings or scan failed)"
