#!/usr/bin/env bash
# Verify the linkerd-check envelope against the signed policy.
#
# Demonstrates both:
#   POSITIVE: 15 edges, 15 mTLS-secured  → policy passes
#   NEGATIVE: 16 edges, 1 insecure       → policy denies, gate blocks deploy
set -euo pipefail
cd "$(dirname "$0")/.."

CILOCK="${CILOCK:-cilock}"

# Extract Merkle subjects from each envelope so verify can find the collection
materials_from() { jq -r '.payload' "$1" | base64 -d | jq -r '.subject[] | select(.name|endswith("materials")) | .digest.sha256'; }
products_from()  { jq -r '.payload' "$1" | base64 -d | jq -r '.subject[] | select(.name|endswith("products")) | .digest.sha256';  }

MAT1=$(materials_from raw/attestation.json)
PRD1=$(products_from  raw/attestation.json)
MAT2=$(materials_from raw/attestation-bypass.json)
PRD2=$(products_from  raw/attestation-bypass.json)

# ── POSITIVE ────────────────────────────────────────────────────────────────
echo
echo "=== POSITIVE: 15/15 edges mTLS-secured ==="
if $CILOCK verify \
     -p policy/policy-signed.json \
     -k policy/cilock.pub \
     -a raw/attestation.json \
     -s "sha256:${MAT1}" \
     -s "sha256:${PRD1}" \
     --enable-archivista=false 2>&1 | tee /tmp/linkerd-pass.log | grep -E "Verification|Step:"; then
  echo "[PASS] policy accepted the all-mTLS envelope"
else
  echo "[FAIL] expected pass"
  exit 1
fi

# ── NEGATIVE ────────────────────────────────────────────────────────────────
echo
echo "=== NEGATIVE: 1 insecure edge (out of 16) — expect deny ==="
set +e
$CILOCK verify \
  -p policy/policy-signed.json \
  -k policy/cilock.pub \
  -a raw/attestation-bypass.json \
  -s "sha256:${MAT2}" \
  -s "sha256:${PRD2}" \
  --enable-archivista=false > /tmp/linkerd-deny.log 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "insecure (non-mTLS) edge" /tmp/linkerd-deny.log; then
  echo "[PASS] policy correctly denied the bypass envelope (cilock rc=$rc)"
  echo "      $(grep -oE 'reports [0-9]+ insecure[^"]*' /tmp/linkerd-deny.log | head -1)"
else
  echo "[FAIL] expected non-zero exit + 'insecure (non-mTLS) edge'; got rc=$rc"
  cat /tmp/linkerd-deny.log
  exit 1
fi

echo
echo "[*] both checks behaved as expected."
