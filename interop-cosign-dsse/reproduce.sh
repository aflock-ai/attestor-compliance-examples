#!/usr/bin/env bash
# End-to-end validation that cilock can verify a cosign-signed DSSE attestation
# as first-class policy evidence via Policy.externalAttestations.
#
# Prereqs:
#   - cosign on PATH (tested with v3.0.2)
#   - cilock built from rookery main at v0.3 material/product (override with $CILOCK)
#   - openssl, jq
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"
command -v "$CILOCK" >/dev/null || { echo "cilock not found (set CILOCK=/path/to/cilock)"; exit 1; }
command -v cosign  >/dev/null || { echo "cosign not found"; exit 1; }

WORK="$(mktemp -d -t cilock-cosign-XXXX)"
echo "[*] work dir: $WORK"
cp hello.go predicate.json "$WORK/"
cd "$WORK"

# -----------------------------------------------------------------------------
# 1. Build the artifact under test (a real Go binary)
# -----------------------------------------------------------------------------
go build -o hello hello.go
ARTIFACT_SHA="$(shasum -a 256 hello | awk '{print $1}')"
echo "[*] artifact sha256: $ARTIFACT_SHA"

# -----------------------------------------------------------------------------
# 2. Generate cosign + cilock key pairs
# -----------------------------------------------------------------------------
COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1
openssl genpkey -algorithm ed25519 -out cilock-key.pem 2>/dev/null
openssl pkey -pubout -in cilock-key.pem -out cilock-pub.pem

COSIGN_KEYID="$(shasum -a 256 cosign.pub | awk '{print $1}')"
CILOCK_KEYID="$(shasum -a 256 cilock-pub.pem | awk '{print $1}')"
echo "[*] cosign keyid: $COSIGN_KEYID"
echo "[*] cilock keyid: $CILOCK_KEYID"

# -----------------------------------------------------------------------------
# 3. cosign attests the artifact (SLSA Provenance v0.2 predicate, DSSE envelope)
# -----------------------------------------------------------------------------
COSIGN_PASSWORD="" cosign attest-blob \
  --key cosign.key \
  --predicate predicate.json \
  --type slsaprovenance \
  --output-attestation /dev/null \
  --new-bundle-format=false \
  --use-signing-config=false \
  --tlog-upload=false \
  --yes \
  hello > cosign-dsse.json 2>/dev/null

# -----------------------------------------------------------------------------
# 4. cilock attests the build step (collection envelope)
# -----------------------------------------------------------------------------
$CILOCK run --step build \
  --signer-file-key-path cilock-key.pem \
  --outfile cilock-attestation.json \
  --attestations environment,material,product \
  --enable-archivista=false \
  -- go build -o hello-cilock hello.go >/dev/null 2>&1

# Pull the Merkle subjects out of the cilock collection so verify can find it.
MATERIALS=$(jq -r '.payload' cilock-attestation.json | base64 -d | jq -r '.subject[] | select(.name|endswith("materials")) | .digest.sha256')
PRODUCTS=$(jq -r '.payload' cilock-attestation.json | base64 -d | jq -r '.subject[] | select(.name|endswith("products")) | .digest.sha256')

# -----------------------------------------------------------------------------
# 5. Build the policy: build-step uses cilock key, external SLSA uses cosign key
# -----------------------------------------------------------------------------
CILOCK_KEY_B64=$(base64 -i cilock-pub.pem | tr -d '\n')
COSIGN_KEY_B64=$(base64 -i cosign.pub | tr -d '\n')

cat > policy.json <<EOF
{
  "expires": "2030-01-01T00:00:00Z",
  "publickeys": {
    "${CILOCK_KEYID}": {"keyid": "${CILOCK_KEYID}", "key": "${CILOCK_KEY_B64}"},
    "${COSIGN_KEYID}": {"keyid": "${COSIGN_KEYID}", "key": "${COSIGN_KEY_B64}"}
  },
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [{"publickeyid": "${CILOCK_KEYID}"}],
      "attestations": [
        {"type": "https://aflock.ai/attestations/environment/v0.1"},
        {"type": "https://aflock.ai/attestations/material/v0.3"},
        {"type": "https://aflock.ai/attestations/command-run/v0.1"},
        {"type": "https://aflock.ai/attestations/product/v0.3"}
      ]
    }
  },
  "externalAttestations": {
    "slsa-provenance-from-cosign": {
      "name": "slsa-provenance-from-cosign",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "required": true,
      "functionaries": [{"publickeyid": "${COSIGN_KEYID}"}]
    }
  }
}
EOF

$CILOCK sign --signer-file-key-path cilock-key.pem -f policy.json -o policy-signed.json >/dev/null 2>&1

# -----------------------------------------------------------------------------
# 6. POSITIVE — both envelopes present, expect pass
# -----------------------------------------------------------------------------
echo
echo "=== POSITIVE: cilock collection + cosign DSSE both present ==="
if $CILOCK verify \
     -p policy-signed.json \
     -k cilock-pub.pem \
     -a cilock-attestation.json \
     -a cosign-dsse.json \
     -f hello \
     -s "sha256:${MATERIALS}" \
     -s "sha256:${PRODUCTS}" \
     --enable-archivista=false 2>&1 | tee verify-pass.log | grep -E "Verification|Step:|Reason"; then
  echo "[PASS] policy accepted the cosign DSSE as required external evidence"
else
  echo "[FAIL] expected pass"
  exit 1
fi

# -----------------------------------------------------------------------------
# 7. NEGATIVE 1 — cosign envelope absent, expect missing-required failure
# -----------------------------------------------------------------------------
echo
echo "=== NEGATIVE 1: drop cosign DSSE ==="
set +e
$CILOCK verify \
     -p policy-signed.json \
     -k cilock-pub.pem \
     -a cilock-attestation.json \
     -f hello \
     -s "sha256:${MATERIALS}" \
     -s "sha256:${PRODUCTS}" \
     --enable-archivista=false > verify-missing.log 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "not found" verify-missing.log; then
  echo "[PASS] policy correctly rejects: external attestation not found (cilock rc=$rc)"
else
  echo "[FAIL] expected non-zero exit + 'not found'; got rc=$rc"; cat verify-missing.log; exit 1
fi

# -----------------------------------------------------------------------------
# 8. NEGATIVE 2 — tampered cosign signature, expect functionary-mismatch failure
# -----------------------------------------------------------------------------
echo
echo "=== NEGATIVE 2: tamper cosign signature ==="
jq '.signatures[0].sig = "MEYCIQDDtampered00000000000000000000000000000000IhAOtampered000000000000000000000000000000=="' \
   cosign-dsse.json > cosign-dsse-tampered.json
set +e
$CILOCK verify \
     -p policy-signed.json \
     -k cilock-pub.pem \
     -a cilock-attestation.json \
     -a cosign-dsse-tampered.json \
     -f hello \
     -s "sha256:${MATERIALS}" \
     -s "sha256:${PRODUCTS}" \
     --enable-archivista=false > verify-tampered.log 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]] && grep -q "rejected by" verify-tampered.log; then
  echo "[PASS] policy correctly rejects tampered cosign signature (cilock rc=$rc)"
else
  echo "[FAIL] expected non-zero exit + 'rejected by'; got rc=$rc"; cat verify-tampered.log; exit 1
fi

echo
echo "[*] all three checks behaved as expected. evidence in $WORK"
