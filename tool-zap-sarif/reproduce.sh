#!/usr/bin/env bash
# Reproduce the validated OWASP ZAP + cilock capture.
#
# Prereqs:
#   - cilock v0.3 on PATH (or set CILOCK env var)
#   - docker installed and running
#   - the zaproxy/zap-stable image (auto-pulled if missing)
#   - an ed25519 signing key at ./key.pem (auto-generated if missing)
#
# Scans an OWASP Juice Shop instance running on localhost:3000. If no Juice
# Shop container is running, this script starts one and tears it down at the
# end. To scan a different target, edit zap-plan.yaml and skip the Juice Shop
# start/stop with: TARGET_ALREADY_RUNNING=1 ./reproduce.sh
set -euo pipefail
cd "$(dirname "$0")"

CILOCK="${CILOCK:-cilock}"
WORKDIR="$(pwd)"
JUICE_NAME="ex-zap-juice-shop"
STARTED_JUICE=0

cleanup() {
  if [ "$STARTED_JUICE" = "1" ]; then
    echo "Stopping Juice Shop ($JUICE_NAME)..."
    docker rm -f "$JUICE_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# 1. Start (or reuse) the Juice Shop target.
if [ "${TARGET_ALREADY_RUNNING:-0}" != "1" ]; then
  if ! curl -sSf -o /dev/null --max-time 3 http://localhost:3000/ 2>/dev/null; then
    echo "Starting Juice Shop on localhost:3000..."
    docker run --rm -d --name "$JUICE_NAME" -p 3000:3000 bkimminich/juice-shop >/dev/null
    STARTED_JUICE=1
    # Wait until it serves HTTP.
    for _ in $(seq 1 30); do
      curl -sSf -o /dev/null --max-time 2 http://localhost:3000/ && break
      sleep 1
    done
  fi
fi

# 2. Pull ZAP image if missing (one-time, ~2.2 GB).
docker image inspect zaproxy/zap-stable >/dev/null 2>&1 || docker pull zaproxy/zap-stable

# 3. Generate a signing key if missing.
[ -f key.pem ] || openssl genpkey -algorithm ed25519 -out key.pem

# 4. Run ZAP under cilock — direct docker invocation, no bash -c shim.
"$CILOCK" run --step zap-scan \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations sarif,environment,git \
  --enable-archivista=false \
  -- docker run --rm --network host \
       -v "$WORKDIR:/zap/wrk/:rw" \
       zaproxy/zap-stable \
       zap.sh -cmd -autorun /zap/wrk/zap-plan.yaml

# 5. Validate.
echo
echo "Predicate types in envelope:"
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'

echo
echo "command-run argv:"
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type=="https://aflock.ai/attestations/command-run/v0.1") | .attestation.cmd'

echo
echo "SARIF finding count: $(jq '.runs[0].results | length' zap.sarif.json)"
echo "ZAP tool/version:    $(jq -r '.runs[0].tool.driver.name + " " + .runs[0].tool.driver.version' zap.sarif.json)"
