#!/bin/bash
# Validated verify recipe for grype.
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify \
  -p "$EX/policy/policy-signed.json" \
  -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-grype.json" \
  -s "sha256:778a02ca8f16cc50fd1be1e951565ba7d45384f58a067990ebab3602955bf9fb"
