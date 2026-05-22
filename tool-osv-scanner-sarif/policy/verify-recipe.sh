#!/bin/bash
# Validated verify recipe for osv-scanner.
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify \
  -p "$EX/policy/policy-signed.json" \
  -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-osv-scanner.json" \
  -s "sha256:d0dc021dadba3e334611aea82ebfae08b3af9ecbf729c6d7ad69e5d04ce1939a"
