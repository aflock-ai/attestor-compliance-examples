#!/bin/bash
# Validated verify recipe for hadolint.
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify \
  -p "$EX/policy/policy-signed.json" \
  -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-hadolint.json" \
  -s "sha256:2d7c53dd9f852681908a744dbee067bccbe30978bee10d2b6e924560b1bc0dbd"
