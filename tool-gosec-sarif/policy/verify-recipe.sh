#!/bin/bash
# Validated verify recipe for gosec.
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify \
  -p "$EX/policy/policy-signed.json" \
  -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-gosec.json" \
  -s "sha256:60a29651226db12ff495183d363a895fe2745e4cb3403502bf1fe3317988dc4d"
