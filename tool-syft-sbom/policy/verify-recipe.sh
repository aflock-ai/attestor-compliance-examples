#!/bin/bash
# Validated verify recipe for syft.
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify \
  -p "$EX/policy/policy-signed.json" \
  -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-syft.json" \
  -s "sha256:a1464d90a4a3b9eaf124e7c7941c1cdb8b821b2da0071c9784249597f440f1c2"
