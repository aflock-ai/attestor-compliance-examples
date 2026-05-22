#!/bin/bash
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify -p "$EX/policy/policy-signed.json" -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-checkov.json" -s "sha256:50742b3d1a1f52559a929fb1004ff2a0a0d2665ad719af1bcdf94bcfbb836c99"
