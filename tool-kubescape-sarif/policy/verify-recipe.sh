#!/bin/bash
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify -p "$EX/policy/policy-signed.json" -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-kubescape.json" -s "sha256:cb8883e93ade2adf7d62d86910b6f84ca31fad5c83491bfc8201991a684a172e"
