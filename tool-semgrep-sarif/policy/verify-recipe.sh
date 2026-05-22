#!/bin/bash
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify -p "$EX/policy/policy-signed.json" -k "$VAL/key.pub" -a "$VAL/tool-envelopes/tool-semgrep.json" -s "sha256:a88fc1c0fa6cc2a7f29d0af3c48624a9cb79c93491b07c4be27bf1d3172e0db9"
