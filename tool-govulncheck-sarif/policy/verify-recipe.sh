#!/bin/bash
set -euo pipefail
EX="$(cd "$(dirname "$0")/.." && pwd)"
VAL="$EX/../_validation"
cilock sign -k "$VAL/key.pem" -f "$EX/policy/policy.json" -o "$EX/policy/policy-signed.json"
cilock verify -p "$EX/policy/policy-signed.json" -k "$VAL/key.pub" \
  -a "$VAL/tool-envelopes/tool-govulncheck.json" -s "sha256:79104291fc0c71d8af55c4e977ff3dbf28c2097740be335c818ee60cfb3344e2"
