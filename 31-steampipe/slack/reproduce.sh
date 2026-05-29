#!/usr/bin/env bash
# Full cilock cycle for the Slack workspace-posture recipe: CAPTURE the posture
# with Steampipe under cilock, then VERIFY it against our NIST 800-171 Rego gate
# — all through cilock.
#
# Prerequisites:
#   - cilock built with the `steampipe` attestor (it is in the default build).
#   - steampipe + the slack plugin: `steampipe plugin install slack`, and a
#     connection config at ~/.steampipe/config/slack.spc:
#         connection "slack" { plugin = "slack"  token = "xoxp-..." }
#     A read-only user token with users:read + channels:read + groups:read is
#     enough for member posture. (Channel posture additionally needs im:read +
#     mpim:read because steampipe's slack_conversation table lists all
#     conversation types — see README; collect.sh degrades gracefully without.)
#   - openssl, jq.
#
# Usage:  ./reproduce.sh
#
# PRIVACY: a real run captures your workspace's member/channel posture into
# attestation.json. Do NOT commit it. The committed raw/ sample is synthetic.
#
# Exit semantics: a non-compliant workspace DENIES (the gate blocks) — that is
# the expected, useful outcome. The script reports the verdict either way.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

CILOCK="${CILOCK:-cilock}"

openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
openssl pkey -in key.pem -pubout -out key.pub 2>/dev/null

# ── CAPTURE ───────────────────────────────────────────────────────────────
# cilock wraps collect.sh, which runs the steampipe query pack and writes one
# JSON product per query. The steampipe attestor (postproduct) seals the rows
# INSIDE the collection — not as a sidecar — so the policy step below can
# require steampipe/v0.1 directly. (Sidecar export is opt-in:
# --attestor-steampipe-export.)
"$CILOCK" run --step slack-posture \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations steampipe,environment \
  --enable-archivista=false \
  -- bash collect.sh

echo "== Captured attestation types =="
jq -r '.payload' attestation.json | base64 -d | jq '[.predicate.attestations[].type]'

# ── BUILD + SIGN THE POLICY ─────────────────────────────────────────────────
# The functionary trusts the key that signed the collection; read the keyid back
# from the envelope rather than guessing.
KEYID=$(jq -r '.signatures[0].keyid' attestation.json)
jq -n \
  --arg keyid "$KEYID" \
  --arg key "$(base64 < key.pub | tr -d '\n')" \
  --arg slack "$(base64 < policy/slack_posture.rego | tr -d '\n')" \
  '{
    expires:"2027-12-31T23:59:59Z", name:"slack-posture-nist-800-171", roots:{},
    publickeys: { ($keyid): { keyid:$keyid, key:$key } },
    steps: { "slack-posture": {
      name:"slack-posture",
      attestations:[
        {type:"https://aflock.ai/attestations/steampipe/v0.1",
         regopolicies:[{name:"slack-posture-nist-800-171", module:$slack}]}
      ],
      functionaries:[{type:"publickey", publickeyid:$keyid}]
    }}
  }' > policy.json

"$CILOCK" sign -k key.pem -f policy.json -o policy-signed.json

# ── VERIFY ──────────────────────────────────────────────────────────────────
# Anchor on the captured product file's digest. The product/v0.3 attestation
# inlines its Merkle leaves, so cilock bridges this file digest to the
# `tree:products` root, finds the `slack-posture` collection, and evaluates the
# Rego over the in-collection steampipe rows.
SUBJECT="sha256:$(jq -r '.payload' attestation.json | base64 -d \
  | jq -r '.predicate.attestations[] | select(.type|endswith("product/v0.3")) | .attestation.leaves[0].fileDigest')"

echo "== cilock verify (policy gate over the signed collection) =="
if "$CILOCK" verify -p policy-signed.json -k key.pub -a attestation.json -s "$SUBJECT"; then
  echo "RESULT: PASS — workspace is compliant; the release gate would allow."
else
  echo "RESULT: DENIED — the gate would block. The deny reasons above are the failing controls."
fi

# ── OFFLINE DEMO (no workspace needed) ───────────────────────────────────────
echo
echo "== Offline: the same Rego over the synthetic non-compliant sample =="
opa eval -d policy/slack_posture.rego -i raw/sample-steampipe-input.json \
  'data.slack_posture.deny' --format pretty
