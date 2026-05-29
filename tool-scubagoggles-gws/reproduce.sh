#!/usr/bin/env bash
# Full cycle for the scubagoggles example: CREATE the attestation, then VERIFY
# it against our Common Controls policy — all through cilock.
#
# Prerequisites:
#   - cilock built with the `scubagoggles` attestor (it is in cmd/cilock's
#     import list; `go build ./cmd/cilock`)
#   - ScubaGoggles installed: `pip install scubagoggles` (a Python package, not
#     a binary), then `scubagoggles getopa` to fetch OPA
#   - A GCP OAuth client credentials.json + a one-time browser sign-in as a
#     Workspace super-admin (token caches next to the credentials file, so this
#     runs headless thereafter). A domain-wide-delegation service account with
#     `--subjectemail` also works.
#   - openssl, jq
#
# Usage:
#   CREDS=/path/to/credentials.json ./reproduce.sh
#
# PRIVACY: this collects your tenant's real configuration into attestation.json.
# Do NOT commit that file (or the generated policy*.json) to a public repo — it
# carries your live GWS settings. The committed raw/sample-provider-input.json
# is SYNTHETIC, used only for the offline demo at the end.
#
# Exit semantics: a non-compliant tenant DENIES (gate blocks) — that's the
# expected, useful outcome here. The script reports the verdict either way.
set -uo pipefail

: "${CREDS:?CREDS must point to your scubagoggles OAuth credentials.json}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

openssl genpkey -algorithm ed25519 -out key.pem
openssl pkey -in key.pem -pubout -out key.pub
mkdir -p out

# ── CREATE ──────────────────────────────────────────────────────────────
# cilock wraps scubagoggles directly; the postproduct scubagoggles attestor
# captures the RAW provider config (not ScubaGoggles' verdict).
cilock run --step gws-assessment \
  --signer-file-key-path key.pem \
  --outfile attestation.json \
  --attestations scubagoggles,environment \
  --enable-archivista=false \
  -- scubagoggles gws -b commoncontrols gmail drive -c "$CREDS" -o ./out --quiet

echo "== Captured facts, not a verdict (leakedVerdict must be false) =="
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|endswith("scubagoggles/v0.1")) | .attestation.predicate
        | {tenantId, domainName, orgUnits:(.orgUnits|length), leakedVerdict:(.config|has("Results"))}'

# ── BUILD + SIGN THE POLICY ─────────────────────────────────────────────
# The functionary trusts the key that signed the attestation; cilock records
# that keyid in the envelope signature, so read it back rather than guessing.
KEYID=$(jq -r '.signatures[0].keyid' attestation.json)
jq -n \
  --arg keyid "$KEYID" \
  --arg key "$(base64 < key.pub | tr -d '\n')" \
  --arg cc "$(base64 < policy/gws_commoncontrols.rego | tr -d '\n')" \
  --arg gmail "$(base64 < policy/gws_gmail.rego | tr -d '\n')" \
  --arg drive "$(base64 < policy/gws_drive.rego | tr -d '\n')" \
  '{
    expires:"2027-12-31T23:59:59Z", name:"gws-nist-800-171-validation-v1", roots:{},
    publickeys: { ($keyid): { keyid:$keyid, key:$key } },
    steps: { "gws-assessment": {
      name:"gws-assessment",
      attestations:[
        {type:"https://aflock.ai/attestations/environment/v0.1", regopolicies:[]},
        {type:"https://aflock.ai/attestations/material/v0.3",    regopolicies:[]},
        {type:"https://aflock.ai/attestations/command-run/v0.1", regopolicies:[]},
        {type:"https://aflock.ai/attestations/product/v0.3",     regopolicies:[]},
        {type:"https://aflock.ai/attestations/scubagoggles/v0.1",
         regopolicies:[
           {name:"gws-commoncontrols", module:$cc},
           {name:"gws-gmail",          module:$gmail},
           {name:"gws-drive",          module:$drive}
         ]}
      ],
      functionaries:[{type:"publickey", publickeyid:$keyid}]
    }}
  }' > policy.json

cilock sign -k key.pem -f policy.json -o policy-signed.json

# ── VERIFY ──────────────────────────────────────────────────────────────
# Use the tenant's primary domain digest as the graph entry-point subject.
DOMAIN=$(jq -r '.payload' attestation.json | base64 -d \
  | jq -r '.predicate.attestations[] | select(.type|endswith("scubagoggles/v0.1")) | .attestation.predicate.domainName')
SUBJECT="sha256:$(printf %s "$DOMAIN" | shasum -a 256 | awk '{print $1}')"

echo "== cilock verify (policy gate over the signed attestation) =="
if cilock verify -p policy-signed.json -k key.pub -a attestation.json -s "$SUBJECT"; then
  echo "RESULT: PASS — tenant is compliant, deploy/release gate would allow."
else
  echo "RESULT: DENIED — gate would block. The deny reasons above are the failing controls."
fi

# ── OFFLINE DEMO (no tenant needed) ─────────────────────────────────────
echo
echo "== Offline: same policy over the synthetic non-compliant sample =="
opa eval -d policy/gws_commoncontrols.rego -i raw/sample-provider-input.json \
  'data.gws_commoncontrols.deny' --format pretty
