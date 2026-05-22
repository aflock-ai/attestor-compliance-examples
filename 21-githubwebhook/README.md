# 21 — `githubwebhook` ⚠️ blocked

## Why this isn't validated against real data

Capturing the real delivery body + HMAC signature needs the `admin:repo_hook` gh CLI scope (interactive browser flow required). The webhook IS configured on this repo (hook id 628641948) and has fired real deliveries on every push, but the gh CLI without the scope only returns delivery metadata, not bodies.

## Recipe (when unblocked)

```bash
SECRET=$(openssl rand -hex 24)
# Create temp webhook with random secret (you control)
gh api -X POST /repos/<org>/<repo>/hooks \
  --field "name=web" \
  --field "config[url]=https://webhook.site/<your-uuid>" \
  --field "config[content_type]=json" \
  --field "config[secret]=$SECRET" \
  --field "events[]=push"

# Trigger a push, then (with admin:repo_hook scope) fetch the delivery:
gh api /repos/<org>/<repo>/hooks/<hook_id>/deliveries/<delivery_id> \
  --jq '.request.payload' > webhook-body.json
DELIVERY_SIG=$(gh api /repos/<org>/<repo>/hooks/<hook_id>/deliveries/<delivery_id> \
  --jq '.request.headers."X-Hub-Signature-256"')

cilock run --step verify-webhook \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations githubwebhook,environment \
  --attestor-githubwebhook-body webhook-body.json \
  --attestor-githubwebhook-secret "$SECRET" \
  --attestor-githubwebhook-received-signature "$DELIVERY_SIG" \
  --attestor-githubwebhook-event push \
  -- echo "verified webhook"
```
