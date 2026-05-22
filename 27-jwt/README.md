# 27 — `jwt` ⚠️ blocked

## Why this isn't validated against real data

Needs a real OIDC token from a provider with a public JWKS endpoint. Easiest path: `gcloud auth print-identity-token` for a Google identity token + the standard Google JWKS endpoint.

## Recipe (when unblocked)

```bash
# Real Google OIDC token (works once `gcloud auth login` is done):
TOKEN=$(gcloud auth print-identity-token --audiences https://aflock.ai)

cilock run --step jwt-validation \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations jwt \
  --attestor-jwt-token "$TOKEN" \
  --attestor-jwt-jwksurl https://www.googleapis.com/oauth2/v3/certs \
  -- echo "verified Google identity token"
```
