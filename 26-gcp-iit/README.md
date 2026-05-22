# 26 — `gcp-iit` ⚠️ blocked

## Why this isn't validated against real data

Needs a real GCE VM. The gcp-iit attestor fetches an instance identity token from the GCE metadata server (http://metadata.google.internal) and verifies its signature against Google's public OIDC certs.

## Recipe (when unblocked)

```bash
# On a real GCE VM:
cilock run --step gcp-identity \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations gcp-iit \
  --attestor-gcp-iit-token-audience https://aflock.ai \
  -- echo "captured GCE identity"
```
