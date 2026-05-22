# 22 — `gitlab` ⚠️ doc-only

## Why this isn't validated against real data

Requires a real GitLab CI runner. The gitlab attestor reads GitLab-specific env vars (CI_PIPELINE_ID, CI_JOB_ID, CI_PROJECT_URL, CI_COMMIT_SHA, GITLAB_FEATURES, etc.) and fetches the GitLab OIDC JWT from `ID_TOKEN_VAR` (or `CI_JOB_JWT_V2` for older runners).

## Recipe (when unblocked)

```bash
# In a .gitlab-ci.yml job:
validate:
  image: alpine:latest
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  script:
    - cilock run --step gitlab-validation \
        --signer-file-key-path $KEY_PATH \
        --outfile attestation.json \
        --attestations environment,git,gitlab \
        -- echo "gitlab run $CI_PIPELINE_ID"
```
