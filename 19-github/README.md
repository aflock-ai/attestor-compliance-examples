# 19 — `github` ✅ validated against real infrastructure

Real GitHub Actions OIDC token issued by `token.actions.githubusercontent.com` during a workflow run on this very repo. The github attestor calls `ACTIONS_ID_TOKEN_REQUEST_URL` with the `ACTIONS_ID_TOKEN_REQUEST_TOKEN` bearer and verifies the JWT against the public JWKS.

## Predicate excerpt

```json
{
  "jwt": {
    "claims": {
      "actor": "colek42",
      "actor_id": "6634325",
      "aud": "witness",
      "base_ref": "",
      "check_run_id": "77383889307",
      "event_name": "push",
      "exp": 1779454809,
      "head_ref": "",
      "iat": 1779454509,
      "iss": "https://token.actions.githubusercontent.com",
      "job_workflow_ref": "aflock-ai/attestor-compliance-examples/.github/workflows/cilock-ci-attestors.yml@refs/heads/main",
      "job_workflow_sha": "4873ae5a76c4a2985a221ad98f10cfc90ea4f975",
      "jti": "3780d06f-fff6-431c-8955-ab6865fe5aad",
      "nbf": 1779454209,
      "ref": "refs/heads/main",
      "ref_protected": "false",
      "ref_type": "branch",
      "repository": "aflock-ai/attestor-compliance-examples",
      "repository_id": "1246284049",
      "repository_owner": "aflock-ai",
      "repository_owner_id": "255775567",
      "repository_visibility": "public",
      "run_attempt": "1",
      "run_id": "26289005397",
      "run_number": "2",
      "runner_environment": "github-hosted",
      "sha": "4873ae5a76c4a2985a221ad98f10cfc90ea4f975",
      "sub": "repo:aflock-ai/attestor-compliance-examples:ref:refs/heads/main",
      "workflow": "cilock-ci-attestors",
      "workflow_ref": "aflock-ai/attestor-compliance-examples/.github/workflows/cilock-ci-attestors.yml@refs/heads/main",
      "workflow_sha": "4873ae5a76c4a2985a221ad98f10cfc90ea4f975"
    },
    "verifiedBy": {
      "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
      "jwk": {
        "use": "sig",
        "kty": "RSA",
        "kid": "38826b17-6a30-5f9b-b169-8beb8202f723",
        "alg": "RS256",
        "n": "5Manmy-zwsk3wEftXNdKFZec4rSWENW4jTGevlvAcU9z3bgLBogQVvqYLtu9baVm2B3rfe5onadobq8po5UakJ0YsTiiEfXWdST7YI2Sdkvv-hOYMcZKYZ4dFvuSO1vQ2DgEkw
... (truncated)
```

## What we found

Real JWT claims captured from workflow run 26289005397:
- `iss`: https://token.actions.githubusercontent.com
- `repository`: aflock-ai/attestor-compliance-examples
- `workflow_ref`: aflock-ai/attestor-compliance-examples/.github/workflows/cilock-ci-attestors.yml@refs/heads/main
- `sha`: 4873ae5a76c4a2985a221ad98f10cfc90ea4f975
- `runner_environment`: github-hosted

The JWT is signed by GitHub's OIDC provider and was verified by cilock against the live JWKS at sigstore-runtime-keys-by-id.

## Reproduce

```bash
# In .github/workflows/cilock-ci-attestors.yml on a runner with id-token: write
cilock run --step github-actions-validation \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run id $GITHUB_RUN_ID"
```
