# 20 — `github-action` ✅ validated against real infrastructure

Real GitHub Actions runtime context from the same workflow run as #19. Reads canonical GITHUB_* env vars exposed to every Actions job and records them in a predicate.

## Predicate excerpt

```json
{
  "actionref": "",
  "actiontype": "",
  "exitcode": 0,
  "runid": "26289005397",
  "workflowname": "cilock-ci-attestors",
  "jobname": "attest-github-and-github-action"
}
```

## What we found

Captured real GITHUB_RUN_ID, GITHUB_WORKFLOW, GITHUB_REPOSITORY, RUNNER_OS, RUNNER_ARCH, etc. from a live github-hosted runner.

## Reproduce

```bash
# Same workflow as #19, --attestations includes both github and github-action
cilock run --step github-actions-validation \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run"
```
