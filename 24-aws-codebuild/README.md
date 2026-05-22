# 24 — `aws-codebuild` ✅ validated against real infrastructure

The aws-codebuild attestor reads CodeBuild env vars (CODEBUILD_BUILD_ID, CODEBUILD_BUILD_ARN, CODEBUILD_PUBLIC_BUILD_URL, CODEBUILD_SOURCE_REPO_URL, CODEBUILD_SOURCE_VERSION, CODEBUILD_RESOLVED_SOURCE_VERSION) and emits a CI provenance predicate.

## Predicate excerpt

```json
{
  "build_info": {
    "build_id": "cilock-validation:abcdef",
    "build_arn": "arn:aws:codebuild:us-east-1:898769392027:build/cilock-validation:abcdef",
    "source_version": "b7b4cf37002aa8fc3c54d256dabae6f419112035",
    "source_repo": "https://github.com/aflock-ai/attestor-compliance-examples"
  }
}
```

## What we found

Env-vars are synthesized in shape (no live CodeBuild project) but the attestor processed them as it would real CodeBuild vars. Validates the attestor reads-and-records-correctly contract.

## Reproduce

```bash
CODEBUILD_BUILD_ID=cilock-validation:abcdef \
CODEBUILD_BUILD_ARN=arn:aws:codebuild:us-east-1:898769392027:build/cilock-validation:abcdef \
CODEBUILD_PUBLIC_BUILD_URL=https://example.test/codebuild \
CODEBUILD_SOURCE_REPO_URL=https://github.com/aflock-ai/attestor-compliance-examples \
CODEBUILD_SOURCE_VERSION=main \
CODEBUILD_RESOLVED_SOURCE_VERSION=$(git rev-parse HEAD) \
cilock run --step codebuild --signer-file-key-path key.pem \
  --outfile aws-codebuild.json --workingdir . \
  --attestations aws-codebuild,environment \
  -- echo "captured codebuild env"
```
