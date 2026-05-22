# 24 — `aws-codebuild` ⚠️ blocked on infra (recipe validated by shape)

Captures AWS CodeBuild project execution metadata (build ID, ARN, source
version, source repo, webhook trigger, batch build ID, AWS region) and
emits an `https://aflock.ai/attestations/aws-codebuild/v0.1` predicate.
When the cilock process can call back into CodeBuild's BatchGetBuilds API
(via the build's IAM service role), the attestor enriches the predicate
with the full `aws/codebuild/types.Build` object — image, source location,
artifact target, environment variables, phase timings, exit code.

## Status

⚠️ **Not validated end-to-end against a live build** in `testifysec-demo`
because there is no CodeBuild service role provisioned in the account. Per
repo guardrails the agent does not provision IAM roles on Cole's behalf.

Two paths exist:

- **Path A — env-var-only synthesis (works locally, no AWS resources
  needed).** Export the `CODEBUILD_*` env vars by hand and run cilock
  anywhere. The attestor reads the env, BatchGetBuilds fails for the fake
  build ID, the attestor logs a warning and continues with the env-var
  data only. Useful for testing the attestor's argv/env contract.
- **Path B — real CodeBuild build (validated shape; needs service role).**
  Run cilock from inside a CodeBuild project's buildspec. CodeBuild
  populates the env vars itself; the build role grants the attestor
  permission to call BatchGetBuilds and enrich the predicate.

## Path A: env-var-only synthesis

This is what the previous README captured. It's still a useful smoke test
for the attestor (proves it reads the env vars correctly) but does not
exercise the BatchGetBuilds enrichment path.

```bash
CODEBUILD_BUILD_ID=cilock-validation:abcdef \
CODEBUILD_BUILD_ARN=arn:aws:codebuild:us-east-1:<account-id>:build/cilock-validation:abcdef \
CODEBUILD_PUBLIC_BUILD_URL=https://example.test/codebuild \
CODEBUILD_SOURCE_REPO_URL=https://github.com/aflock-ai/attestor-compliance-examples \
CODEBUILD_SOURCE_VERSION=main \
CODEBUILD_RESOLVED_SOURCE_VERSION=$(git rev-parse HEAD) \
AWS_REGION=us-east-1 \
cilock run --step codebuild \
  --signer-file-key-path key.pem \
  --outfile aws-codebuild.json \
  --workingdir . \
  --enable-archivista=false \
  --attestations aws-codebuild,environment \
  -- echo "captured codebuild env"
```

The wrapped command is `echo` because the aws-codebuild attestor is
`prematerial` — the predicate is populated before the wrapped command
runs. In a real CodeBuild build the wrapped command is the actual build
step (compile, package, publish).

## Path B: real CodeBuild build (recipe; not yet executed)

```yaml
# buildspec.yml at the root of the source repo
version: 0.2
phases:
  pre_build:
    commands:
      # Pull cilock binary that was built with --with .../aws-codebuild.
      - curl -sLO https://github.com/aflock-ai/rookery/releases/download/v0.3.x/cilock-linux-amd64
      - chmod +x cilock-linux-amd64
      - mv cilock-linux-amd64 /usr/local/bin/cilock
      # Ephemeral signing key for the demo (use AWS KMS in production —
      # see signer-examples/aws-kms/).
      - openssl genpkey -algorithm ed25519 -out key.pem
  build:
    commands:
      - |
        cilock run --step compile \
          --signer-file-key-path key.pem \
          --outfile attestation.json \
          --attestations aws-codebuild,environment \
          --enable-archivista=false \
          -- bash -c "echo 'package main; func main(){}' > main.go && go build -o demo main.go"
artifacts:
  files:
    - attestation.json
    - demo
```

```bash
# One-time setup (requires permission to create IAM roles + CodeBuild projects)
# Per repo guardrails, this is the operator's responsibility, not the agent's.

# 1. Create a CodeBuild service role.
aws iam create-role \
  --role-name cilock-demo-codebuild-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'
aws iam attach-role-policy \
  --role-name cilock-demo-codebuild-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess
aws iam put-role-policy \
  --role-name cilock-demo-codebuild-role \
  --policy-name BatchGetBuilds \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Action":["codebuild:BatchGetBuilds"],"Resource":"*"}]
  }'

# 2. Create a tiny CodeBuild project.
aws codebuild create-project --cli-input-json '{
  "name": "cilock-demo-aws-codebuild",
  "source": {"type": "GITHUB", "location": "https://github.com/aflock-ai/attestor-compliance-examples.git", "buildspec": "24-aws-codebuild/buildspec.yml"},
  "artifacts": {"type": "NO_ARTIFACTS"},
  "environment": {"type": "LINUX_CONTAINER", "computeType": "BUILD_GENERAL1_SMALL", "image": "aws/codebuild/amazonlinux-x86_64-standard:5.0"},
  "serviceRole": "arn:aws:iam::<account-id>:role/cilock-demo-codebuild-role"
}' --profile testifysec-demo --region us-east-1

# 3. Trigger a build.
aws codebuild start-build --project-name cilock-demo-aws-codebuild --profile testifysec-demo --region us-east-1
```

## Why this shape

- **No env-var injection by the user.** When running inside a real
  CodeBuild build the `CODEBUILD_*` env vars are populated by AWS itself.
  cilock just reads them. There is no `cp` step and no shell shim that
  manufactures the env — the captured predicate's identity claims come
  directly from the CodeBuild execution environment.
- **BatchGetBuilds enriches with API truth.** Env vars can be forged on a
  shell; the BatchGetBuilds API call goes through the IAM service role
  attached to the build, so the enriched `build_details` field is what
  CodeBuild *says* about the build via its own API — independently
  verifiable later by anyone with `codebuild:BatchGetBuilds`.
- **Wrapped command is the real build step.** In Path B above the wrapped
  command is `go build`. `command-run/v0.1` records that argv. The
  product/v0.3 attestor captures the compiled `demo` binary as a Merkle
  leaf. The full chain reads: "CodeBuild project P, build B, source
  commit S, env E, ran `go build`, produced binary with hash H, all
  signed by the file signer; CodeBuild API independently corroborates
  project + build + source via BatchGetBuilds."

## Validate it locally (after Path B infra is provisioned)

```bash
# Trigger a build.
BUILD_ID=$(aws codebuild start-build --project-name cilock-demo-aws-codebuild \
  --profile testifysec-demo --region us-east-1 \
  --query 'build.id' --output text)
echo "Started build: $BUILD_ID"

# Poll for completion.
while true; do
  STATUS=$(aws codebuild batch-get-builds --ids "$BUILD_ID" \
    --profile testifysec-demo --region us-east-1 \
    --query 'builds[0].buildStatus' --output text)
  [ "$STATUS" = "IN_PROGRESS" ] || break
  sleep 10
done
echo "Build status: $STATUS"

# Pull attestation.json from CloudWatch Logs (or wherever the buildspec
# uploaded it) and inspect.
jq -r '.payload' attestation.json | base64 -d | jq '.predicate.attestations | map(.type)'
# expected (order may vary):
#   https://aflock.ai/attestations/environment/v0.1
#   https://aflock.ai/attestations/aws-codebuild/v0.1
#   https://aflock.ai/attestations/material/v0.3
#   https://aflock.ai/attestations/command-run/v0.1
#   https://aflock.ai/attestations/product/v0.3

jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | select(.type|contains("aws-codebuild")) | .attestation.build_info | {build_id, build_arn, source_version, source_repo}'
```

## Reproduce Path A (no AWS resources required)

```bash
bash reproduce.sh
```
