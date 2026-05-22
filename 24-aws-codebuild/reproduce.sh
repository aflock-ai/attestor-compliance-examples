#!/bin/bash
# Path A: env-var-only smoke test of the aws-codebuild attestor.
# Works on any machine — no CodeBuild resources required.
# See README.md for Path B (real CodeBuild build) which requires a
# CodeBuild service role provisioned in the target account.
set -euo pipefail

: "${ACCOUNT_ID:=898769392027}"

CODEBUILD_BUILD_ID=cilock-validation:abcdef \
CODEBUILD_BUILD_ARN="arn:aws:codebuild:us-east-1:${ACCOUNT_ID}:build/cilock-validation:abcdef" \
CODEBUILD_PUBLIC_BUILD_URL=https://example.test/codebuild \
CODEBUILD_SOURCE_REPO_URL=https://github.com/aflock-ai/attestor-compliance-examples \
CODEBUILD_SOURCE_VERSION=main \
CODEBUILD_RESOLVED_SOURCE_VERSION="$(git rev-parse HEAD)" \
AWS_REGION=us-east-1 \
cilock run --step codebuild \
  --signer-file-key-path key.pem \
  --outfile aws-codebuild.json \
  --workingdir . \
  --enable-archivista=false \
  --attestations aws-codebuild,environment \
  -- echo "captured codebuild env"
