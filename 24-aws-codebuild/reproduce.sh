#!/bin/bash
# Reproduce the aws-codebuild attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
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
