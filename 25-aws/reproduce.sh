#!/bin/bash
# Reproduce the aws (EC2 IID) attestor against real infrastructure.
#
# IMPORTANT: This must run ON AN EC2 INSTANCE. The IID is fetched from IMDSv2
# at 169.254.169.254 which is not reachable from anywhere else.
#
# See README.md for the full scenario.
set -euo pipefail

# Install AWS CLI v2 if missing (Amazon Linux 2023's default awscli is broken).
if ! /usr/local/bin/aws --version >/dev/null 2>&1; then
  TMP=$(mktemp -d)
  pushd "$TMP" >/dev/null
  curl -sLO https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
  unzip -qo awscli-exe-linux-x86_64.zip
  sudo ./aws/install --update >/dev/null
  popd >/dev/null
  rm -rf "$TMP"
fi

PATH=/usr/local/bin:$PATH cilock run \
  --step ec2-identity \
  --signer-file-key-path key.pem \
  --outfile aws-iid.json \
  --workingdir . \
  --enable-archivista=false \
  --platform-url "" \
  --attestations aws,environment \
  -- bash -c "aws sts get-caller-identity --output json > caller.json"
