#!/bin/bash
# Reproduce the pip-install attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
source .venv/bin/activate && cilock run --step pip-install-real \
  --signer-file-key-path key.pem --outfile pip.json --workingdir . \
  --attestations pip-install,environment \
  -- bash -c "pip install --quiet httpx && pip list --format=json > pip-list.json"
