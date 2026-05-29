#!/usr/bin/env bash
# The program cilock wraps: run the Slack posture query pack and write one JSON
# product per query. Steampipe authenticates from its own connection config
# (~/.steampipe/config/slack.spc) — no token in argv or env, so nothing secret
# lands in the command-run record.
#
# Run from this directory (reproduce.sh does); products land in ./out for the
# product/v0.3 Merkle tree to hash.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

# Member posture — needs users:read (always available on a posture token).
steampipe query --output json queries/slack_users.sql > out/slack_users.json

# Channel posture — steampipe's slack_conversation table lists ALL conversation
# types, so it requires im:read + mpim:read in addition to channels:read +
# groups:read. A least-privilege posture token omits the DM scopes, so this
# query may fail with missing_scope. Capture it best-effort: skip (don't fail
# the run) when the scopes aren't granted. Grant im:read + mpim:read on the app
# to gate channels live too (see README).
if steampipe query --output json queries/slack_channels.sql > out/slack_channels.json.tmp 2>/dev/null \
   && jq -e '.rows' out/slack_channels.json.tmp >/dev/null 2>&1; then
  mv out/slack_channels.json.tmp out/slack_channels.json
  echo "captured: out/slack_users.json out/slack_channels.json"
else
  rm -f out/slack_channels.json.tmp
  echo "captured: out/slack_users.json (channels skipped — needs im:read+mpim:read; see README)" >&2
fi
