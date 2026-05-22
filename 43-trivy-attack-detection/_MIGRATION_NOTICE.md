# Migration notice — consolidated from `aflock-ai/cilock-trivy-detection-test`

This directory was the standalone repo
[`aflock-ai/cilock-trivy-detection-test`](https://github.com/aflock-ai/cilock-trivy-detection-test)
until 2026-05-22, when it was consolidated into this monorepo of examples.

## What moved

Every file (attestations, policies, test scripts, Dockerfile, entrypoint,
server.js) was copied as-is. The trivy attack reproduction still runs the
same way; only the path changed.

## What was removed

- `policy-key.pem` — the test private key was excluded from the migration.
  Test keys are regenerated per-run in this repo via `_validation/key.pem`
  (gitignored) so private material never lands in version control.

## What stays at the old path

Nothing. The old repo will be deleted; this is the canonical home.

## What downstream needs

If you have bookmarks or links to the old repo URL, update them to:

`https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection/`
