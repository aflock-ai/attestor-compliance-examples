# `scripts/` — recapture + re-sign automation

These scripts automate the maintainer-side work of regenerating the
committed example artifacts after a cilock version bump (or after editing
a policy.json by hand).

They assume:

- A v0.3 cilock binary is on `$PATH` (built from `aflock-ai/rookery` main
  after `rookery#136`).
- `_validation/key.pem` (gitignored) exists in the repo root with the
  maintainer's signing key.
- For tool envelopes: the scanner CLIs (`syft`, `gosec`, `grype`, …) are
  installed locally. Missing tools cause the affected example to SKIP,
  not fail.

## Workflow

The intended use is:

```bash
# After merging the v0.3 cutover PRs and building v0.3 cilock:
./scripts/recapture-all.sh
```

That orchestrator runs the three stages below in order. You can also run
them individually.

### Stage 1: `recapture-tool-envelopes.sh`

Walks every `tool-*` example, runs its documented `cilock run`
invocation against a stable target (e.g. `alpine:3.20` for the container
scanners), and writes the resulting signed envelope to
`_validation/tool-envelopes/<example>.json` — which is where each
`verify-recipe.sh` expects to find it.

Per-example invocations are defined as named bash functions
(`recap_syft`, `recap_gosec`, …) inside the script so it's easy to
override a single example's target (e.g. point grype at a different
image) without touching the dispatch loop.

Each generated envelope is validated as v0.3-shaped before the script
moves on. A v0.2 or v0.1 envelope produced by a stale cilock binary
fails the script loudly rather than silently writing a non-conforming
capture.

### Stage 2: `recapture-policy-signatures.sh`

Runs `cilock sign -k _validation/key.pem -f policy.json -o
policy-signed.json` for every example with a `policy.json`. This is a
pure transformation — no tool prerequisites and no captures needed.

You can run this stage alone any time you edit a `policy.json` by hand.

### Stage 3: re-run every `verify-recipe.sh`

Confirms the freshly captured envelopes verify against the freshly
signed policies. Failures here mean either:

- the policy.json change broke the contract (intended? double-check),
- the v0.3 envelope shape isn't what the policy expected (drift between
  the policy and the producing attestor), or
- a Rego rule denies on the new envelope data (your scan results
  legitimately tripped a gate).

## Why the scripts are this verbose

Inlining the per-example `cilock run` invocations in a single
top-level script makes the recapture reproducible without re-reading
every example's README to find the documented invocation. It also makes
it possible to flip the whole repo from one cilock version to another
with a single command — the failure mode is "everything fails" or
"everything passes," not "11 of 13 silently pass because someone forgot
to recapture example #7."

## What these scripts do NOT do

- Do not push captured envelopes anywhere. Inspect them locally first.
- Do not upload to Archivista. Bundle/upload is a separate flow.
- Do not regenerate `_validation/key.pub`. That file is committed; if
  the maintainer rotates `key.pem`, `key.pub` must be regenerated and
  committed in the same PR.
