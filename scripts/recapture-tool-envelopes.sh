#!/usr/bin/env bash
# Recapture every tool-* example's signed envelope against a v0.3 cilock
# binary.
#
# Run this after merging the v0.3-cutover PR(s). The committed
# verify-recipe.sh scripts reference envelopes at
# _validation/tool-envelopes/<example>.json — this script regenerates
# those envelopes by running the documented `cilock run` invocation for
# each example.
#
# Prerequisites:
#   - cilock binary on PATH (v0.3+, i.e. built from rookery main after #136)
#   - $REPO_ROOT/_validation/key.pem exists
#   - Each tool's CLI is on PATH for the examples you want to recapture.
#     Missing tools cause that example to SKIP (logged), not fail.
#
# What it does NOT do:
#   - Does not push captured envelopes anywhere.
#   - Does not re-sign policy.json (run recapture-policy-signatures.sh for
#     that — they're independent operations).
#   - Does not run verify-recipe.sh — run that separately after this
#     script completes so you see verify against the fresh capture.
#
# Each example's recapture is a function below. Keeping them as named
# functions rather than a big table makes it easy to override individual
# tool invocations (e.g. point grype at a different image) without
# touching the dispatch loop.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VAL_DIR="$REPO_ROOT/_validation"
KEY_PEM="$VAL_DIR/key.pem"
ENVELOPES_DIR="$VAL_DIR/tool-envelopes"
WORK_DIR="$VAL_DIR/work"

# ---------------------------------------------------------------------------
# Prereq checks
# ---------------------------------------------------------------------------

if ! command -v cilock >/dev/null 2>&1; then
  echo "error: cilock not found on PATH" >&2
  exit 2
fi

if [ ! -f "$KEY_PEM" ]; then
  echo "error: signing key not found at $KEY_PEM" >&2
  exit 2
fi

# Sanity-check cilock version supports v0.3.
ATTESTORS_OUT="$(cilock attestors list 2>&1)"
if ! grep -qF "attestations/product/v0.3" <<<"$ATTESTORS_OUT"; then
  echo "error: cilock binary does not appear to support product/v0.3" >&2
  echo "       build from rookery main (post #136) and put it on PATH." >&2
  exit 2
fi

mkdir -p "$ENVELOPES_DIR" "$WORK_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# Validate that the produced attestation envelope is v0.3-shaped: must
# carry the product/v0.3 predicate type in its in-toto Statement payload.
# Catches the case where someone runs an older cilock by accident.
validate_v03() {
  local envelope="$1"
  if ! python3 - "$envelope" <<'PY' >/dev/null 2>&1; then
import json, base64, sys
env = json.load(open(sys.argv[1]))
payload = json.loads(base64.b64decode(env['payload']))
seen = set()
for att in payload.get('predicate', {}).get('attestations', []):
    seen.add(att.get('type', ''))
required = 'https://aflock.ai/attestations/product/v0.3'
sys.exit(0 if required in seen else 1)
PY
    echo "error: envelope $envelope does not carry product/v0.3 predicate type" >&2
    return 1
  fi
}

# Run a tool-example recapture. Args:
#   $1 — example dir name (e.g. tool-syft-sbom)
#   $2 — name of the tool binary that must be on PATH to recapture
#   $3 — short tag for the envelope filename (e.g. tool-syft)
#   $4..N — the actual cilock run command (as separate args)
run_example() {
  local example="$1"; shift
  local tool="$1"; shift
  local tag="$1"; shift
  local outfile="$ENVELOPES_DIR/$tag.json"

  if ! have "$tool"; then
    echo "skip:   $example ($tool not on PATH)"
    skipped=$((skipped+1))
    return 0
  fi

  echo "run:    $example"
  pushd "$WORK_DIR" >/dev/null
  if "$@" >/dev/null 2>&1; then
    if validate_v03 "$outfile"; then
      echo "  -> $outfile (v0.3 OK)"
      captured=$((captured+1))
    else
      errored=$((errored+1))
    fi
  else
    echo "error:  $example (cilock run failed)" >&2
    errored=$((errored+1))
  fi
  popd >/dev/null
}

captured=0
skipped=0
errored=0

# ---------------------------------------------------------------------------
# Per-example recaptures
#
# Each block mirrors the "## Validated invocation" block from that
# example's README. If a tool needs a specific target (image, file, etc.),
# pick something stable and document it in the comment.
# ---------------------------------------------------------------------------

# tool-syft-sbom: syft against alpine:3.20 (stable, small image).
recap_syft() {
  syft alpine:3.20 -o cyclonedx-json="$WORK_DIR/alpine.cdx.json" >/dev/null 2>&1
  run_example tool-syft-sbom syft tool-syft \
    cilock run --step syft-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-syft.json" \
      --workingdir "$WORK_DIR" \
      --attestations sbom,environment \
      -- bash -c "cp $WORK_DIR/alpine.cdx.json $WORK_DIR/syft-product.json"
}

# tool-gosec-sarif: gosec against the current repo.
recap_gosec() {
  ( cd "$WORK_DIR" && gosec -fmt=sarif -out=gosec.sarif "$REPO_ROOT/..." ) >/dev/null 2>&1 || true
  run_example tool-gosec-sarif gosec tool-gosec \
    cilock run --step gosec-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-gosec.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/gosec.sarif $WORK_DIR/gosec-product.sarif"
}

# tool-grype-sarif: grype against alpine:3.20.
recap_grype() {
  grype alpine:3.20 -o sarif --file "$WORK_DIR/grype.sarif" >/dev/null 2>&1 || true
  run_example tool-grype-sarif grype tool-grype \
    cilock run --step grype-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-grype.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/grype.sarif $WORK_DIR/grype-product.sarif"
}

# tool-hadolint-sarif: needs a Dockerfile.
recap_hadolint() {
  printf 'FROM alpine:3.20\nRUN echo hello\n' > "$WORK_DIR/Dockerfile"
  hadolint -f sarif "$WORK_DIR/Dockerfile" > "$WORK_DIR/hadolint.sarif" 2>/dev/null || true
  run_example tool-hadolint-sarif hadolint tool-hadolint \
    cilock run --step hadolint-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-hadolint.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/hadolint.sarif $WORK_DIR/hadolint-product.sarif"
}

# tool-kubescape-sarif: needs a deploy.yaml input.
recap_kubescape() {
  cat > "$WORK_DIR/deploy.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
  - name: c
    image: alpine:3.20
    command: ["sleep", "60"]
YAML
  kubescape scan "$WORK_DIR/deploy.yaml" --format sarif --output "$WORK_DIR/kubescape.sarif" >/dev/null 2>&1 || true
  run_example tool-kubescape-sarif kubescape tool-kubescape \
    cilock run --step kubescape-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-kubescape.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/kubescape.sarif $WORK_DIR/kubescape-product.sarif"
}

# tool-osv-scanner-sarif: scan the repo root for OSV-known issues.
recap_osv_scanner() {
  ( cd "$WORK_DIR" && osv-scanner --format sarif --output osv.sarif "$REPO_ROOT" ) >/dev/null 2>&1 || true
  run_example tool-osv-scanner-sarif osv-scanner tool-osv-scanner \
    cilock run --step osv-scanner-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-osv-scanner.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/osv.sarif $WORK_DIR/osv-scanner-product.sarif"
}

# tool-semgrep-sarif: needs auto-config + the repo as scan target.
recap_semgrep() {
  ( cd "$WORK_DIR" && semgrep scan --config=auto --sarif --output semgrep.sarif --error-only "$REPO_ROOT" ) >/dev/null 2>&1 || true
  run_example tool-semgrep-sarif semgrep tool-semgrep \
    cilock run --step semgrep-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-semgrep.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/semgrep.sarif $WORK_DIR/semgrep-product.sarif"
}

# tool-checkov-sarif: needs at least one IaC file to scan.
recap_checkov() {
  printf 'resource "null_resource" "x" {}\n' > "$WORK_DIR/main.tf"
  ( cd "$WORK_DIR" && checkov -d . --output sarif --output-file-path checkov-output ) >/dev/null 2>&1 || true
  run_example tool-checkov-sarif checkov tool-checkov \
    cilock run --step checkov-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-checkov.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/checkov-output/results_sarif.sarif $WORK_DIR/checkov-product.sarif"
}

# tool-govulncheck-sarif: needs a Go module.
recap_govulncheck() {
  ( cd "$WORK_DIR" && govulncheck -format=sarif "$REPO_ROOT/..." > govulncheck.sarif ) 2>/dev/null || true
  run_example tool-govulncheck-sarif govulncheck tool-govulncheck \
    cilock run --step govulncheck-scan \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$ENVELOPES_DIR/tool-govulncheck.json" \
      --workingdir "$WORK_DIR" \
      --attestations sarif,environment \
      -- bash -c "cp $WORK_DIR/govulncheck.sarif $WORK_DIR/govulncheck-product.sarif"
}

# 28-prowler: special case. Requires AWS credentials. We capture a
# pre-recorded prowler-out.json instead of running real prowler. This
# matches the README's documented offline path.
recap_prowler() {
  if [ ! -f "$REPO_ROOT/28-prowler/prowler-out.json" ]; then
    echo "skip:   28-prowler (no pre-recorded prowler-out.json in checkout)"
    skipped=$((skipped+1))
    return 0
  fi
  run_example 28-prowler bash prowler-real \
    cilock run --step prowler-real \
      --signer-file-key-path "$KEY_PEM" \
      --outfile "$WORK_DIR/prowler-real.json" \
      --workingdir "$REPO_ROOT/28-prowler" \
      --attestations prowler,environment \
      -- bash -c "cp $REPO_ROOT/28-prowler/prowler-out.json $WORK_DIR/prowler-out.json"
}

recap_syft        || true
recap_gosec       || true
recap_grype       || true
recap_hadolint    || true
recap_kubescape   || true
recap_osv_scanner || true
recap_semgrep     || true
recap_checkov     || true
recap_govulncheck || true
recap_prowler     || true

echo
echo "summary: $captured captured, $skipped skipped (tool not on PATH), $errored errored"
[ "$errored" -eq 0 ]
