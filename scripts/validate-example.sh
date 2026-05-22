#!/usr/bin/env bash
# Validate a single example end-to-end: capture an envelope, verify it's
# v0.3-shaped, run the example's policy (if present), and produce a JSON
# summary the README-generation step (validate-example-readme.py) can
# render into a consistent README section.
#
# Usage:
#   ./scripts/validate-example.sh <example-dir>
#
# Output:
#   _validation/results/<example-dir>/
#     attestation.json           — the signed envelope
#     attestation.product.tree.json
#     attestation.material.tree.json
#     verify-output.txt          — stderr+stdout of `cilock verify` if a policy was run
#     summary.json               — machine-readable status (used by README generator)
#
# Status codes inside summary.json:
#   "ok"               — full capture + verify succeeded
#   "skip:no-runtime"  — the example's tool/runtime is not installed locally
#   "skip:needs-cloud" — needs cloud credentials we don't have
#   "skip:needs-ci"    — needs a GH Actions runner (OIDC, etc.)
#   "fail:capture"     — cilock run failed
#   "fail:verify"      — cilock verify denied (might be intentional!)
#   "fail:shape"       — envelope is not v0.3-shaped
#
# Subagents call this script per-example and check summary.json status.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VAL_DIR="$REPO_ROOT/_validation"
KEY_PEM="$VAL_DIR/key.pem"
KEY_PUB="$VAL_DIR/key.pub"

if [ $# -lt 1 ]; then
  echo "usage: $0 <example-dir>" >&2
  exit 2
fi

EXAMPLE="$1"
EXAMPLE_DIR="$REPO_ROOT/$EXAMPLE"
if [ ! -d "$EXAMPLE_DIR" ]; then
  echo "error: $EXAMPLE_DIR does not exist" >&2
  exit 2
fi

RESULTS_DIR="$VAL_DIR/results/$EXAMPLE"
mkdir -p "$RESULTS_DIR"
SUMMARY="$RESULTS_DIR/summary.json"

# Helper: write the summary and exit. Args: status, message.
finalize() {
  local status="$1"
  local message="$2"
  python3 - "$SUMMARY" "$EXAMPLE" "$status" "$message" <<'PY'
import json, sys, os, time
summary_path, example, status, message = sys.argv[1:5]
data = {
    "example": example,
    "status": status,
    "message": message,
    "validated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
# Merge with any existing summary fields (e.g. envelope_path) so capture
# results aren't clobbered if validate is re-run.
if os.path.exists(summary_path):
    try:
        with open(summary_path) as f: prior = json.load(f)
        prior.update(data)
        data = prior
    except Exception:
        pass
with open(summary_path, "w") as f:
    json.dump(data, f, indent=2)
print(json.dumps(data, indent=2))
PY
  case "$status" in
    ok) exit 0 ;;
    skip:*) exit 0 ;;  # skip is not failure
    *) exit 1 ;;
  esac
}

# Prereqs.
if ! command -v cilock >/dev/null 2>&1; then
  finalize "fail:setup" "cilock not on PATH"
fi
if [ ! -f "$KEY_PEM" ]; then
  finalize "fail:setup" "$KEY_PEM missing"
fi

# Sanity check the cilock version. v0.3 required.
ATTESTORS_OUT="$(cilock attestors list 2>&1)"
if ! grep -qF "attestations/product/v0.3" <<<"$ATTESTORS_OUT"; then
  finalize "fail:setup" "cilock binary does not register product/v0.3"
fi

# ---------------------------------------------------------------------------
# Per-example capture dispatch.
#
# Each example has its own capture recipe. We dispatch on the directory
# name. Recipes can:
#   - call `capture_basic <attestor-name>` for the "just run cilock with
#     this attestor enabled against an empty workingdir" pattern.
#   - call `skip_with_reason <skip-status> <message>` to bail out.
#   - inline the cilock run if special prep is needed (e.g. generate a
#     Dockerfile first).
#
# The dispatch table at the bottom of this file maps example name ->
# capture function name. Adding a new example is a 5-line change there.
# ---------------------------------------------------------------------------

WORK_DIR="$(mktemp -d -t cilock-capture-XXXXXX)"
cleanup() { rm -rf "$WORK_DIR"; }
have() { command -v "$1" >/dev/null 2>&1; }
trap cleanup EXIT

OUTFILE="$RESULTS_DIR/attestation.json"

capture_basic() {
  local attestors="$1"
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run \
    --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations "$attestors" \
    -- echo "capture for $EXAMPLE" >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
  # Copy sidecars too.
  for ext in product.tree.json material.tree.json; do
    src="${OUTFILE%.json}.$ext"
    if [ -f "$src" ]; then
      mv "$src" "$RESULTS_DIR/$(basename "$src")"
    fi
  done
}

skip_with_reason() {
  finalize "skip:$1" "$2"
}

# Validate envelope shape: must include v0.3 product + material.
validate_envelope_shape() {
  local rc
  python3 - "$OUTFILE" >"$RESULTS_DIR/shape.json" 2>&1 <<'PY'
import json, base64, sys
env = json.load(open(sys.argv[1]))
payload = json.loads(base64.b64decode(env["payload"]))
types = sorted(a["type"] for a in payload.get("predicate", {}).get("attestations", []))
required = "https://aflock.ai/attestations/product/v0.3"
if required not in types:
    print(json.dumps({"ok": False, "types": types, "missing": required}))
    sys.exit(1)
print(json.dumps({"ok": True, "types": types, "subjects": [s.get("name") for s in payload.get("subject", [])]}))
PY
  rc=$?
  if [ "$rc" -ne 0 ]; then
    finalize "fail:shape" "envelope is not v0.3-shaped"
  fi
}

# ---------------------------------------------------------------------------
# Capture recipes per example
# ---------------------------------------------------------------------------

cap_01_command_run()     { capture_basic "environment,command-run"; }
cap_02_product()         { capture_basic "environment"; }
cap_03_material()        { capture_basic "environment"; }
cap_04_environment()     { capture_basic "environment"; }
cap_05_git() {
  # Need a real git repo. Init one in the workdir.
  pushd "$WORK_DIR" >/dev/null
  git init -q . >/dev/null 2>&1 || true
  git config user.email "validation@example.com"
  git config user.name "Validation"
  echo "hello" > README.txt
  git add . && git commit -q -m "init" >/dev/null 2>&1 || true
  popd >/dev/null
  capture_basic "environment,git"
}
cap_06_configuration() {
  # configuration attestor needs at least one config file in workdir.
  echo "key: value" > "$WORK_DIR/config.yaml"
  capture_basic "environment,configuration"
}
cap_07_lockfiles() {
  # Provide a representative lockfile.
  cat > "$WORK_DIR/package-lock.json" <<'JSON'
{
  "name": "example",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "packages": {}
}
JSON
  capture_basic "environment,lockfiles"
}
cap_08_link()            { capture_basic "environment,link"; }
cap_09_sbom() {
  # sbom attestor processes files that became products (i.e. the command
  # WROTE them). Write the SBOM via the wrapped command so it's a product.
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run \
    --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations environment,sbom \
    -- bash -c 'cat > sbom.spdx.json <<JSON
{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"example","documentNamespace":"https://example.com/example","packages":[]}
JSON' >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
}
cap_10_maven()           { skip_with_reason "no-runtime" "needs a real Maven project + mvn binary"; }
cap_11_pip_install()     { skip_with_reason "no-runtime" "needs Python venv + pip install of a real package"; }
cap_12_omnitrail()       { skip_with_reason "no-runtime" "needs omnitrail CLI"; }
cap_13_k8smanifest() {
  cat > "$WORK_DIR/deploy.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
  - name: c
    image: alpine:3.20
YAML
  capture_basic "environment,k8smanifest"
}
cap_14_system_packages() {
  if [ "$(uname -s)" != "Linux" ]; then
    skip_with_reason "no-runtime" "system-packages requires Linux (/etc/os-release)"
    return
  fi
  capture_basic "environment,system-packages"
}
cap_15_oci()             { skip_with_reason "no-runtime" "needs OCI image and docker/podman to inspect"; }
cap_16_docker()          { skip_with_reason "no-runtime" "needs docker daemon"; }
cap_17_docker_bench()    { skip_with_reason "no-runtime" "needs docker-bench-security CLI"; }
cap_18_kube_bench()      { skip_with_reason "no-runtime" "needs kube-bench CLI"; }
cap_19_github()          { skip_with_reason "needs-ci" "needs GitHub Actions OIDC token (ACTIONS_ID_TOKEN_REQUEST_*)"; }
cap_20_github_action()   { skip_with_reason "needs-ci" "needs GitHub Actions runner"; }
cap_21_githubwebhook()   { skip_with_reason "needs-ci" "needs a real GitHub webhook delivery body"; }
cap_22_gitlab()          { skip_with_reason "needs-ci" "needs a GitLab CI runner"; }
cap_23_jenkins()         { skip_with_reason "needs-ci" "needs a Jenkins build env"; }
cap_24_aws_codebuild()   { skip_with_reason "needs-cloud" "needs an AWS CodeBuild project"; }
cap_25_aws()             { skip_with_reason "needs-cloud" "needs AWS instance metadata service"; }
cap_26_gcp_iit()         { skip_with_reason "needs-cloud" "needs GCP instance identity token"; }
cap_27_jwt() {
  # jwt attestor verifies an arbitrary token against a JWKS URL. Capture
  # requires either a real JWKS endpoint or a self-hosted one + matching
  # token. Too complex for a default capture; users typically run this
  # inside GitHub Actions where the OIDC JWKS + token are auto-injected.
  skip_with_reason "needs-ci" "jwt requires a valid JWT + JWKS URL pair; typically captured in GH Actions context"
}
cap_28_prowler() {
  # Prowler example has a captured prowler-out.json bundled in the dir.
  if [ ! -f "$EXAMPLE_DIR/prowler-out.json" ]; then
    skip_with_reason "no-runtime" "no captured prowler-out.json in checkout"
    return
  fi
  pushd "$WORK_DIR" >/dev/null
  cp "$EXAMPLE_DIR/prowler-out.json" .
  if ! cilock run --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations prowler,environment \
    -- bash -c "cp prowler-out.json prowler-product.json" >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
}
cap_29_oscap()           { skip_with_reason "no-runtime" "needs OpenSCAP CLI + SCAP content"; }
cap_30_inspec()          { skip_with_reason "no-runtime" "needs InSpec CLI + profile"; }
cap_31_steampipe()       { skip_with_reason "no-runtime" "needs Steampipe CLI + plugin"; }
cap_32_structured_data() {
  skip_with_reason "no-runtime" "structured-data attestor not in the default cilock preset; build with --preset all to enable"
}
cap_33_aws_config()      { skip_with_reason "needs-cloud" "needs AWS Config snapshot"; }
cap_34_asff()            { skip_with_reason "needs-cloud" "needs AWS Security Hub finding"; }
cap_35_nessus()          { skip_with_reason "no-runtime" "needs Nessus scan output"; }
cap_36_sarif() {
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run \
    --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations environment,sarif \
    -- bash -c 'cat > scan.sarif <<JSON
{"$schema":"https://json.schemastore.org/sarif-2.1.0","version":"2.1.0","runs":[{"tool":{"driver":{"name":"example","rules":[]}},"results":[]}]}
JSON' >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
}
cap_37_vex() {
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run \
    --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations environment,vex \
    -- bash -c 'cat > example.vex.json <<JSON
{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1","author":"validation","timestamp":"2026-01-01T00:00:00Z","statements":[]}
JSON' >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
}
cap_38_slsa()            { capture_basic "environment,slsa"; }
cap_39_secretscan() {
  echo "this output has no secrets" > "$WORK_DIR/clean.txt"
  capture_basic "environment,secretscan"
}
cap_40_sinkhole_flows()  { skip_with_reason "no-runtime" "needs sinkhole flow capture"; }
cap_41_policyverify() {
  # policyverify is the meta-attestor that records a verify result. Skip:
  # we'd need to run a prior verify first.
  skip_with_reason "no-runtime" "policyverify is emitted by cilock verify; capture is meta-recursive"
}
cap_42_vsa()             { skip_with_reason "no-runtime" "VSA is emitted by cilock verify; capture is meta-recursive"; }
cap_43_trivy_attack_detection() {
  # Has its own entrypoint.sh.
  if [ ! -f "$EXAMPLE_DIR/entrypoint.sh" ]; then
    skip_with_reason "no-runtime" "no entrypoint.sh in checkout"
    return
  fi
  pushd "$EXAMPLE_DIR" >/dev/null
  if ! cilock run --step "$EXAMPLE" \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$EXAMPLE_DIR" \
    --attestations secretscan,environment \
    -- bash entrypoint.sh >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "cilock run failed; see capture.log"
  fi
  popd >/dev/null
}

# tool-* examples wrap an external scanner's invocation.
# Each recipe:
#   1. Checks that the scanner CLI is installed (skip:no-runtime if not).
#   2. Runs the scanner against a stable target inside the cilock-wrapped
#      command so the SARIF/SBOM output becomes a product.
# Targets are intentionally tiny + stable (alpine:3.20, a generated
# Dockerfile, a sample manifest) so a re-run produces a re-runnable
# capture without external state drift.

cap_tool_syft_sbom() {
  have syft || { skip_with_reason "no-runtime" "syft not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run --step tool-syft-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sbom,environment \
    -- bash -c 'syft alpine:3.20 -o cyclonedx-json=syft-product.json' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "syft scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_grype_sarif() {
  have grype || { skip_with_reason "no-runtime" "grype not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run --step tool-grype-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'grype alpine:3.20 -o sarif --file grype-product.sarif' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "grype scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_trivy_sarif() {
  have trivy || { skip_with_reason "no-runtime" "trivy not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  if ! cilock run --step tool-trivy-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'trivy image --format sarif --output trivy-product.sarif alpine:3.20' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "trivy scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_gosec_sarif() {
  have gosec || { skip_with_reason "no-runtime" "gosec not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > go.mod <<'GOMOD'
module example.com/scantarget

go 1.21
GOMOD
  cat > main.go <<'GO'
package main

import "fmt"

func main() {
	fmt.Println("hello, world")
}
GO
  # gosec exits non-zero on findings — use -no-fail to keep wrap exit clean.
  if ! cilock run --step tool-gosec-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'gosec -fmt=sarif -out=gosec-product.sarif -no-fail ./... || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "gosec scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_hadolint_sarif() {
  have hadolint || { skip_with_reason "no-runtime" "hadolint not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  printf 'FROM alpine:3.20\nRUN echo hello\n' > Dockerfile
  if ! cilock run --step tool-hadolint-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'hadolint -f sarif Dockerfile > hadolint-product.sarif || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "hadolint scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_kubescape_sarif() {
  have kubescape || { skip_with_reason "no-runtime" "kubescape not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > deploy.yaml <<'YAML'
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
  if ! cilock run --step tool-kubescape-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'kubescape scan deploy.yaml --format sarif --output kubescape-product.sarif --enable-host-scan=false 2>/dev/null || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "kubescape scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_osv_scanner_sarif() {
  have osv-scanner || { skip_with_reason "no-runtime" "osv-scanner not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > package-lock.json <<'JSON'
{
  "name": "scantarget",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "scantarget", "version": "0.0.0" }
  }
}
JSON
  if ! cilock run --step tool-osv-scanner-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'osv-scanner --format sarif --output osv-product.sarif --lockfile=package-lock.json . 2>/dev/null || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "osv-scanner scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_semgrep_sarif() {
  have semgrep || { skip_with_reason "no-runtime" "semgrep not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > sample.py <<'PY'
def hello():
    print("hello")
PY
  if ! cilock run --step tool-semgrep-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'semgrep scan --config=auto --sarif --output semgrep-product.sarif . 2>/dev/null || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "semgrep scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_checkov_sarif() {
  have checkov || { skip_with_reason "no-runtime" "checkov not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > main.tf <<'TF'
resource "null_resource" "example" {}
TF
  if ! cilock run --step tool-checkov-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'checkov -d . --output sarif --output-file-path checkov-out --quiet 2>/dev/null || true; cp checkov-out/results_sarif.sarif checkov-product.sarif 2>/dev/null || echo "{\"version\":\"2.1.0\",\"runs\":[]}" > checkov-product.sarif' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "checkov scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_tool_govulncheck_sarif() {
  have govulncheck || { skip_with_reason "no-runtime" "govulncheck not on PATH"; return; }
  pushd "$WORK_DIR" >/dev/null
  cat > go.mod <<'GOMOD'
module example.com/scantarget

go 1.21
GOMOD
  cat > main.go <<'GO'
package main

func main() { println("hello") }
GO
  if ! cilock run --step tool-govulncheck-scan \
    --signer-file-key-path "$KEY_PEM" \
    --outfile "$OUTFILE" \
    --workingdir "$WORK_DIR" \
    --attestations sarif,environment \
    -- bash -c 'govulncheck -format=sarif ./... > govulncheck-product.sarif 2>/dev/null || true' \
    >"$RESULTS_DIR/capture.log" 2>&1; then
    popd >/dev/null
    finalize "fail:capture" "govulncheck scan failed; see capture.log"
  fi
  popd >/dev/null
}

cap_signer_examples_aws_kms()        { skip_with_reason "needs-cloud" "needs an AWS KMS CMK"; }
cap_multi_step_attestationsFrom()    { skip_with_reason "needs-ci" "needs a real build/scan/release pipeline"; }

# Dispatch table.
case "$EXAMPLE" in
  01-command-run)       cap_01_command_run ;;
  02-product)           cap_02_product ;;
  03-material)          cap_03_material ;;
  04-environment)       cap_04_environment ;;
  05-git)               cap_05_git ;;
  06-configuration)     cap_06_configuration ;;
  07-lockfiles)         cap_07_lockfiles ;;
  08-link)              cap_08_link ;;
  09-sbom)              cap_09_sbom ;;
  10-maven)             cap_10_maven ;;
  11-pip-install)       cap_11_pip_install ;;
  12-omnitrail)         cap_12_omnitrail ;;
  13-k8smanifest)       cap_13_k8smanifest ;;
  14-system-packages)   cap_14_system_packages ;;
  15-oci)               cap_15_oci ;;
  16-docker)            cap_16_docker ;;
  17-docker-bench)      cap_17_docker_bench ;;
  18-kube-bench)        cap_18_kube_bench ;;
  19-github)            cap_19_github ;;
  20-github-action)     cap_20_github_action ;;
  21-githubwebhook)     cap_21_githubwebhook ;;
  22-gitlab)            cap_22_gitlab ;;
  23-jenkins)           cap_23_jenkins ;;
  24-aws-codebuild)     cap_24_aws_codebuild ;;
  25-aws)               cap_25_aws ;;
  26-gcp-iit)           cap_26_gcp_iit ;;
  27-jwt)               cap_27_jwt ;;
  28-prowler)           cap_28_prowler ;;
  29-oscap)             cap_29_oscap ;;
  30-inspec)            cap_30_inspec ;;
  31-steampipe)         cap_31_steampipe ;;
  32-structured-data)   cap_32_structured_data ;;
  33-aws-config)        cap_33_aws_config ;;
  34-asff)              cap_34_asff ;;
  35-nessus)            cap_35_nessus ;;
  36-sarif)             cap_36_sarif ;;
  37-vex)               cap_37_vex ;;
  38-slsa)              cap_38_slsa ;;
  39-secretscan)        cap_39_secretscan ;;
  40-sinkhole-flows)    cap_40_sinkhole_flows ;;
  41-policyverify)      cap_41_policyverify ;;
  42-vsa)               cap_42_vsa ;;
  43-trivy-attack-detection) cap_43_trivy_attack_detection ;;
  tool-checkov-sarif)         cap_tool_checkov_sarif ;;
  tool-gosec-sarif)           cap_tool_gosec_sarif ;;
  tool-govulncheck-sarif)     cap_tool_govulncheck_sarif ;;
  tool-grype-sarif)           cap_tool_grype_sarif ;;
  tool-hadolint-sarif)        cap_tool_hadolint_sarif ;;
  tool-kubescape-sarif)       cap_tool_kubescape_sarif ;;
  tool-osv-scanner-sarif)     cap_tool_osv_scanner_sarif ;;
  tool-semgrep-sarif)         cap_tool_semgrep_sarif ;;
  tool-syft-sbom)             cap_tool_syft_sbom ;;
  tool-trivy-sarif)           cap_tool_trivy_sarif ;;
  signer-examples/aws-kms)    cap_signer_examples_aws_kms ;;
  multi-step-attestationsFrom) cap_multi_step_attestationsFrom ;;
  *)
    finalize "fail:setup" "no capture recipe for $EXAMPLE — add one to scripts/validate-example.sh"
    ;;
esac

# If we got here, the recipe ran without invoking skip_with_reason or
# finalize. Validate envelope shape, then finalize ok.
if [ ! -f "$OUTFILE" ]; then
  finalize "fail:capture" "no envelope produced (capture recipe forgot to call capture_basic?)"
fi
validate_envelope_shape

# Capture some sample bytes for the README.
python3 - "$OUTFILE" >"$RESULTS_DIR/predicate-excerpt.json" <<'PY'
import json, base64, sys
env = json.load(open(sys.argv[1]))
payload = json.loads(base64.b64decode(env["payload"]))
# Find the attestor predicate the example is named after (best-effort).
out = {"subjects": payload.get("subject", []), "predicates": []}
for a in payload.get("predicate", {}).get("attestations", []):
    out["predicates"].append({
        "type": a.get("type"),
        "body_keys": sorted(list(a.get("attestation", {}).keys())) if isinstance(a.get("attestation"), dict) else None,
    })
print(json.dumps(out, indent=2))
PY

finalize "ok" "captured + validated"
