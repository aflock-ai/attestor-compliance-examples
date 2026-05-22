#!/usr/bin/env bash
# Reproduce the multi-step-attestationsFrom example end-to-end.
#
# This script:
#   1. Generates a fresh Ed25519 signing key into _validation/work/key.{pem,pub}.
#   2. Runs build → scan-syft → scan-trivy as three separate `cilock run`
#      invocations, each in a clean directory so the v0.3 BackRef spine lines
#      up (each scan's material/v0.3 tree:materials root equals the build's
#      product/v0.3 tree:products root).
#   3. Emits the inclusion-proof envelope via `cilock prove` against the
#      build's product tree sidecar.
#   4. Runs a no-op `release` step that subject-binds the artifact digest so
#      `cilock verify -f <binary>` can seed envelope discovery.
#   5. Renders policy.json with the fresh keyid baked in, signs it, and
#      verifies the full evidence set.
#
# Required tools: cilock, go, syft, trivy, openssl, jq, base64.
#
# Run from the example directory:
#   ./verify-recipe.sh
#
# Or pass --cilock=/path/to/cilock to use a non-PATH binary.

set -euo pipefail

CILOCK="cilock"
for arg in "$@"; do
	case "$arg" in
	--cilock=*) CILOCK="${arg#--cilock=}" ;;
	esac
done

EX_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${EX_DIR}/_validation/work"
BUILD_DIR="${EX_DIR}/build"

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"/{out,scan-syft,scan-trivy,release}

# ---------------------------------------------------------------------------
# Fresh keypair (Ed25519 — small, deterministic, no padding ambiguity).
# ---------------------------------------------------------------------------
KEY_PEM="${WORK_DIR}/key.pem"
KEY_PUB="${WORK_DIR}/key.pub"
openssl genpkey -algorithm ed25519 -out "${KEY_PEM}" >/dev/null 2>&1
openssl pkey -in "${KEY_PEM}" -pubout -out "${KEY_PUB}" >/dev/null 2>&1
KEYID="$(shasum -a 256 "${KEY_PUB}" | awk '{print $1}')"
KEY_B64="$(base64 -i "${KEY_PUB}" | tr -d '\n')"

echo "==> using fresh keypair, keyid=${KEYID}"

# ---------------------------------------------------------------------------
# 1. BUILD — go build inside build/. The product attestor records `hello` as
#    the only product (tree size = 1, leaf at path "hello").
# ---------------------------------------------------------------------------
rm -f "${BUILD_DIR}/hello"
(cd "${BUILD_DIR}" && \
	"${CILOCK}" run \
		--step build \
		--signer-file-key-path "${KEY_PEM}" \
		--outfile "${WORK_DIR}/out/build.attestation.json" \
		--attestations environment \
		-- go build -trimpath -o hello main.go) >/dev/null
echo "==> built ${BUILD_DIR}/hello"

BIN_DIGEST="$(shasum -a 256 "${BUILD_DIR}/hello" | awk '{print $1}')"
BUILD_ROOT="$(jq -r '.payload' "${WORK_DIR}/out/build.attestation.json" | \
	base64 -d | jq -r '.subject[] | select(.name | contains("product/v0.3/tree:products")) | .digest.sha256')"
echo "    binary digest    = sha256:${BIN_DIGEST}"
echo "    product treeRoot = sha256:${BUILD_ROOT}"

# ---------------------------------------------------------------------------
# 2a. SCAN-SYFT — syft generates a CycloneDX SBOM of the binary. We copy the
#     binary into a clean directory so the scan's material/v0.3
#     tree:materials root equals build's product/v0.3 tree:products root
#     (== the v0.3 BackRef spine). The --subjects flag inject the artifact
#     digest as an explicit subject so verify can seed search from the binary
#     digest alone.
# ---------------------------------------------------------------------------
cp "${BUILD_DIR}/hello" "${WORK_DIR}/scan-syft/hello"
(cd "${WORK_DIR}/scan-syft" && \
	"${CILOCK}" run \
		--step scan-syft \
		--signer-file-key-path "${KEY_PEM}" \
		--outfile "${WORK_DIR}/out/scan-syft.attestation.json" \
		--attestations environment,sbom \
		--subjects "artifact=sha256:${BIN_DIGEST}" \
		-- bash -c "syft hello -o cyclonedx-json=hello.cdx.json") >/dev/null
echo "==> scan-syft done"

# ---------------------------------------------------------------------------
# 2b. SCAN-TRIVY — trivy filesystem scan; recorded as sarif/v0.1.
# ---------------------------------------------------------------------------
cp "${BUILD_DIR}/hello" "${WORK_DIR}/scan-trivy/hello"
(cd "${WORK_DIR}/scan-trivy" && \
	"${CILOCK}" run \
		--step scan-trivy \
		--signer-file-key-path "${KEY_PEM}" \
		--outfile "${WORK_DIR}/out/scan-trivy.attestation.json" \
		--attestations environment,sarif \
		--subjects "artifact=sha256:${BIN_DIGEST}" \
		-- bash -c "trivy fs --quiet --format sarif --output hello.sarif.json hello") >/dev/null
echo "==> scan-trivy done"

# ---------------------------------------------------------------------------
# 3. PROVE — emit per-file inclusion-proof envelope binding file:hello to
#    build's product Merkle root.
# ---------------------------------------------------------------------------
(cd "${BUILD_DIR}" && \
	"${CILOCK}" prove \
		--tree-sidecar "${WORK_DIR}/out/build.attestation.product.tree.json" \
		--file hello \
		--signer-file-key-path "${KEY_PEM}" \
		--outfile "${WORK_DIR}/out/inclusion-proof.json") >/dev/null
echo "==> inclusion-proof emitted"

# ---------------------------------------------------------------------------
# 4. RELEASE — a cheap no-op step whose only purpose is to attach the Rego
#    module and to subject-bind both the artifact digest and the build's
#    product Merkle root so verify can discover all envelopes from a single
#    -f flag.
# ---------------------------------------------------------------------------
(cd "${WORK_DIR}/release" && \
	"${CILOCK}" run \
		--step release \
		--signer-file-key-path "${KEY_PEM}" \
		--outfile "${WORK_DIR}/out/release.attestation.json" \
		--attestations environment \
		--subjects "artifact=sha256:${BIN_DIGEST}" \
		--subjects "build-tree=sha256:${BUILD_ROOT}" \
		-- bash -c "echo 'release gate evaluated' > release.log") >/dev/null
echo "==> release step recorded"

# ---------------------------------------------------------------------------
# 5. RENDER + SIGN POLICY — substitute the fresh keyid and the base64-encoded
#    Rego module into policy/policy.json. We render into work/ so we don't
#    touch the committed reference policy.
# ---------------------------------------------------------------------------
REGO_B64="$(base64 -i "${EX_DIR}/policy/rego/release-gate.rego" | tr -d '\n')"

# Substitute fresh keyid / keymaterial / rego into the committed template.
# We rewrite both the publickeys map's keyid and the keymaterial, and each
# functionary's publickeyid reference. jq makes this safe.
jq \
	--arg keyid "${KEYID}" \
	--arg keymaterial "${KEY_B64}" \
	--arg rego "${REGO_B64}" \
	'
	.publickeys = ({} | .[$keyid] = {keyid: $keyid, key: $keymaterial}) |
	(.externalAttestations.inclusionProof.functionaries[].publickeyid) |= $keyid |
	(.steps[].functionaries[].publickeyid) |= $keyid |
	(.steps.release.attestations[0].regopolicies[0].module) |= $rego
	' "${EX_DIR}/policy/policy.json" > "${WORK_DIR}/policy-rendered.json"

"${CILOCK}" sign \
	-k "${KEY_PEM}" \
	-f "${WORK_DIR}/policy-rendered.json" \
	-o "${WORK_DIR}/policy-signed.json" >/dev/null
echo "==> policy signed"

# ---------------------------------------------------------------------------
# 6. VERIFY — the full evidence set. -f <binary> seeds verify with the
#    binary's content digest; from there the BackRef graph (build's
#    product/v0.3 tree:products subject == scan-*/material/v0.3
#    tree:materials subject + the explicit --subjects artifact= injected on
#    the scan envelopes) expands to discover every step's envelope, and the
#    externalAttestations.inclusionProof match pulls in the prove envelope.
# ---------------------------------------------------------------------------
echo "==> verifying..."
"${CILOCK}" verify \
	-p "${WORK_DIR}/policy-signed.json" \
	-k "${KEY_PUB}" \
	-a "${WORK_DIR}/out/build.attestation.json,${WORK_DIR}/out/scan-syft.attestation.json,${WORK_DIR}/out/scan-trivy.attestation.json,${WORK_DIR}/out/release.attestation.json,${WORK_DIR}/out/inclusion-proof.json" \
	-f "${BUILD_DIR}/hello"
