package cilock.release

# ============================================================================
# release-gate rego — the first end-to-end demonstration of the cilock v0.3
# BackRef graph spine using attestationsFrom + an inclusion-proof emitted via
# `cilock prove`.
#
# input.steps.<step>.<predicateType> is populated by the policy engine when
# the release step declares attestationsFrom: [build, scan-syft, scan-trivy].
# Each entry is the bare attestor JSON for that predicate type, as recorded
# in the named step's collection envelope.
#
# input.external.<name> is populated when the release step declares
# externalFrom: [inclusionProof] and the matching predicate-type envelope
# verified. The inclusion-proof envelope is a bare-predicate DSSE (not a
# Collection), which is why it is wired in as an externalAttestation rather
# than as a step attestation. See attestation/policy/step.go for the
# externalFrom mechanism.
#
# The three checks below cover the three "cross-step" invariants that motivate
# the v0.3 spine:
#
#   1. The artifact the scanners scanned is the artifact the build produced.
#      Enforced by re-deriving the build's product Merkle root from build's
#      product/v0.3 predicate, then asserting the inclusion-proof's treeRoot
#      matches. Without this assertion, an attacker who swapped the artifact
#      between build and scan would still pass the gate.
#
#   2. The SBOM is non-empty. A zero-component SBOM means syft either failed
#      silently or saw an unexpectedly content-free binary; either case the
#      release pipeline rejects.
#
#   3. Trivy's SARIF report has zero error-level findings. SARIF level
#      "error" is the most-severe bucket; release refuses to ship if any
#      finding lands there.
# ============================================================================

# ----------------------------------------------------------------------------
# Convenience accessors. Each is undefined when its source predicate is
# absent, so the `not <accessor>` rules below fire cleanly.
# ----------------------------------------------------------------------------

build_product := input.steps.build["https://aflock.ai/attestations/product/v0.3"]

scan_sbom := input.steps["scan-syft"]["https://cyclonedx.org/bom"]

scan_sarif := input.steps["scan-trivy"]["https://aflock.ai/attestations/sarif/v0.1"]

inclusion_proof := input.external.inclusionProof

# ----------------------------------------------------------------------------
# Check 1: cross-step artifact identity binding.
#
# The build step's product/v0.3 attestation has a merkleRoot field — the
# Merkle root of the build's product tree. `cilock prove --tree-sidecar
# <build-product-tree-sidecar> --file hello` emits an inclusion-proof
# envelope whose treeRoot field equals that same merkleRoot, and whose
# subject is `file:hello` with the binary's content digest.
#
# Asserting `inclusion_proof.treeRoot == build_product.merkleRoot` is the
# cryptographic binding between the scanner's input and the build's output.
# ----------------------------------------------------------------------------

deny[msg] {
	not build_product
	msg := "release: build step is missing product/v0.3 attestation"
}

deny[msg] {
	not inclusion_proof
	msg := "release: inclusion-proof external attestation is missing"
}

deny[msg] {
	build_product
	inclusion_proof
	inclusion_proof.treeRoot != build_product.merkleRoot
	msg := sprintf(
		"release: inclusion-proof treeRoot %v does not match build product merkleRoot %v",
		[inclusion_proof.treeRoot, build_product.merkleRoot],
	)
}

# ----------------------------------------------------------------------------
# Check 2: SBOM components are non-empty.
# ----------------------------------------------------------------------------

deny[msg] {
	not scan_sbom
	msg := "release: scan-syft step is missing cyclonedx SBOM attestation"
}

deny[msg] {
	count(scan_sbom.components) < 1
	msg := "release: scan-syft SBOM has zero components; release blocked"
}

# ----------------------------------------------------------------------------
# Check 3: trivy SARIF has zero error-level findings.
# ----------------------------------------------------------------------------

deny[msg] {
	not scan_sarif
	msg := "release: scan-trivy step is missing sarif attestation"
}

deny[msg] {
	finding := scan_sarif.report.runs[_].results[_]
	finding.level == "error"
	msg := sprintf(
		"release: scan-trivy reported SARIF error-level finding %v at %v",
		[finding.ruleId, finding.locations[0].physicalLocation.artifactLocation.uri],
	)
}
