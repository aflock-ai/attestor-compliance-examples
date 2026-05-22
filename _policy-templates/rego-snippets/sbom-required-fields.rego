package sbom_required_fields

# Gate for the sbom attestor. Requires a discriminator (CycloneDX or SPDX)
# and at least one component recorded. Catches stub SBOMs (empty
# `components: []`) which are common when the SBOM generator can't see
# the artifact it was meant to inspect.

deny[msg] {
    input._sbomFormat == ""
    msg := "SBOM is neither CycloneDX nor SPDX shape — discriminator missing"
}

# CycloneDX 1.6 requires `components`:
deny[msg] {
    input._sbomFormat == "cyclonedx"
    count(input.components) == 0
    msg := "CycloneDX SBOM has zero components — likely a stub"
}

# SPDX 2.3 requires `packages`:
deny[msg] {
    input._sbomFormat == "spdx"
    count(input.packages) == 0
    msg := "SPDX SBOM has zero packages — likely a stub"
}
