package cilock.verify

import rego.v1

# Deny any step where secretscan found credentials
deny contains msg if {
    some step in input.predicate.attestations
    step.type == "https://aflock.ai/attestations/secretscan/v0.1"
    some finding in step.attestation.findings
    msg := sprintf("Secret detected: %s (%s)", [finding.ruleId, finding.location])
}
