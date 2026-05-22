package cilock.verify

import rego.v1

# Approved action source prefixes
approved_sources := ["chainguard-dev/", "testifysec/", "actions/", "aflock-ai/"]

# Deny actions from unapproved sources
deny contains msg if {
    some step in input.predicate.attestations
    step.type == "https://aflock.ai/attestations/github-action/v0.1"
    ref := step.attestation.actionref
    not source_approved(ref)
    msg := sprintf("Action from untrusted source: %s", [ref])
}

# Deny actions with unpinned refs
deny contains msg if {
    some step in input.predicate.attestations
    step.type == "https://aflock.ai/attestations/github-action/v0.1"
    not step.attestation.refpinned
    msg := sprintf("Action ref not pinned to SHA: %s", [step.attestation.actionref])
}

# Deny if any secrets detected
deny contains msg if {
    some step in input.predicate.attestations
    step.type == "https://aflock.ai/attestations/secretscan/v0.1"
    some finding in step.attestation.findings
    msg := sprintf("Secret detected: %s", [finding.ruleId])
}

# Helper: check if ref starts with any approved source
source_approved(ref) if {
    some prefix in approved_sources
    startswith(ref, prefix)
}
