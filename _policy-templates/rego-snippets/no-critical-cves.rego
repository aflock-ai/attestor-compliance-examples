package no_critical_cves

# Generic "no Critical CVEs" gate. Apply against any attestation whose
# predicate has a `summary.bySeverity.critical.fail` field (prowler, asff,
# trivy native, etc.). For SARIF-wrapped tools the path is different —
# see no-error-level-sarif-findings.rego.

deny[msg] {
    input.summary.bySeverity.critical.fail > 0
    msg := sprintf("found %d critical findings (allowed: 0)", [input.summary.bySeverity.critical.fail])
}
