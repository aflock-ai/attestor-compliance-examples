package no_error_sarif_findings

# Generic SARIF gate: deny if any result has level=error. Works for any
# tool that emits SARIF 2.1.0 — semgrep, gosec, trivy, hadolint, etc.
# Input is the sarif attestor's predicate (which preserves the SARIF
# document byte-for-byte as predicate.report).

import future.keywords.in

deny[msg] {
    some run in input.report.runs
    some result in run.results
    result.level == "error"
    msg := sprintf("SARIF result with level=error: %s", [result.ruleId])
}
