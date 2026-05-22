package scan_must_have_data

# Defense against silent scan failures. If a scanner errored out and emitted
# zero findings, that looks like "no problems" to a naive gate but is
# actually "we never scanned." Require at least 1 check executed.

# For prowler-shape predicates:
deny[msg] {
    input.summary.totalChecks == 0
    msg := "scan executed 0 checks — refusing to gate on an empty scan"
}

# For SARIF-shape predicates:
deny[msg] {
    not input.report.runs[0]
    msg := "SARIF report has no runs[] — scanner did not produce output"
}
