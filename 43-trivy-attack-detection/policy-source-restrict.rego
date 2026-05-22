package cilock.verify

deny[msg] {
    ref := input.actionref
    not startswith(ref, "actions/")
    not startswith(ref, "chainguard-dev/")
    msg := sprintf("Action from untrusted source: %s", [ref])
}

deny[msg] {
    not input.refpinned
    msg := sprintf("Action ref not pinned to SHA: %s", [input.actionref])
}
