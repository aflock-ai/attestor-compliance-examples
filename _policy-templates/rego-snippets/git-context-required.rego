package git_context_required

# Asserts the cilock run was launched from a git checkout. Without git
# context an envelope can't be back-referenced to the source commit,
# breaking the chain from artifact back to code.

deny[msg] {
    not input.commithash
    msg := "git attestation has no commithash — cilock run was not from a git checkout"
}
