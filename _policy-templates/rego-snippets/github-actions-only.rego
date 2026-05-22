package github_actions_only

# Asserts the github attestor's OIDC token was issued by a real GitHub
# Actions runner (issuer = https://token.actions.githubusercontent.com)
# and that the workflow is on this repo's allowlist.

deny[msg] {
    input.jwt.claims.iss != "https://token.actions.githubusercontent.com"
    msg := sprintf("OIDC issuer is not GitHub Actions: %s", [input.jwt.claims.iss])
}

deny[msg] {
    not startswith(input.jwt.claims.repository, "aflock-ai/")
    msg := sprintf("OIDC repository is outside the aflock-ai org: %s", [input.jwt.claims.repository])
}

deny[msg] {
    input.jwt.claims.runner_environment != "github-hosted"
    msg := sprintf("OIDC runner_environment is not github-hosted: %s", [input.jwt.claims.runner_environment])
}
