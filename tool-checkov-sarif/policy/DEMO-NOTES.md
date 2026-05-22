# This example DEMONSTRATES policy DENYING a real checkov finding

The verify-recipe.sh here exits non-zero with a `policy was denied` message — that's the gate working as intended, not a bug. checkov found a real issue, the Rego policy says "no SARIF results with level=error," so the deploy is refused.

See `expected-verify-output.txt` for the actual captured DENY message.

To pass:
- Fix the checkov finding in source, OR
- Loosen the policy to allow this severity level.
