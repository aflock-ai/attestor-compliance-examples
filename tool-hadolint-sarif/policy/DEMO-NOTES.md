# This example DEMONSTRATES policy DENYING a real Dockerfile finding — by design

Running `verify-recipe.sh` here exits non-zero with:

```
collection rejected: tool-hadolint, Reason: collection validation failed:
 - rego policy evaluation failed for attestor type https://aflock.ai/attestations/sarif/v0.1: policy was denied due to: SARIF result with level=error: DL3020 in tool Hadolint
```

This is the policy working as intended. Hadolint flagged `DL3020` (use `COPY` instead of `ADD` for files/directories) on the sample Dockerfile we wrapped. The policy says "deny if any SARIF result has level=error," so verify denies.

In a CI pipeline this would block the build with a clear, signed reason. To pass:

- Fix the Dockerfile (replace `ADD` with `COPY`), OR
- Loosen the policy if your team accepts certain rule violations.

The `expected-verify-output.txt` next to this file captures the live DENY message.
