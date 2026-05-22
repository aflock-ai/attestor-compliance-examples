# This example DEMONSTRATES policy DENYING a real finding — that's the point

Running `verify-recipe.sh` here will **exit non-zero** with:

```
collection rejected: tool-gosec, Reason: collection validation failed:
 - rego policy evaluation failed for attestor type https://aflock.ai/attestations/sarif/v0.1: policy was denied due to: SARIF result with level=error: G304 in tool gosec
```

This is NOT a bug. The policy says "deny if any SARIF result has level=error." Gosec scanned the rookery `cilock` package, found a real G304 (file inclusion via variable — operator-supplied path used in `os.Open`), and the policy correctly refuses the deploy.

In a CI pipeline this would block the release with a clear, signed, attributable reason — exactly what cilock is for.

To see a PASS instead:

- Fix the gosec finding in the source code (`//nolint:gosec` with reason, or restructure to validate the path), then re-run, OR
- Loosen the policy to allow `level=note` / `level=warning` only, blocking `level=error` only above a count threshold.

The `expected-verify-output.txt` next to this file captures the actual DENY message from the live run.
