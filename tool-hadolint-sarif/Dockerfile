# Intentionally non-pinned base image (DL3007) for a deterministic hadolint finding.
FROM alpine:latest

# Non-pinned apk install (DL3018) — second deterministic finding.
RUN apk add curl

# Running as root (no USER directive) plus other style/ignore-pragma findings.
USER root

CMD ["sh"]
