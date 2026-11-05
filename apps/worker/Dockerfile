# HegoSentinel Isolated Scanner Worker (Sprint 7 Containment — P0)
# Runs as a separate unprivileged workload (never inside the API container) with:
# - Non-root user 65532:65532 (nobody/nonroot)
# - Read-only root filesystem (--read-only)
# - No Docker socket, no privileged mode, --cap-drop=ALL, --security-opt=no-new-privileges:true
# - Default network disabled (--network=none)
# - Optional pinned Semgrep CE (1.183.0) & Trivy (0.76.1) installation via build arg

FROM node:22.16.0-bookworm-slim

ARG INSTALL_SCANNERS=false
ARG SEMGREP_VERSION=1.183.0
ARG TRIVY_VERSION=0.76.1

ENV NODE_ENV=production \
    HEGOSENTINEL_WORKER_ISOLATED=1 \
    HEGOSENTINEL_NETWORK_MODE=none \
    PINNED_SEMGREP_VERSION=${SEMGREP_VERSION} \
    PINNED_TRIVY_VERSION=${TRIVY_VERSION} \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    TRIVY_NO_PROGRESS=true \
    HTTP_PROXY="" \
    HTTPS_PROXY="" \
    ALL_PROXY="" \
    NO_PROXY="*"

RUN if [ "$INSTALL_SCANNERS" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates curl && \
      pip3 install --break-system-packages --no-cache-dir "semgrep==${SEMGREP_VERSION}" && \
      curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy && \
      apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app

COPY --chown=65532:65532 package.json package-lock.json tsconfig.json ./
COPY --chown=65532:65532 types ./types
COPY --chown=65532:65532 schemas ./schemas
COPY --chown=65532:65532 packages ./packages
COPY --chown=65532:65532 integrations ./integrations
COPY --chown=65532:65532 scripts ./scripts
COPY --chown=65532:65532 examples ./examples
COPY --chown=65532:65532 apps/egress-broker ./apps/egress-broker
COPY --chown=65532:65532 apps/worker ./apps/worker

USER 65532:65532

CMD ["node", "--experimental-strip-types", "./apps/worker/src/index.ts", "--self-check"]


