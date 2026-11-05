# HegoSentinel Out-of-Worker Trusted Egress Broker (Sprint 7 — Section 3)
# Runs outside the scanner worker container on an isolated internal bridge network,
# enforcing deny-by-default PerRunNetworkPolicy, SignedRemoteExecutionGrant,
# EmergencyStopRegistry, SSRF/DNS-rebind/redirect blocking, and SHA-256 hash-chained audit logs.

FROM node:22.16.0-bookworm-slim

ENV NODE_ENV=production \
    HEGOSENTINEL_BROKER_ISOLATED=1 \
    HTTP_PROXY="" \
    HTTPS_PROXY="" \
    ALL_PROXY="" \
    NO_PROXY="*"

WORKDIR /app

COPY --chown=65532:65532 package.json package-lock.json tsconfig.json ./
COPY --chown=65532:65532 types ./types
COPY --chown=65532:65532 schemas ./schemas
COPY --chown=65532:65532 packages ./packages
COPY --chown=65532:65532 integrations ./integrations
COPY --chown=65532:65532 apps/worker ./apps/worker
COPY --chown=65532:65532 apps/egress-broker ./apps/egress-broker

USER 65532:65532

EXPOSE 8473

CMD ["node", "--experimental-strip-types", "./apps/egress-broker/src/index.ts"]

