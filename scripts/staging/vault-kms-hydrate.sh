#!/usr/bin/env bash
# HegoSentinel Sprint 11 — KMS / HashiCorp Vault Secret Hydration Script (`scripts/staging/vault-kms-hydrate.sh`)
#
# Pulls staging secrets from HashiCorp Vault KV v2 (or generates ephemeral test-staging secrets in `--ephemeral-ci` mode)
# into a mode `0600` tmpfs file (`/dev/shm/hegosentinel-staging.env`) so plaintext secrets never touch persistent disk.
set -euo pipefail

MODE="${1:---vault}"
OUT_FILE="${2:-/dev/shm/hegosentinel-staging.env}"

umask 077

if [[ "${MODE}" == "--ephemeral-ci" ]]; then
  rand_hex() { openssl rand -hex 24; }
  APP_KEY_B64="base64:$(openssl rand -base64 32)"
  cat > "${OUT_FILE}" <<EOF
STAGING_DOMAIN=staging.hegosentinel.internal
TLS_CERT_MODE=internal
APP_KEY=${APP_KEY_B64}
DB_DATABASE=hegosentinel_staging
DB_ADMIN_USERNAME=hegosentinel
DB_ADMIN_PASSWORD=$(rand_hex)
DB_APP_USERNAME=hegosentinel_app
DB_APP_PASSWORD=$(rand_hex)
REDIS_PASSWORD=$(rand_hex)
HEGOSENTINEL_SUPERVISOR_SECRET=$(rand_hex)
HEGOSENTINEL_BROKER_SECRET=$(rand_hex)
HEGOSENTINEL_EPHEMERAL_DOCKER_WORKER=1
WORKER_DOCKER_HOST=tcp://docker-socket-proxy:2375
EOF
  chmod 0600 "${OUT_FILE}"
  echo "[OK] Hydrated ephemeral staging secrets into tmpfs (${OUT_FILE}, mode 0600)"
  exit 0
fi

: "${VAULT_ADDR:?VAULT_ADDR is required for --vault mode}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required for --vault mode}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/data/hegosentinel/staging}"

RESPONSE="$(curl -sf -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR%/}/v1/${VAULT_SECRET_PATH}")"

node -e '
const fs = require("node:fs");
const payload = JSON.parse(process.argv[1]);
const data = (payload && payload.data && payload.data.data) || {};
const required = [
  "STAGING_DOMAIN",
  "APP_KEY",
  "DB_DATABASE",
  "DB_ADMIN_USERNAME",
  "DB_ADMIN_PASSWORD",
  "DB_APP_USERNAME",
  "DB_APP_PASSWORD",
  "REDIS_PASSWORD",
  "HEGOSENTINEL_SUPERVISOR_SECRET",
  "HEGOSENTINEL_BROKER_SECRET"
];
for (const key of required) {
  if (!data[key] || String(data[key]).includes("__HYDRATE")) {
    console.error(`[FAIL] Missing or placeholder secret in Vault response: ${key}`);
    process.exit(1);
  }
}
const lines = Object.entries(data).map(([k, v]) => `${k}=${v}`);
fs.writeFileSync(process.argv[2], lines.join("\n") + "\n", { mode: 0o600 });
' "${RESPONSE}" "${OUT_FILE}"

chmod 0600 "${OUT_FILE}"
echo "[OK] Vault KV v2 secrets hydrated to ${OUT_FILE} (mode 0600)"

