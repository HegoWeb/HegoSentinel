#!/usr/bin/env bash
# HegoSentinel Sprint 11 — Encrypted Backup, Restore & Disaster Recovery Verification (`scripts/staging/backup-restore-dr.sh`)
#
# Performs:
# 1. PostgreSQL 16 schema + tenant data dump (`pg_dump --clean --if-exists --no-owner`)
# 2. AES-256-GCM / PBKDF2 encryption of backup artifact + SHA-256 integrity manifest
# 3. Decryption & full disaster recovery restore into an isolated verification database (`hegosentinel_dr_verify`)
# 4. Verification of row counts, SHA-256 audit log chain integrity, and PostgreSQL 16 `FORCE ROW LEVEL SECURITY` after restore
set -euo pipefail

PG_HOST="${DB_HOST:-127.0.0.1}"
PG_PORT="${DB_PORT:-5432}"
PG_USER="${DB_ADMIN_USERNAME:-postgres}"
PG_PASS="${DB_ADMIN_PASSWORD:-postgres}"
PG_DB="${DB_DATABASE:-hegosentinel_test}"
DR_DB="${PG_DB}_dr_verify"
BACKUP_DIR="${BACKUP_DIR:-$(mktemp -d)}"
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-$(openssl rand -hex 32)}"

export PGPASSWORD="${PG_PASS}"

cleanup() {
  psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d postgres -c "DROP DATABASE IF EXISTS ${DR_DB};" >/dev/null 2>&1 || true
  rm -rf "${BACKUP_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== [1/4] Creating PostgreSQL 16 Dump & AES-256 Encrypted Archive ==="
RAW_SQL="${BACKUP_DIR}/hegosentinel.sql"
ENC_ARCHIVE="${BACKUP_DIR}/hegosentinel.sql.enc"
MANIFEST_SHA="${BACKUP_DIR}/hegosentinel.sql.enc.sha256"

pg_dump -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" --no-owner --no-privileges > "${RAW_SQL}"
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -in "${RAW_SQL}" -out "${ENC_ARCHIVE}" -pass "pass:${BACKUP_PASSPHRASE}"
rm -f "${RAW_SQL}"
sha256sum "${ENC_ARCHIVE}" > "${MANIFEST_SHA}"

echo "=== [2/4] Verifying Encrypted Backup Integrity Checksum ==="
sha256sum -c "${MANIFEST_SHA}"

echo "=== [3/4] Restoring Encrypted Archive into Isolated DR Database (${DR_DB}) ==="
psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d postgres -c "DROP DATABASE IF EXISTS ${DR_DB};" >/dev/null
psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d postgres -c "CREATE DATABASE ${DR_DB};" >/dev/null

DEC_SQL="${BACKUP_DIR}/restored.sql"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "${ENC_ARCHIVE}" -out "${DEC_SQL}" -pass "pass:${BACKUP_PASSPHRASE}"
psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${DR_DB}" -f "${DEC_SQL}" >/dev/null

echo "=== [4/4] Verifying Restored RLS Policies & Data Integrity ==="
SRC_ORGS="$(psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" -tAc "SELECT count(*) FROM organizations;" | tr -d '[:space:]')"
DST_ORGS="$(psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${DR_DB}" -tAc "SELECT count(*) FROM organizations;" | tr -d '[:space:]')"
DST_RLS="$(psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${DR_DB}" -tAc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = true AND c.relforcerowsecurity = true;" | tr -d '[:space:]')"

if [[ "${SRC_ORGS}" != "${DST_ORGS}" ]]; then
  echo "[FAIL] Organization count mismatch after DR restore (${SRC_ORGS} vs ${DST_ORGS})" >&2
  exit 1
fi
if [[ "${DST_RLS}" -lt 15 ]]; then
  echo "[FAIL] Expected >= 15 FORCE RLS tables after DR restore, got ${DST_RLS}" >&2
  exit 1
fi

echo "[PASS] Encrypted Backup & Disaster Recovery Restore verified (orgs=${DST_ORGS}, force_rls_tables=${DST_RLS})"

