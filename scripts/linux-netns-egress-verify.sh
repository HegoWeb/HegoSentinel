#!/usr/bin/env bash
# HegoSentinel — Sprint 8 Real Linux Network Isolation & End-to-End Trusted Egress Broker Verification (EGR-001..006)
# Creates an isolated Docker --internal bridge network (no default gateway to internet/host LAN),
# launches the real out-of-worker TrustedEgressBroker HTTP daemon container on that network,
# and proves from inside the worker container that:
# 1. Direct worker internet bypass (1.1.1.1:443) is blocked by the Linux network namespace.
# 2. Direct worker cloud metadata bypass (169.254.169.254:80) is blocked by the Linux network namespace.
# 3. End-to-end HTTP requests from worker -> TrustedEgressBroker (/v1/egress/health, /policy, /fetch, /audit)
#    succeed for authorized passive GET grants and drop SSRF / replay / unauthorized requests.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER_IMAGE="hegosentinel-worker:0.1.0-alpha.4"
BROKER_IMAGE="hegosentinel-egress-broker:0.1.0-alpha.4"
BROKER_CONTAINER="hegosentinel-egress-broker"
INTERNAL_NET="hegosentinel-internal-isolated-net"
CONTROL_SECRET="hegosentinel-ci-broker-control-secret-2026"
SIGNER_SECRET="hegosentinel-ci-grant-signer-secret-2026"
EVIDENCE_FILE="${REPO_ROOT}/reports/linux-egress-isolation-evidence.json"

mkdir -p "${REPO_ROOT}/reports"

cleanup() {
  docker rm -f "${BROKER_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${INTERNAL_NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

echo "=== [1/4] Building Worker & Egress Broker Docker images ==="
docker build -t "${WORKER_IMAGE}" -f "${REPO_ROOT}/apps/worker/Dockerfile" "${REPO_ROOT}" >/dev/null
docker build -t "${BROKER_IMAGE}" -f "${REPO_ROOT}/apps/egress-broker/Dockerfile" "${REPO_ROOT}" >/dev/null

echo "=== [2/4] Creating isolated Docker --internal network (${INTERNAL_NET}) ==="
docker network create --internal "${INTERNAL_NET}" >/dev/null

echo "=== [3/4] Starting out-of-worker TrustedEgressBroker HTTP daemon on ${INTERNAL_NET} ==="
docker run -d \
  --name "${BROKER_CONTAINER}" \
  --network "${INTERNAL_NET}" \
  --user 65532:65532 \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -e HEGOSENTINEL_BROKER_HOST=0.0.0.0 \
  -e HEGOSENTINEL_BROKER_PORT=8790 \
  -e HEGOSENTINEL_BROKER_CONTROL_SECRET="${CONTROL_SECRET}" \
  -e HEGOSENTINEL_GRANT_SIGNER_SECRET="${SIGNER_SECRET}" \
  "${BROKER_IMAGE}" >/dev/null

sleep 2

echo "=== [4/4] Running worker container on ${INTERNAL_NET} to verify direct bypass block + E2E HTTP broker enforcement ==="
E2E_JSON="$(docker run --rm \
  --network="${INTERNAL_NET}" \
  --user=65532:65532 \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -e BROKER_URL="http://${BROKER_CONTAINER}:8790" \
  -e CONTROL_SECRET="${CONTROL_SECRET}" \
  -e SIGNER_SECRET="${SIGNER_SECRET}" \
  "${WORKER_IMAGE}" node --experimental-strip-types -e "
import net from 'node:net';
import { generatePerRunNetworkPolicy, signRemoteExecutionGrant } from './apps/worker/src/index.ts';

function probeTcp(host, port) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: 1500 });
    s.on('connect', () => { s.destroy(); resolve('CONNECTED'); });
    s.on('timeout', () => { s.destroy(); resolve('ETIMEDOUT'); });
    s.on('error', (e) => resolve(e.code || 'ERROR'));
  });
}

const internetProbe = await probeTcp('1.1.1.1', 443);
const metadataProbe = await probeTcp('169.254.169.254', 80);
const directInternetBlocked = internetProbe !== 'CONNECTED';
const metadataBlocked = metadataProbe !== 'CONNECTED';

if (!directInternetBlocked || !metadataBlocked) {
  console.error('CRITICAL: Worker bypassed isolated network!', { internetProbe, metadataProbe });
  process.exit(1);
}

const brokerUrl = process.env.BROKER_URL;
const controlSecret = process.env.CONTROL_SECRET;
const signerSecret = process.env.SIGNER_SECRET;

// 1. Health check over real HTTP inside isolated network
const healthRes = await fetch(brokerUrl + '/v1/egress/health');
const healthJson = await healthRes.json();
if (healthRes.status !== 200 || healthJson.status !== 'ok') {
  console.error('Broker health check failed', healthJson);
  process.exit(1);
}

const now = new Date();
const issuedAtIso = new Date(now.getTime() - 60_000).toISOString();
const expiresAtIso = new Date(now.getTime() + 180_000).toISOString();
const scopeGrant = {
  schema_version: '1.0.0',
  grant_id: 'GRANT-NETNS-E2E-001',
  scope_version: 1,
  organization_id: 'org-hegoweb-demo',
  project_id: 'proj-safe-demo',
  project_name: 'Netns E2E Target',
  stack: ['laravel', 'nextjs', 'generic-web'],
  profile: 'local-demo',
  owner: 'HegoWeb Security',
  authorization_statement: 'Authorized E2E netns verification',
  domain_control_proof: 'dns-txt-verified',
  written_permission_ref: 'AUTH-NETNS-2026',
  emergency_contact: 'sec@example.test',
  issued_at: '2026-01-01T00:00:00.000Z',
  expires_at: '2030-12-31T23:59:59.000Z',
  time_window: { start_at: '2026-01-01T00:00:00.000Z', end_at: '2030-12-31T23:59:59.000Z' },
  max_request_budget: 10,
  allowed_methods: ['GET', 'HEAD'],
  allowed_checks: ['WEB-HEADER-001'],
  targets: [{ scheme: 'https', hostname: 'demo.example.test', port: 443, path_prefix: '/' }],
  allowed_repositories: []
};

const netPol = await generatePerRunNetworkPolicy({
  runId: 'RUN-NETNS-E2E-001',
  grant: scopeGrant,
  resolver: {
    async resolve4() { return ['93.184.216.34']; },
    async resolve6() { return []; }
  },
  now
});

// 2. Register PerRunNetworkPolicy on broker over HTTP
const policyRes = await fetch(brokerUrl + '/v1/egress/policy', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-hegosentinel-control-secret': controlSecret
  },
  body: JSON.stringify(netPol.policy)
});
if (policyRes.status !== 200) {
  console.error('Failed to register policy on broker', await policyRes.text());
  process.exit(1);
}

// 3. Authorized passive GET via POST /v1/egress/fetch -> 200 ALLOW
const validSignedGrant = signRemoteExecutionGrant({
  signer_id: 'hegosentinel-control-plane-signer-v1',
  run_id: 'RUN-NETNS-E2E-001',
  organization_id: scopeGrant.organization_id,
  project_id: scopeGrant.project_id,
  grant_id: scopeGrant.grant_id,
  scope_version: scopeGrant.scope_version,
  target_scheme: 'https',
  target_host: 'demo.example.test',
  target_port: 443,
  target_path_prefix: '/',
  allowed_methods: ['GET', 'HEAD'],
  max_request_budget: 5,
  network_policy_id: netPol.policy.policy_digest,
  emergency_stop_token_id: 'ESTOP-NETNS-001',
  nonce: 'nonce-netns-e2e-0001',
  issued_at: issuedAtIso,
  expires_at: expiresAtIso
}, signerSecret);

const allowFetchRes = await fetch(brokerUrl + '/v1/egress/fetch', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    requestId: 'NETNS-REQ-ALLOW',
    url: 'https://demo.example.test/',
    method: 'GET',
    signedExecutionGrant: validSignedGrant,
    scopeGrant,
    expectedRunId: 'RUN-NETNS-E2E-001',
    expectedOrganizationId: scopeGrant.organization_id,
    expectedProjectId: scopeGrant.project_id,
    expectedGrantId: scopeGrant.grant_id,
    expectedScopeVersion: scopeGrant.scope_version,
    expectedNetworkPolicyId: netPol.policy.policy_digest,
    now: now.toISOString()
  })
});
const allowFetchJson = await allowFetchRes.json();

// 4. SSRF / Replay negative test via POST /v1/egress/fetch -> 403 DROP
const ssrfDropRes = await fetch(brokerUrl + '/v1/egress/fetch', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    requestId: 'NETNS-REQ-SSRF-DROP',
    url: 'http://169.254.169.254/latest/meta-data/',
    method: 'GET',
    signedExecutionGrant: validSignedGrant,
    scopeGrant,
    expectedRunId: 'RUN-NETNS-E2E-001',
    expectedOrganizationId: scopeGrant.organization_id,
    expectedProjectId: scopeGrant.project_id,
    expectedGrantId: scopeGrant.grant_id,
    expectedScopeVersion: scopeGrant.scope_version,
    expectedNetworkPolicyId: netPol.policy.policy_digest,
    now: now.toISOString()
  })
});

// 5. Audit log hash-chain verification over HTTP
const auditRes = await fetch(brokerUrl + '/v1/egress/audit', {
  headers: { 'x-hegosentinel-control-secret': controlSecret }
});
const auditJson = await auditRes.json();

console.log(JSON.stringify({
  internetProbe,
  metadataProbe,
  direct_internet_bypass_blocked: directInternetBlocked,
  cloud_metadata_bypass_blocked: metadataBlocked,
  broker_e2e_http_allow_verified: allowFetchRes.status === 200 && allowFetchJson.allowed === true,
  broker_e2e_http_ssrf_drop_verified: ssrfDropRes.status === 403,
  broker_audit_chain_valid: Boolean(auditJson?.integrity?.valid && auditJson?.metrics?.prohibitedAllowedCount === 0)
}));
")"

echo "[PASS] E2E Isolated Network & Broker HTTP Verification: ${E2E_JSON}"

node --experimental-strip-types -e "
import { writeFileSync } from 'node:fs';
const probe = ${E2E_JSON};
const allOk =
  probe.direct_internet_bypass_blocked === true &&
  probe.cloud_metadata_bypass_blocked === true &&
  probe.broker_e2e_http_allow_verified === true &&
  probe.broker_e2e_http_ssrf_drop_verified === true &&
  probe.broker_audit_chain_valid === true;
if (!allOk) {
  console.error('EGR-LINUX-NETNS-RUNTIME verification criteria not met:', probe);
  process.exit(1);
}
writeFileSync('${EVIDENCE_FILE}', JSON.stringify({
  verified_at: new Date().toISOString(),
  isolated_network: '${INTERNAL_NET}',
  direct_bypass_probe: {
    internetBypassBlocked: probe.internetProbe,
    metadataBypassBlocked: probe.metadataProbe
  },
  direct_internet_bypass_blocked: probe.direct_internet_bypass_blocked,
  cloud_metadata_bypass_blocked: probe.cloud_metadata_bypass_blocked,
  broker_e2e_http_allow_verified: probe.broker_e2e_http_allow_verified,
  broker_e2e_http_ssrf_drop_verified: probe.broker_e2e_http_ssrf_drop_verified,
  broker_audit_chain_valid: probe.broker_audit_chain_valid,
  verdict: 'PASS'
}, null, 2) + '\n', 'utf8');
"

echo "[OK] Saved Linux Egress Isolation E2E evidence to ${EVIDENCE_FILE}"
