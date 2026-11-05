import assert from 'node:assert/strict';
import test from 'node:test';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';
import {
  dispatchWorkerSupervisorHttpRequest,
  WorkerSupervisorService
} from '../../apps/worker/src/supervisor.ts';

function buildValidGrant(overrides: Partial<ScopeAuthorizationGrant> = {}): ScopeAuthorizationGrant {
  const now = Date.now();
  const issuedAt = new Date(now - 60_000).toISOString();
  const expiresAt = new Date(now + 3600_000).toISOString();
  return {
    schema_version: '1.0.0',
    grant_id: 'GRANT-SUPERVISOR-S10-001',
    scope_version: 3,
    organization_id: 'org-acme-sec',
    project_id: 'proj-acme-portal',
    project_name: 'Acme Portal Security Program',
    owner: 'usr-acme-owner',
    authorization_statement: 'Authorized offline source and passive header security assessment for Acme Portal.',
    written_permission_ref: 'PERM-ACME-2026-S10-001',
    emergency_contact: 'secops@acme-example.com',
    issued_at: issuedAt,
    expires_at: expiresAt,
    time_window: {
      start_at: issuedAt,
      end_at: expiresAt,
      timezone: 'UTC'
    },
    targets: [
      {
        target_id: 'target-acme-portal',
        scheme: 'https',
        hostname: 'portal.acme-example.com',
        port: 443,
        path_prefix: '/'
      }
    ],
    allowed_methods: ['GET', 'HEAD'],
    allowed_checks: [
      'WEB-TLS-001',
      'WEB-HEADER-001',
      'WEB-COOKIE-001',
      'WEB-REDIRECT-001',
      'CODE-001',
      'DEP-001'
    ],
    max_request_budget: 25,
    ...overrides
  };
}

test('S10-04.1: WorkerSupervisorService enforces API container separation, blocks restricted-remote fail-closed, and builds WKR-001..005 Docker args', async () => {
  const supervisor = new WorkerSupervisorService({
    supervisorSecret: 's10-test-supervisor-hmac-secret-key-2026'
  });

  const posture = supervisor.getArchitecturePosture();
  assert.equal(posture.separated_from_api_container, true);
  assert.equal(posture.api_mounts_docker_socket, false);
  assert.equal(posture.restricted_remote_default, 'disabled_fail_closed');

  const grant = buildValidGrant();

  // 1. restricted-remote MUST fail closed by default (S10-06)
  const remoteRes = await supervisor.superviseScanExecution({
    scan_id: 'HS-SUP-REMOTE-001',
    mode: 'restricted-remote',
    grant
  });
  assert.equal(remoteRes.allowed, false);
  assert.equal(remoteRes.reason, 'remote_egress_isolation_unverified');

  // 2. Forbidden host mount (/var/run/docker.sock) MUST be rejected (WKR-002)
  const forbiddenMountRes = await supervisor.superviseScanExecution({
    scan_id: 'HS-SUP-SOCK-001',
    mode: 'offline-fixture',
    grant,
    repository_path: '/var/run/docker.sock'
  });
  assert.equal(forbiddenMountRes.allowed, false);
  assert.equal(forbiddenMountRes.reason, 'forbidden_worker_mount_or_env');

  // 3. Forbidden secret/proxy env var MUST be rejected (WKR-002)
  const forbiddenEnvRes = await supervisor.superviseScanExecution({
    scan_id: 'HS-SUP-ENV-001',
    mode: 'offline-fixture',
    grant,
    extra_env: { AWS_SECRET_ACCESS_KEY: 'AKIA-LEAK' }
  });
  assert.equal(forbiddenEnvRes.allowed, false);
  assert.equal(forbiddenEnvRes.reason, 'forbidden_worker_mount_or_env');

  // 4. Valid offline scan supervision builds hardened WKR-001..005 arguments and signed attestation
  const validRes = await supervisor.superviseScanExecution({
    scan_id: 'HS-SUP-VALID-001',
    mode: 'offline-fixture',
    grant,
    repository_path: 'examples/synthetic-targets/laravel-app'
  });
  assert.equal(validRes.allowed, true);
  assert.equal(validRes.supervisor_isolated_from_api, true);
  assert.equal(validRes.api_mounts_docker_socket, false);
  assert.ok(Array.isArray(validRes.docker_args));
  assert.ok(validRes.docker_args.includes('--network=none'));
  assert.ok(validRes.docker_args.includes('--user=65532:65532'));
  assert.ok(validRes.docker_args.includes('--read-only'));
  assert.ok(validRes.docker_args.includes('--cap-drop=ALL'));
  assert.ok(validRes.docker_args.includes('--security-opt=no-new-privileges:true'));

  // Verify signed WorkerCapabilityAttestation
  assert.ok(validRes.attestation);
  assert.ok(validRes.container_policy_digest);
  const attDecision = supervisor.verifyCapabilityAttestation({
    attestation: validRes.attestation,
    grant,
    expectedRunId: 'HS-SUP-VALID-001',
    expectedContainerPolicyDigest: validRes.container_policy_digest,
    expectedNetworkPolicyDigest: 'offline-network-none-digest'
  });
  assert.equal(attDecision.allowed, true);
});

test('S10-04.2 & S10-06: Emergency Stop (< 2000ms SLA), cancelled scan restart prevention, and SignedRemoteExecutionGrant single-use nonce', async () => {
  const supervisor = new WorkerSupervisorService({
    supervisorSecret: 's10-test-supervisor-hmac-secret-key-2026'
  });
  const grant = buildValidGrant();

  const cancelRes = await supervisor.cancelScan({
    scan_id: 'HS-SUP-CANCEL-009',
    container_id: 'hego-scan-hs-sup-cancel-009'
  });
  assert.equal(cancelRes.terminated, true);
  assert.equal(cancelRes.status, 'cancelled');
  assert.equal(cancelRes.within_two_second_sla, true);
  assert.ok(cancelRes.latency_ms < 2000);
  assert.equal(cancelRes.signal_sequence, 'SIGTERM -> SIGKILL');

  // Cancelled scan cannot be restarted
  const restartAttempt = await supervisor.superviseScanExecution({
    scan_id: 'HS-SUP-CANCEL-009',
    mode: 'offline-fixture',
    grant
  });
  assert.equal(restartAttempt.allowed, false);
  assert.equal(restartAttempt.cancelled, true);
  assert.equal(restartAttempt.reason, 'scan_cancelled');

  // Short-lived SignedRemoteExecutionGrant & single-use nonce (S10-06)
  const now = new Date();
  const signedGrant = supervisor.issueShortLivedExecutionGrant({
    run_id: 'HS-RUN-777',
    organization_id: grant.organization_id,
    project_id: grant.project_id,
    grant_id: grant.grant_id,
    scope_version: grant.scope_version,
    target_scheme: 'https',
    target_host: 'portal.acme-example.com',
    target_port: 443,
    target_path_prefix: '/',
    allowed_methods: ['GET', 'HEAD'],
    max_request_budget: 10,
    network_policy_id: 'netpol-777',
    emergency_stop_token_id: 'estop-777',
    nonce: 'nonce-single-use-sprint10-777',
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 120_000).toISOString()
  });

  const firstVerify = supervisor.verifyShortLivedExecutionGrant({
    signedGrant,
    expectedRunId: 'HS-RUN-777',
    expectedOrganizationId: grant.organization_id,
    expectedProjectId: grant.project_id,
    expectedGrantId: grant.grant_id,
    expectedScopeVersion: grant.scope_version,
    expectedTargetHost: 'portal.acme-example.com',
    expectedTargetPort: 443,
    expectedNetworkPolicyId: 'netpol-777',
    env: {},
    now
  });
  assert.equal(firstVerify.allowed, true);

  // Replay with same nonce MUST be blocked
  const replayVerify = supervisor.verifyShortLivedExecutionGrant({
    signedGrant,
    expectedRunId: 'HS-RUN-777',
    expectedOrganizationId: grant.organization_id,
    expectedProjectId: grant.project_id,
    expectedGrantId: grant.grant_id,
    expectedScopeVersion: grant.scope_version,
    expectedTargetHost: 'portal.acme-example.com',
    expectedTargetPort: 443,
    expectedNetworkPolicyId: 'netpol-777',
    env: {},
    now
  });
  assert.equal(replayVerify.allowed, false);
  assert.match(replayVerify.detail, /replay blocked/i);
});

test('S10-04.3: Worker Supervisor HTTP dispatcher handles health, execute, and cancel endpoints', async () => {
  const supervisor = new WorkerSupervisorService({
    supervisorSecret: 's10-http-supervisor-secret-key-2026'
  });

  const healthRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
    method: 'GET',
    path: '/v1/supervisor/health'
  });
  assert.equal(healthRes.statusCode, 200);
  assert.equal(healthRes.body.ok, true);
  assert.equal(healthRes.body.api_mounts_docker_socket, false);

  const execRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
    method: 'POST',
    path: '/v1/supervisor/execute',
    body: {
      scan_id: 'HS-HTTP-SUP-001',
      mode: 'offline-fixture',
      grant: buildValidGrant()
    }
  });
  assert.equal(execRes.statusCode, 200);
  assert.equal(execRes.body.allowed, true);

  const cancelRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
    method: 'POST',
    path: '/v1/supervisor/cancel',
    body: { scan_id: 'HS-HTTP-SUP-001' }
  });
  assert.equal(cancelRes.statusCode, 200);
  assert.equal(cancelRes.body.terminated, true);
  assert.equal(cancelRes.body.within_two_second_sla, true);
});
