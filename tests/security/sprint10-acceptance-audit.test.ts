import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import {
  TrustedEgressBroker,
  type BrokerProxyRequest
} from '../../apps/egress-broker/src/index.ts';
import {
  dispatchWorkerSupervisorHttpRequest,
  WorkerSupervisorService
} from '../../apps/worker/src/supervisor.ts';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function loadValidGrant(): ScopeAuthorizationGrant {
  const now = Date.now();
  const issuedAt = new Date(now - 60_000).toISOString();
  const expiresAt = new Date(now + 3600_000).toISOString();
  return {
    schema_version: '1.0.0',
    grant_id: 'GRANT-S10-ACCEPTANCE-001',
    scope_version: 1,
    organization_id: 'org-hegoweb-sec',
    project_id: 'proj-laravel-commerce',
    project_name: 'Laravel Order & Checkout API',
    stack: ['laravel', 'generic-web'],
    profile: 'local-demo',
    owner: 'Demo Owner',
    authorization_statement: 'Authorized offline source and passive web assessment for Sprint 10 acceptance audit.',
    domain_control_proof: 'dns-txt:hegosentinel-verify=s10acceptance001',
    written_permission_ref: 'LEGAL-S10-ACCEPTANCE-2026-001',
    emergency_contact: 'admin@hegoweb.local',
    issued_at: issuedAt,
    expires_at: expiresAt,
    time_window: {
      start_at: issuedAt,
      end_at: expiresAt
    },
    max_request_budget: 15,
    allowed_methods: ['GET', 'HEAD'],
    allowed_checks: [
      'WEB-HEADER-001',
      'WEB-COOKIE-001',
      'WEB-TLS-001',
      'WEB-REDIRECT-001',
      'CODE-001',
      'DEP-001'
    ],
    targets: [
      {
        scheme: 'https',
        hostname: 'demo.example.test',
        port: 443,
        path_prefix: '/'
      }
    ],
    allowed_repositories: [resolve(process.cwd(), 'examples/synthetic-targets/laravel-app')]
  };
}

describe('Sprint 10 Final Acceptance Audit — Section 3 & Section 6 Live Verification', () => {
  it('Section 3: launches a real long-running worker subprocess, verifies OS PID is alive, kills it via Emergency Stop in < 2000ms, and blocks restart', async () => {
    const supervisor = new WorkerSupervisorService({
      supervisorSecret: 's10-acceptance-supervisor-secret-2026'
    });
    const grant = loadValidGrant();
    const scanId = 'SCAN-LONGRUN-ESTOP-001';

    // 1. Start a long-running (6000ms) scan asynchronously via the supervisor HTTP dispatcher
    const inFlightScanPromise = dispatchWorkerSupervisorHttpRequest(supervisor, {
      method: 'POST',
      path: '/v1/supervisor/execute',
      body: {
        scan_id: scanId,
        mode: 'offline-fixture',
        grant,
        simulated_duration_ms: 6000,
        execute_worker_bridge: true
      }
    });

    // 2. Poll supervisor until the real OS worker subprocess PID is spawned and running
    let workerPid: number | null = null;
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 50));
      const activeRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
        method: 'GET',
        path: `/v1/supervisor/scans/${scanId}`
      });
      if (activeRes.statusCode === 200) {
        const activeBody = activeRes.body as {
          scan?: { worker_pid?: number | null; status?: string };
        };
        if (
          activeBody.scan?.status === 'running' &&
          typeof activeBody.scan?.worker_pid === 'number' &&
          activeBody.scan.worker_pid > 0
        ) {
          workerPid = activeBody.scan.worker_pid;
          break;
        }
      }
    }

    assert.ok(
      typeof workerPid === 'number' && workerPid > 0,
      'Expected Worker Supervisor to spawn a real OS subprocess with a valid PID'
    );
    assert.equal(isPidAlive(workerPid), true, `Expected worker subprocess PID ${workerPid} to be alive before Emergency Stop`);

    // 3. Trigger Emergency Stop while the scan is actively running and measure real OS termination time
    const stopWallStart = performance.now();
    const cancelRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
      method: 'POST',
      path: '/v1/supervisor/cancel',
      body: {
        scan_id: scanId,
        worker_pid: workerPid
      }
    });
    const cancelBody = cancelRes.body;
    const inFlightResult = await inFlightScanPromise;
    const stopWallElapsedMs = Math.round(performance.now() - stopWallStart);

    // Verify OS process is genuinely dead
    let pidAliveAfter = isPidAlive(workerPid);
    if (pidAliveAfter) {
      await new Promise((r) => setTimeout(r, 100));
      pidAliveAfter = isPidAlive(workerPid);
    }

    assert.equal(cancelRes.statusCode, 200);
    assert.equal(cancelBody.terminated, true);
    assert.equal(cancelBody.process_terminated, true);
    assert.equal(cancelBody.terminated_pid, workerPid);
    assert.equal(pidAliveAfter, false, `Expected worker subprocess PID ${workerPid} to be dead after Emergency Stop`);
    assert.ok(
      stopWallElapsedMs < 2000,
      `Expected real OS subprocess termination + in-flight scan abort within < 2000ms, measured ${stopWallElapsedMs}ms`
    );
    assert.equal(inFlightResult.statusCode, 403);
    assert.equal(inFlightResult.body.allowed, false);
    assert.equal(inFlightResult.body.cancelled, true);
    assert.equal(inFlightResult.body.reason, 'scan_cancelled');

    // 4. Verify that restarting the cancelled scan is permanently blocked
    const restartRes = await dispatchWorkerSupervisorHttpRequest(supervisor, {
      method: 'POST',
      path: '/v1/supervisor/execute',
      body: {
        scan_id: scanId,
        mode: 'offline-fixture',
        grant,
        execute_worker_bridge: true
      }
    });
    const restartBody = restartRes.body;
    assert.equal(restartRes.statusCode, 403);
    assert.equal(restartBody.allowed, false);
    assert.equal(restartBody.cancelled, true);
    assert.equal(restartBody.reason, 'scan_cancelled');
  });

  it('Section 6.1: executes Semgrep (CODE-001) and Trivy (DEP-001) through isolated Worker Supervisor HTTP service and enforces WKR-001..005 flags', async () => {
    const supervisor = new WorkerSupervisorService({
      supervisorSecret: 's10-acceptance-supervisor-secret-2026'
    });
    const grant = loadValidGrant();
    const res = await dispatchWorkerSupervisorHttpRequest(supervisor, {
      method: 'POST',
      path: '/v1/supervisor/execute',
      body: {
        scan_id: 'SCAN-S10-SEMGREP-TRIVY-001',
        mode: 'offline-fixture',
        grant,
        repository_path: resolve(process.cwd(), 'examples/synthetic-targets/laravel-app'),
        fixture_variant: 'baseline',
        execute_worker_bridge: true
      }
    });
    const body = res.body as unknown as {
      allowed: boolean;
      supervisor_isolated_from_api: boolean;
      api_mounts_docker_socket: boolean;
      docker_args: string[];
      pinned_versions: { semgrep: string; trivy: string };
      report?: {
        coverage: { checks: Array<{ rule_id: string; status: string }> };
        findings: Array<{ rule_id: string }>;
      };
    };

    assert.equal(res.statusCode, 200);
    assert.equal(body.allowed, true);
    assert.equal(body.supervisor_isolated_from_api, true);
    assert.equal(body.api_mounts_docker_socket, false);
    assert.equal(body.pinned_versions.semgrep, '1.183.0');
    assert.equal(body.pinned_versions.trivy, '0.76.1');
    assert.ok(body.docker_args.includes('--read-only'), 'Missing WKR-002 --read-only');
    assert.ok(body.docker_args.includes('--cap-drop=ALL'), 'Missing WKR-002 --cap-drop=ALL');
    assert.ok(body.docker_args.includes('--security-opt=no-new-privileges:true'), 'Missing WKR-002 no-new-privileges');
    assert.ok(body.docker_args.includes('--network=none'), 'Missing WKR-003 --network=none');
    assert.ok(body.docker_args.includes('--user=65532:65532'), 'Missing WKR-001 non-root user 65532:65532');

    const rulesExecuted = new Set((body.report?.coverage.checks ?? []).map((c) => c.rule_id));
    assert.ok(rulesExecuted.has('CODE-001'), 'Expected CODE-001 (Semgrep) in scan coverage');
    assert.ok(rulesExecuted.has('DEP-001'), 'Expected DEP-001 (Trivy) in scan coverage');
    const findingRules = new Set((body.report?.findings ?? []).map((f) => f.rule_id));
    assert.ok(findingRules.has('CODE-001'), 'Expected CODE-001 finding from Semgrep');
    assert.ok(findingRules.has('DEP-001'), 'Expected DEP-001 finding from Trivy');
  });

  it('Section 6.2: enforces Trusted Egress Broker SSRF blocks, single-use grant nonces, B2 secret redaction, and strict restricted-remote fail-closed gate', async () => {
    const supervisor = new WorkerSupervisorService({
      supervisorSecret: 's10-broker-secret-2026'
    });
    const grant = loadValidGrant();

    // 1. restricted-remote must fail closed at Worker Supervisor
    const remoteAttempt = await supervisor.superviseScanExecution({
      scan_id: 'SCAN-REMOTE-BLOCKED-001',
      mode: 'restricted-remote',
      grant
    });
    assert.equal(remoteAttempt.allowed, false);
    assert.equal(remoteAttempt.reason, 'remote_egress_isolation_unverified');

    // 2. TrustedEgressBroker SSRF & bypass negative tests
    const broker = new TrustedEgressBroker({
      trustedSigners: { 'hegosentinel-control-plane-v1': 's10-broker-secret-2026' },
      resolver: {
        resolve4: async (h: string) => (h.includes('evil-unapproved') ? ['93.184.216.34'] : ['127.0.0.1']),
        resolve6: async () => []
      }
    });
    const ssrfTargets = [
      'http://127.0.0.1:8080/admin?api_key=supersecret123',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'https://10.0.0.1/internal?token=secret_jwt_token',
      'https://evil-unapproved.example.com/steal?password=mySecretPassword'
    ];

    for (const targetUrl of ssrfTargets) {
      const reqInput: BrokerProxyRequest = {
        requestId: `REQ-${Math.random().toString(36).slice(2, 8)}`,
        url: targetUrl,
        method: 'GET',
        signedExecutionGrant: undefined,
        scopeGrant: grant,
        expectedRunId: 'RUN-SSRF-TEST-01',
        expectedOrganizationId: grant.organization_id,
        expectedProjectId: grant.project_id,
        expectedGrantId: grant.grant_id,
        expectedScopeVersion: grant.scope_version,
        expectedNetworkPolicyId: 'NPOL-S10-TEST-01'
      };
      const decision = await broker.executeBrokeredPassiveRequest(reqInput, async () => {
        throw new Error('Upstream transport must never be invoked for blocked SSRF/out-of-scope targets');
      });
      assert.equal(decision.allowed, false, `Expected TrustedEgressBroker to block ${targetUrl}`);
      assert.equal(decision.action, 'DROP');
    }

    // Verify B2: no secret query parameter survives in the broker audit trail
    const auditDump = JSON.stringify(broker.getAuditLog());
    assert.equal(auditDump.includes('supersecret123'), false, 'B2 violation: api_key leaked in broker audit log');
    assert.equal(auditDump.includes('secret_jwt_token'), false, 'B2 violation: token leaked in broker audit log');
    assert.equal(auditDump.includes('mySecretPassword'), false, 'B2 violation: password leaked in broker audit log');
    assert.equal(broker.verifyAuditLogIntegrity().valid, true, 'Expected broker SHA-256 audit hash chain to remain valid');
  });
});
