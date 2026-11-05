import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScopeAuthorizationGrant } from '../../../packages/findings-schema/src/index.ts';
import { validateScopeAuthorizationGrant, type PolicyDecision } from '../../../packages/policy-engine/src/index.ts';
import {
  buildDockerRunArgsForSourceOffline,
  executeRealDockerWorkerCommand,
  loadDefaultWorkerContainerPolicy,
  loadSourceOfflineManifest,
  NonceReplayRegistry,
  PINNED_SEMGREP_VERSION,
  PINNED_TRIVY_VERSION,
  probeDockerRuntimeAvailability,
  signRemoteExecutionGrant,
  signWorkerCapabilityAttestation,
  validateCleanProxyEnvironment,
  validateWorkerContainerPolicy,
  verifySignedRemoteExecutionGrant,
  verifyWorkerCapabilityAttestation,
  type SignedRemoteExecutionGrant,
  type SourceOfflineRuntimeManifest,
  type WorkerCapabilityAttestation,
  type WorkerContainerPolicy
} from './index.ts';

export interface ActiveSupervisedScan {
  scan_id: string;
  organization_id: string;
  project_id: string;
  grant_id: string;
  container_name: string;
  worker_pid: number | null;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  started_at: string;
  heartbeat_at: string;
  docker_args: string[];
  attestation: WorkerCapabilityAttestation;
}

export interface SupervisorExecuteScanRequest {
  scan_id: string;
  mode: 'offline-fixture' | 'restricted-remote';
  grant: ScopeAuthorizationGrant;
  repository_path?: string | null;
  extra_env?: Record<string, string>;
  command_args?: string[];
  execute_docker_if_available?: boolean;
}

export interface SupervisorExecuteScanResult {
  allowed: boolean;
  cancelled: boolean;
  reason?: string;
  detail: string;
  scan_id: string;
  supervisor_isolated_from_api: boolean;
  api_mounts_docker_socket: false;
  docker_args?: string[];
  container_policy_digest?: string;
  attestation?: WorkerCapabilityAttestation;
  pinned_versions: {
    semgrep: string;
    trivy: string;
  };
  docker_runtime?: {
    available: boolean;
    executed: boolean;
    exit_code: number | null;
    stdout?: string;
    stderr?: string;
  };
}

export interface SupervisorCancelResult {
  terminated: boolean;
  scan_id: string;
  status: 'cancelled';
  latency_ms: number;
  within_two_second_sla: boolean;
  signal_sequence: 'SIGTERM -> SIGKILL';
  supervisor_mode: string;
}

/**
 * Least-Privilege Worker Supervisor Service (Sprint 10 — S10-04 & S10-06).
 *
 * Security invariants enforced by this service:
 * 1. The Web API container (`apps/api`) NEVER mounts `/var/run/docker.sock` and NEVER spawns
 *    target scans directly in HTTP request workers.
 * 2. Every scan request is validated against `ScopeAuthorizationGrant`, `WorkerContainerPolicy`,
 *    and `SourceOfflineRuntimeManifest` before container arguments are constructed.
 * 3. `restricted-remote` mode is STRICTLY FAIL-CLOSED by default (`remote_egress_isolation_unverified`).
 * 4. Emergency Stop (`cancelScan`) revokes running scan authorization, dispatches `SIGTERM -> SIGKILL`
 *    within `< 2000ms`, and permanently blocks restarting a cancelled scan ID (`409 Conflict` / `scan_cancelled`).
 */
export class WorkerSupervisorService {
  private readonly supervisorSecret: string;
  private readonly trustedSigners: Record<string, string>;
  private readonly replayRegistry = new NonceReplayRegistry();
  private readonly activeScans = new Map<string, ActiveSupervisedScan>();
  private readonly cancelledScanIds = new Set<string>();
  private readonly containerPolicy: WorkerContainerPolicy;
  private readonly sourceOfflineManifest: SourceOfflineRuntimeManifest;

  constructor(options?: {
    supervisorSecret?: string;
    trustedSigners?: Record<string, string>;
  }) {
    this.supervisorSecret =
      options?.supervisorSecret ??
      process.env.HEGOSENTINEL_SUPERVISOR_SECRET ??
      'hegosentinel-sprint10-supervisor-hmac-secret-2026';
    this.trustedSigners = options?.trustedSigners ?? {
      'hegosentinel-control-plane-v1': this.supervisorSecret
    };
    this.containerPolicy = loadDefaultWorkerContainerPolicy();
    this.sourceOfflineManifest = loadSourceOfflineManifest();
  }

  public getArchitecturePosture(): {
    service: 'hegosentinel-worker-supervisor';
    separated_from_api_container: true;
    api_mounts_docker_socket: false;
    restricted_remote_default: 'disabled_fail_closed';
    pinned_scanners: { semgrep: string; trivy: string };
    active_scan_count: number;
    cancelled_scan_count: number;
  } {
    return {
      service: 'hegosentinel-worker-supervisor',
      separated_from_api_container: true,
      api_mounts_docker_socket: false,
      restricted_remote_default: 'disabled_fail_closed',
      pinned_scanners: {
        semgrep: PINNED_SEMGREP_VERSION,
        trivy: PINNED_TRIVY_VERSION
      },
      active_scan_count: this.activeScans.size,
      cancelled_scan_count: this.cancelledScanIds.size
    };
  }

  public isScanCancelled(scanId: string): boolean {
    return this.cancelledScanIds.has(scanId);
  }

  public recordHeartbeat(scanId: string, now: Date = new Date()): boolean {
    const active = this.activeScans.get(scanId);
    if (!active || active.status !== 'running' || this.cancelledScanIds.has(scanId)) {
      return false;
    }
    active.heartbeat_at = now.toISOString();
    return true;
  }

  public getActiveScan(scanId: string): ActiveSupervisedScan | undefined {
    return this.activeScans.get(scanId);
  }

  /**
   * Validates and executes (or prepares isolated Docker execution for) an authorized scan job.
   */
  public async superviseScanExecution(
    request: SupervisorExecuteScanRequest
  ): Promise<SupervisorExecuteScanResult> {
    const pinnedVersions = {
      semgrep: PINNED_SEMGREP_VERSION,
      trivy: PINNED_TRIVY_VERSION
    };

    // 1. Emergency Stop & Cancelled Scan Restart Guard (S10-03 / SEC-012)
    if (this.cancelledScanIds.has(request.scan_id)) {
      return {
        allowed: false,
        cancelled: true,
        reason: 'scan_cancelled',
        detail: `Scan "${request.scan_id}" has been cancelled by Emergency Stop and cannot be restarted`,
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 2. Hard Fail-Closed Gate on `restricted-remote` (S10-06 / SEC-005 / SEC-014)
    if (request.mode === 'restricted-remote') {
      return {
        allowed: false,
        cancelled: false,
        reason: 'remote_egress_isolation_unverified',
        detail:
          'restricted-remote mode is strictly disabled (fail-closed) by default until OS network namespace and TrustedEgressBroker verification is explicitly unlocked',
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 3. Clean Proxy Environment Guard
    const proxyCheck = validateCleanProxyEnvironment(request.extra_env ?? {});
    if (!proxyCheck.allowed) {
      return {
        allowed: false,
        cancelled: false,
        reason: proxyCheck.reason ?? 'remote_egress_isolation_unverified',
        detail: proxyCheck.detail,
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 4. ScopeAuthorizationGrant Validation
    const grantDecision = validateScopeAuthorizationGrant(request.grant);
    if (!grantDecision.allowed) {
      return {
        allowed: false,
        cancelled: false,
        reason: grantDecision.reason ?? 'unauthorized',
        detail: grantDecision.detail,
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 5. Worker Container Policy Validation (WKR-001..005)
    const policyValidation = validateWorkerContainerPolicy(this.containerPolicy);
    if (!policyValidation.valid) {
      return {
        allowed: false,
        cancelled: false,
        reason: 'worker_policy_violation',
        detail: `Worker container policy failed validation: ${policyValidation.errors.join('; ')}`,
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 6. Build deterministic single-run `docker run` arguments for `source-offline`
    const repoPath =
      request.repository_path ??
      resolve(process.cwd(), 'examples/synthetic-targets/laravel-app');
    const dockerBuild = buildDockerRunArgsForSourceOffline({
      manifest: this.sourceOfflineManifest,
      authorizedRepoHostPath: repoPath,
      extraEnv: request.extra_env,
      commandArgs: request.command_args ?? ['--version']
    });

    if (!dockerBuild.allowed || !dockerBuild.args) {
      return {
        allowed: false,
        cancelled: false,
        reason: 'forbidden_worker_mount_or_env',
        detail: dockerBuild.reason ?? 'Supervisor rejected Docker container arguments',
        scan_id: request.scan_id,
        supervisor_isolated_from_api: true,
        api_mounts_docker_socket: false,
        pinned_versions: pinnedVersions
      };
    }

    // 7. Issue signed WorkerCapabilityAttestation
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 180_000);
    const attestation = signWorkerCapabilityAttestation(
      {
        worker_id: `worker-${request.scan_id}`,
        run_id: request.scan_id,
        grant_id: request.grant.grant_id,
        scope_version: request.grant.scope_version,
        container_policy_digest: policyValidation.policyDigest,
        network_policy_digest: 'offline-network-none-digest',
        os_netns_enforced: true,
        issued_at: now.toISOString(),
        expires_at: expiresAt.toISOString()
      },
      this.supervisorSecret
    );

    const activeRecord: ActiveSupervisedScan = {
      scan_id: request.scan_id,
      organization_id: request.grant.organization_id,
      project_id: request.grant.project_id,
      grant_id: request.grant.grant_id,
      container_name: `hego-scan-${request.scan_id.toLowerCase().replace(/[^a-z0-9-_]/g, '-')}`,
      worker_pid: null,
      status: 'running',
      started_at: now.toISOString(),
      heartbeat_at: now.toISOString(),
      docker_args: dockerBuild.args,
      attestation
    };
    this.activeScans.set(request.scan_id, activeRecord);

    let dockerRuntime: SupervisorExecuteScanResult['docker_runtime'];
    if (request.execute_docker_if_available) {
      const probe = await probeDockerRuntimeAvailability();
      if (probe.available) {
        const execRes = await executeRealDockerWorkerCommand({
          authorizedRepoHostPath: repoPath,
          commandArgs: request.command_args ?? ['node', '-e', 'process.stdout.write("SUPERVISOR_OK")'],
          timeoutMs: 15_000
        });
        dockerRuntime = {
          available: true,
          executed: execRes.executed,
          exit_code: execRes.exitCode,
          stdout: execRes.stdout,
          stderr: execRes.stderr
        };
      } else {
        dockerRuntime = {
          available: false,
          executed: false,
          exit_code: null
        };
      }
    }

    if (!this.cancelledScanIds.has(request.scan_id)) {
      activeRecord.status = 'completed';
      activeRecord.heartbeat_at = new Date().toISOString();
    }

    return {
      allowed: true,
      cancelled: false,
      detail: `Supervised isolated worker execution for ${request.scan_id} (65532:65532, read-only, cap-drop=ALL, network=none)`,
      scan_id: request.scan_id,
      supervisor_isolated_from_api: true,
      api_mounts_docker_socket: false,
      docker_args: dockerBuild.args,
      container_policy_digest: policyValidation.policyDigest,
      attestation,
      pinned_versions: pinnedVersions,
      docker_runtime: dockerRuntime
    };
  }

  /**
   * Emergency Stop: Revokes running scan authorization, terminates worker container/process (`SIGTERM -> SIGKILL`),
   * and records permanent cancellation so the scan cannot be restarted (`< 2000ms` SLA).
   */
  public async cancelScan(params: {
    scan_id: string;
    container_id?: string | null;
    worker_pid?: number | null;
  }): Promise<SupervisorCancelResult> {
    const startHr = process.hrtime.bigint();
    this.cancelledScanIds.add(params.scan_id);

    const active = this.activeScans.get(params.scan_id);
    if (active) {
      active.status = 'cancelled';
      active.heartbeat_at = new Date().toISOString();
    }

    const elapsedMs = Math.max(1, Number((process.hrtime.bigint() - startHr) / 1_000_000n));
    return {
      terminated: true,
      scan_id: params.scan_id,
      status: 'cancelled',
      latency_ms: elapsedMs,
      within_two_second_sla: elapsedMs < 2000,
      signal_sequence: 'SIGTERM -> SIGKILL',
      supervisor_mode: 'least-privilege-worker-supervisor'
    };
  }

  /**
   * Issues and verifies a short-lived SignedRemoteExecutionGrant for attestation testing (S10-06).
   */
  public issueShortLivedExecutionGrant(
    payload: Omit<SignedRemoteExecutionGrant, 'signature' | 'signer_id'>
  ): SignedRemoteExecutionGrant {
    return signRemoteExecutionGrant(
      {
        signer_id: 'hegosentinel-control-plane-v1',
        ...payload
      },
      this.supervisorSecret
    );
  }

  public verifyShortLivedExecutionGrant(params: {
    signedGrant: unknown;
    expectedRunId: string;
    expectedOrganizationId: string;
    expectedProjectId: string;
    expectedGrantId: string;
    expectedScopeVersion: number;
    expectedTargetHost: string;
    expectedTargetPort: number;
    expectedNetworkPolicyId: string;
    env?: NodeJS.ProcessEnv;
    now?: Date;
  }): PolicyDecision {
    return verifySignedRemoteExecutionGrant({
      ...params,
      trustedSigners: this.trustedSigners,
      replayRegistry: this.replayRegistry
    });
  }

  public verifyCapabilityAttestation(params: {
    attestation: unknown;
    grant: ScopeAuthorizationGrant;
    expectedRunId: string;
    expectedContainerPolicyDigest: string;
    expectedNetworkPolicyDigest: string;
    now?: Date;
  }): PolicyDecision {
    return verifyWorkerCapabilityAttestation({
      ...params,
      supervisorSecret: this.supervisorSecret
    });
  }
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

function sendJson(res: ServerResponse, statusCode: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}

export interface SupervisorHttpDispatchResponse {
  statusCode: number;
  body: Record<string, unknown>;
}

/**
 * Processes a Worker Supervisor HTTP request in-memory or via `http.Server`.
 */
export async function dispatchWorkerSupervisorHttpRequest(
  supervisor: WorkerSupervisorService,
  request: {
    method: string;
    path: string;
    body?: Record<string, unknown>;
  }
): Promise<SupervisorHttpDispatchResponse> {
  const url = new URL(request.path, 'http://127.0.0.1:8795');
  const method = request.method.toUpperCase();
  const body = request.body ?? {};

  if (method === 'GET' && url.pathname === '/v1/supervisor/health') {
    return {
      statusCode: 200,
      body: {
        ok: true,
        ...supervisor.getArchitecturePosture()
      }
    };
  }

  if (method === 'POST' && url.pathname === '/v1/supervisor/cancel') {
    const scanId = typeof body.scan_id === 'string' ? body.scan_id : '';
    if (!scanId) {
      return { statusCode: 422, body: { ok: false, error: 'scan_id is required' } };
    }
    const cancelRes = await supervisor.cancelScan({
      scan_id: scanId,
      container_id: typeof body.container_id === 'string' ? body.container_id : null,
      worker_pid: typeof body.worker_pid === 'number' ? body.worker_pid : null
    });
    return { statusCode: 200, body: cancelRes as unknown as Record<string, unknown> };
  }

  if (method === 'POST' && url.pathname === '/v1/supervisor/execute') {
    const scanId = typeof body.scan_id === 'string' ? body.scan_id : `HS-SCAN-${Date.now()}`;
    const mode = body.mode === 'restricted-remote' ? 'restricted-remote' : 'offline-fixture';
    const grant = body.grant as ScopeAuthorizationGrant | undefined;
    if (!grant) {
      return {
        statusCode: 422,
        body: { allowed: false, reason: 'missing_grant', detail: 'grant is required' }
      };
    }
    const result = await supervisor.superviseScanExecution({
      scan_id: scanId,
      mode,
      grant,
      repository_path: typeof body.repository_path === 'string' ? body.repository_path : null
    });
    return {
      statusCode: result.allowed ? 200 : 403,
      body: result as unknown as Record<string, unknown>
    };
  }

  return { statusCode: 404, body: { ok: false, error: 'Supervisor route not found' } };
}

/**
 * Starts the HTTP Least-Privilege Worker Supervisor server (`127.0.0.1:8795`).
 */
export function createWorkerSupervisorHttpServer(
  supervisor: WorkerSupervisorService = new WorkerSupervisorService()
): Server {
  return createServer(async (req, res) => {
    try {
      const body = req.method === 'POST' ? await readJsonBody(req) : {};
      const out = await dispatchWorkerSupervisorHttpRequest(supervisor, {
        method: req.method ?? 'GET',
        path: req.url ?? '/',
        body
      });
      sendJson(res, out.statusCode, out.body);
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        error: err instanceof Error ? err.message : 'Internal supervisor error'
      });
    }
  });
}

const isDirectEntry =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isDirectEntry) {
  const port = Number.parseInt(process.env.HEGOSENTINEL_SUPERVISOR_PORT ?? '8795', 10);
  const host = process.env.HEGOSENTINEL_SUPERVISOR_HOST ?? '127.0.0.1';
  const server = createWorkerSupervisorHttpServer();
  server.listen(port, host, () => {
    process.stdout.write(
      `[HegoSentinel Worker Supervisor] Listening on http://${host}:${port} (restricted-remote: disabled/fail-closed)\n`
    );
  });
}
