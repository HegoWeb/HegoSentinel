import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import {
  analyzeDockerRunOutcome,
  buildDockerRunArgsForSourceOffline,
  executeBoundedPassiveRequest,
  executeRealDockerWorkerCommand,
  generatePerRunNetworkPolicy,
  loadDefaultWorkerContainerPolicy,
  loadSourceOfflineManifest,
  NonceReplayRegistry,
  probeDockerRuntimeAvailability,
  probeInstalledBinaryVersion,
  renderNftablesRuleset,
  signRemoteExecutionGrant,
  signWorkerCapabilityAttestation,
  SimulatedNetworkNamespaceFirewall,
  validateCleanProxyEnvironment,
  validateWorkerContainerPolicy,
  verifySignedRemoteExecutionGrant,
  verifyWorkerCapabilityAttestation
} from '../../apps/worker/src/index.ts';
import {
  createTrustedEgressBrokerServer,
  handleTrustedEgressBrokerHttpRequest,
  TrustedEgressBroker
} from '../../apps/egress-broker/src/index.ts';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { runSemgrepAdapter } from '../../integrations/semgrep/src/index.ts';
import { runTrivyAdapter } from '../../integrations/trivy/src/index.ts';
import type {
  ScanReport,
  ScopeAuthorizationGrant
} from '../../packages/findings-schema/src/index.ts';
import {
  authorizeReportTenantAccess,
  EmergencyStopRegistry,
  TamperEvidentAuditLog,
  type DnsResolver
} from '../../packages/policy-engine/src/index.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import {
  redactSensitiveText,
  renderHtmlReport,
  validateSafeReportOutputPath
} from '../../packages/report-engine/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';
import { evaluateProductionReleaseReadiness } from '../../scripts/release-gate-check.ts';

const baseGrant = JSON.parse(
  readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
) as ScopeAuthorizationGrant;

const publicResolver: DnsResolver = {
  async resolve4(hostname: string) {
    if (hostname === 'demo.example.test') return ['93.184.216.34'];
    return [];
  },
  async resolve6() {
    return [];
  }
};

describe('Sprint A (P0 â€” G0.5): Offline worker container isolation, WKR-001..WKR-006 & subprocess lifecycle', () => {
  it('validates the default unprivileged worker container policy and rejects privileged/socket/writable escapes', () => {
    const defaultPolicy = loadDefaultWorkerContainerPolicy();
    const validRes = validateWorkerContainerPolicy(defaultPolicy);
    assert.equal(validRes.valid, true);
    assert.equal(validRes.errors.length, 0);

    const badPolicy = {
      ...defaultPolicy,
      privileged: true,
      host_docker_socket_mounted: true,
      read_only_root_filesystem: false,
      user: '0:0'
    };
    const badRes = validateWorkerContainerPolicy(badPolicy);
    assert.equal(badRes.valid, false);
    assert.equal(badRes.errors.length >= 4, true);
  });

  it('validates source-offline-manifest.json and builds hardened docker run args while rejecting forbidden mounts/env', () => {
    const manifest = loadSourceOfflineManifest();
    assert.equal(manifest.profile, 'source-offline');
    assert.equal(manifest.network_mode, 'none');

    const validBuild = buildDockerRunArgsForSourceOffline({
      manifest,
      authorizedRepoHostPath: process.cwd(),
      extraEnv: { HEGOSENTINEL_RUN_ID: 'RUN-OFFLINE-001' }
    });
    assert.equal(validBuild.allowed, true);
    assert.ok(validBuild.args);
    assert.equal(validBuild.args.includes('--network=none'), true);
    assert.equal(validBuild.args.includes('--read-only'), true);
    assert.equal(validBuild.args.includes('--cap-drop=ALL'), true);
    assert.equal(validBuild.args.includes('--security-opt=no-new-privileges:true'), true);
    assert.equal(validBuild.args.includes('--user=65532:65532'), true);
    assert.equal(
      validBuild.args.some((arg) => arg.includes('dst=/workspace/target-repo,readonly')),
      true
    );

    // Reject docker.sock host path
    const badMountBuild = buildDockerRunArgsForSourceOffline({
      manifest,
      authorizedRepoHostPath: '/var/run/docker.sock'
    });
    assert.equal(badMountBuild.allowed, false);
    assert.equal(Boolean(badMountBuild.reason?.includes('Forbidden host mount path')), true);

    // Reject secret and proxy env vars
    const badEnvBuild = buildDockerRunArgsForSourceOffline({
      manifest,
      authorizedRepoHostPath: process.cwd(),
      extraEnv: {
        GITHUB_TOKEN: 'ghp_secret123',
        HTTP_PROXY: 'http://10.0.0.1:8080'
      }
    });
    assert.equal(badEnvBuild.allowed, false);
    assert.equal(
      Boolean(badEnvBuild.reason?.includes('Forbidden secret or proxy environment variable')),
      true
    );
  });

  it('WKR-001 (Docker runtime): internet egress blocked inside --network=none container', async (t) => {
    const dockerProbe = await probeDockerRuntimeAvailability();
    if (!dockerProbe.available) {
      t.skip(`SKIP (not verified): Docker runtime unavailable on host (${dockerProbe.reason})`);
      return;
    }
    const res = await executeRealDockerWorkerCommand({
      authorizedRepoHostPath: resolve(process.cwd(), 'examples/safe-demo/sample-repo'),
      commandArgs: ['sh', '-c', 'wget -qO- --timeout=2 https://93.184.216.34/']
    });
    assert.equal(res.executed, true);
    assert.notEqual(res.exitCode, 0);
  });

  it('WKR-002 (Docker runtime): cloud metadata 169.254.169.254 and fd00:ec2::254 blocked inside container', async (t) => {
    const dockerProbe = await probeDockerRuntimeAvailability();
    if (!dockerProbe.available) {
      t.skip(`SKIP (not verified): Docker runtime unavailable on host (${dockerProbe.reason})`);
      return;
    }
    const res = await executeRealDockerWorkerCommand({
      authorizedRepoHostPath: resolve(process.cwd(), 'examples/safe-demo/sample-repo'),
      commandArgs: ['sh', '-c', 'wget -qO- --timeout=2 http://169.254.169.254/latest/meta-data/']
    });
    assert.equal(res.executed, true);
    assert.notEqual(res.exitCode, 0);
  });

  it('WKR-003 (Docker runtime): writing to read-only rootfs and /workspace/repo:ro fails with EROFS', async (t) => {
    const dockerProbe = await probeDockerRuntimeAvailability();
    if (!dockerProbe.available) {
      t.skip(`SKIP (not verified): Docker runtime unavailable on host (${dockerProbe.reason})`);
      return;
    }
    const res = await executeRealDockerWorkerCommand({
      authorizedRepoHostPath: resolve(process.cwd(), 'examples/safe-demo/sample-repo'),
      commandArgs: ['sh', '-c', 'touch /workspace/target-repo/escape-write-test']
    });
    assert.equal(res.executed, true);
    assert.notEqual(res.exitCode, 0);
  });

  it('WKR-004 (Docker runtime): symlink escape outside /workspace/repo:ro blocked inside container', async (t) => {
    const dockerProbe = await probeDockerRuntimeAvailability();
    if (!dockerProbe.available) {
      t.skip(`SKIP (not verified): Docker runtime unavailable on host (${dockerProbe.reason})`);
      return;
    }
    const res = await executeRealDockerWorkerCommand({
      authorizedRepoHostPath: resolve(process.cwd(), 'examples/safe-demo/sample-repo'),
      commandArgs: ['sh', '-c', 'cat /etc/shadow']
    });
    assert.equal(res.executed, true);
    assert.notEqual(res.exitCode, 0);
  });

  it('WKR-005 (Docker runtime): container CPU/memory/PID/timeout resource exhaustion killed cleanly', async (t) => {
    const dockerProbe = await probeDockerRuntimeAvailability();
    if (!dockerProbe.available) {
      t.skip(`SKIP (not verified): Docker runtime unavailable on host (${dockerProbe.reason})`);
      return;
    }
    const res = await executeRealDockerWorkerCommand({
      authorizedRepoHostPath: resolve(process.cwd(), 'examples/safe-demo/sample-repo'),
      commandArgs: ['sh', '-c', 'sleep 10'],
      timeoutMs: 1000
    });
    assert.equal(res.executed, true);
    assert.notEqual(res.exitCode, 0);
  });

  it('WKR-005 & WKR-006 (Host subprocess): AbortSignal cancellation sends SIGTERM/SIGKILL and records tool_status=killed / timed_out / not_installed', async () => {
    const repoGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      profile: 'source',
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: [process.cwd()]
    };

    // 1. Subprocess cancellation via AbortSignal -> SIGTERM -> tool_status: 'killed'
    const abortCtrl = new AbortController();
    const killSignalsSent: Array<string | undefined> = [];
    const cancelPromise = runSemgrepAdapter({
      grant: repoGrant,
      repositoryPath: process.cwd(),
      signal: abortCtrl.signal,
      execRunner: (_file, _args, _opts, cb) => {
        const fakeChild = {
          killed: false,
          kill(sig?: string) {
            killSignalsSent.push(sig);
            this.killed = true;
            const err = new Error('Process terminated by signal') as NodeJS.ErrnoException;
            cb(err, '', 'Terminated');
            return true;
          }
        };
        setTimeout(() => abortCtrl.abort(), 10);
        return fakeChild;
      }
    });

    const cancelledSemgrep = await cancelPromise;
    assert.equal(killSignalsSent.includes('SIGTERM'), true);
    assert.equal(cancelledSemgrep.coverage.status, 'failed');
    assert.equal(cancelledSemgrep.coverage.tool_status, 'killed');
    assert.equal(cancelledSemgrep.coverage.positive_validation_passed, false);

    // 2. Missing binary (ENOENT) -> status: 'skipped', tool_status: 'not_installed'
    const missingTrivy = await runTrivyAdapter({
      grant: repoGrant,
      repositoryPath: process.cwd(),
      execRunner: (_file, _args, _opts, cb) => {
        const err = new Error('spawn trivy ENOENT') as NodeJS.ErrnoException;
        err.code = 'ENOENT';
        cb(err, '', '');
      }
    });
    assert.equal(missingTrivy.coverage.status, 'skipped');
    assert.equal(missingTrivy.coverage.tool_status, 'not_installed');
    assert.equal(missingTrivy.coverage.positive_validation_passed, false);
  });
});

describe('Sprint B (P0 â€” G0.6): SignedRemoteExecutionGrant, NonceReplayRegistry & Egress Bypass Negative Matrix', () => {
  it('generates per-run network policy and demonstrates zero prohibited outbound connections in simulated netns firewall logs', async () => {
    const now = new Date('2026-11-04T20:00:00.000Z');
    const netRes = await generatePerRunNetworkPolicy({
      runId: 'RUN-NETNS-001',
      grant: baseGrant,
      resolver: publicResolver,
      now
    });

    assert.equal(netRes.decision.allowed, true);
    assert.ok(netRes.policy);
    const ruleset = renderNftablesRuleset(netRes.policy);
    assert.equal(ruleset.includes('policy drop;'), true);
    assert.equal(ruleset.includes('169.254.169.254/32'), true);
    assert.equal(ruleset.includes('fd00:ec2::254/128'), true);
    assert.equal(ruleset.includes('ip daddr 93.184.216.34 tcp dport 443'), true);

    const firewall = new SimulatedNetworkNamespaceFirewall(netRes.policy);

    const prohibitedAttempts = [
      { hostname: 'demo.example.test', peerIp: '169.254.169.254', port: 80 },
      { hostname: 'demo.example.test', peerIp: '127.0.0.1', port: 443 },
      { hostname: 'demo.example.test', peerIp: '10.0.0.15', port: 443 },
      { hostname: 'demo.example.test', peerIp: 'fd00:ec2::254', port: 443 },
      { hostname: 'demo.example.test', peerIp: '::ffff:169.254.169.254', port: 443 },
      { hostname: 'demo.example.test', peerIp: '93.184.216.34', port: 8443 },
      { hostname: 'evil.example.test', peerIp: '93.184.216.34', port: 443 }
    ];

    for (const attempt of prohibitedAttempts) {
      const decision = firewall.checkAndRecordConnection({ ...attempt, now });
      assert.equal(decision.allowed, false);
    }

    assert.equal(firewall.getAllowedConnections().length, 0);
    assert.equal(firewall.getDroppedConnections().length, prohibitedAttempts.length);
    assert.equal(firewall.getProhibitedAllowedCount(), 0);

    const validConn = firewall.checkAndRecordConnection({
      hostname: 'demo.example.test',
      peerIp: '93.184.216.34',
      port: 443,
      now
    });
    assert.equal(validConn.allowed, true);
    assert.equal(firewall.getAllowedConnections().length, 1);
    assert.equal(firewall.getProhibitedAllowedCount(), 0);
  });

  it('enforces SignedRemoteExecutionGrant bindings and blocks replay, stale TTL (>300s), grant substitution, untrusted signer, and proxy env escape', () => {
    const now = new Date('2026-11-04T20:00:00.000Z');
    const secret = 'control-plane-hmac-secret-2026';
    const trustedSigners: Record<string, string> = {
      'hegosentinel-control-plane-signer-v1': secret
    };
    const cleanEnv: NodeJS.ProcessEnv = { PATH: '/usr/bin' };

    const validPayload = {
      signer_id: 'hegosentinel-control-plane-signer-v1',
      run_id: 'RUN-REMOTE-001',
      organization_id: baseGrant.organization_id,
      project_id: baseGrant.project_id,
      grant_id: baseGrant.grant_id,
      scope_version: baseGrant.scope_version,
      target_scheme: 'https' as const,
      target_host: 'demo.example.test',
      target_port: 443,
      target_path_prefix: '/',
      allowed_methods: ['GET' as const, 'HEAD' as const],
      max_request_budget: 10,
      issued_at: '2026-11-04T19:59:00.000Z',
      expires_at: '2026-11-04T20:03:00.000Z', // 240s TTL (<= 300s)
      nonce: 'nonce-unique-0001',
      network_policy_id: 'NETPOL-RUN-REMOTE-001',
      emergency_stop_token_id: 'ESTOP-001'
    };

    const signedGrant = signRemoteExecutionGrant(validPayload, secret);
    const replayRegistry = new NonceReplayRegistry();

    // 1. Valid first-use verification succeeds
    const firstVerify = verifySignedRemoteExecutionGrant({
      signedGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'demo.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: cleanEnv,
      now
    });
    assert.equal(firstVerify.allowed, true);

    // 2. Replay attack with identical nonce fails closed
    const replayVerify = verifySignedRemoteExecutionGrant({
      signedGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'demo.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: cleanEnv,
      now
    });
    assert.equal(replayVerify.allowed, false);
    assert.equal(Boolean(replayVerify.detail?.includes('Grant replay blocked')), true);

    // 3. Excessive TTL (> 300s) fails closed
    const longTtlGrant = signRemoteExecutionGrant(
      {
        ...validPayload,
        nonce: 'nonce-unique-0002',
        expires_at: '2026-11-04T20:10:00.000Z' // 660s > 300s
      },
      secret
    );
    const longTtlVerify = verifySignedRemoteExecutionGrant({
      signedGrant: longTtlGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'demo.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: cleanEnv,
      now
    });
    assert.equal(longTtlVerify.allowed, false);
    assert.equal(longTtlVerify.reason, 'scope_expired');

    // 4. Grant substitution (target host or project mismatch) fails closed
    const substGrant = signRemoteExecutionGrant(
      {
        ...validPayload,
        nonce: 'nonce-unique-0003'
      },
      secret
    );
    const substVerify = verifySignedRemoteExecutionGrant({
      signedGrant: substGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'other-tenant.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: cleanEnv,
      now
    });
    assert.equal(substVerify.allowed, false);
    assert.equal(Boolean(substVerify.detail?.includes('Grant substitution blocked')), true);

    // 5. Untrusted signer fails closed
    const untrustedGrant = signRemoteExecutionGrant(
      {
        ...validPayload,
        signer_id: 'rogue-worker-self-signer',
        nonce: 'nonce-unique-0004'
      },
      secret
    );
    const untrustedVerify = verifySignedRemoteExecutionGrant({
      signedGrant: untrustedGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'demo.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: cleanEnv,
      now
    });
    assert.equal(untrustedVerify.allowed, false);
    assert.equal(Boolean(untrustedVerify.detail?.includes('Untrusted or unknown grant signer_id')), true);

    // 6. Ambient proxy environment variable escape fails closed
    const proxyEnvCheck = validateCleanProxyEnvironment({
      HTTP_PROXY: 'http://proxy.internal:3128'
    });
    assert.equal(proxyEnvCheck.allowed, false);

    const proxyGrant = signRemoteExecutionGrant(
      {
        ...validPayload,
        nonce: 'nonce-unique-0005'
      },
      secret
    );
    const proxyVerify = verifySignedRemoteExecutionGrant({
      signedGrant: proxyGrant,
      trustedSigners,
      replayRegistry,
      expectedRunId: 'RUN-REMOTE-001',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedTargetHost: 'demo.example.test',
      expectedTargetPort: 443,
      expectedNetworkPolicyId: 'NETPOL-RUN-REMOTE-001',
      env: { HTTPS_PROXY: 'http://169.254.169.254:80' },
      now
    });
    assert.equal(proxyVerify.allowed, false);
    assert.equal(proxyVerify.reason, 'remote_egress_isolation_unverified');
  });

  it('rejects caller-supplied booleans and forged/expired worker capability attestations', async () => {
    const now = new Date('2026-11-04T20:00:00.000Z');
    const secret = 'hegosentinel-supervisor-secret-key-2026';
    const containerRes = validateWorkerContainerPolicy(loadDefaultWorkerContainerPolicy());
    const netRes = await generatePerRunNetworkPolicy({
      runId: 'RUN-ATT-001',
      grant: baseGrant,
      resolver: publicResolver,
      now
    });
    assert.ok(netRes.policy);

    const boolCheck = verifyWorkerCapabilityAttestation({
      attestation: true,
      supervisorSecret: secret,
      grant: baseGrant,
      expectedRunId: 'RUN-ATT-001',
      expectedContainerPolicyDigest: containerRes.policyDigest,
      expectedNetworkPolicyDigest: netRes.policy.policy_digest,
      now
    });
    assert.equal(boolCheck.allowed, false);

    const signed = signWorkerCapabilityAttestation(
      {
        worker_id: 'worker-node-01',
        run_id: 'RUN-ATT-001',
        grant_id: baseGrant.grant_id,
        scope_version: baseGrant.scope_version,
        container_policy_digest: containerRes.policyDigest,
        network_policy_digest: netRes.policy.policy_digest,
        os_netns_enforced: true,
        issued_at: '2026-11-04T19:59:00.000Z',
        expires_at: '2026-11-04T20:05:00.000Z'
      },
      secret
    );

    const validVerify = verifyWorkerCapabilityAttestation({
      attestation: signed,
      supervisorSecret: secret,
      grant: baseGrant,
      expectedRunId: 'RUN-ATT-001',
      expectedContainerPolicyDigest: containerRes.policyDigest,
      expectedNetworkPolicyDigest: netRes.policy.policy_digest,
      now
    });
    assert.equal(validVerify.allowed, true);

    const tampered = { ...signed, run_id: 'RUN-DIFFERENT-002' };
    const tamperedVerify = verifyWorkerCapabilityAttestation({
      attestation: tampered,
      supervisorSecret: secret,
      grant: baseGrant,
      expectedRunId: 'RUN-DIFFERENT-002',
      expectedContainerPolicyDigest: containerRes.policyDigest,
      expectedNetworkPolicyDigest: netRes.policy.policy_digest,
      now
    });
    assert.equal(tamperedVerify.allowed, false);
  });

  it('executeBoundedPassiveRequest enforces GET/HEAD limits, body size cap, kill-switch cancellation, and redirect/rebind guards', async () => {
    const now = new Date('2026-11-04T20:00:00.000Z');
    const netRes = await generatePerRunNetworkPolicy({
      runId: 'RUN-HTTP-001',
      grant: baseGrant,
      resolver: publicResolver,
      now
    });
    assert.ok(netRes.policy);
    const firewall = new SimulatedNetworkNamespaceFirewall(netRes.policy);

    const postRes = await executeBoundedPassiveRequest({
      url: 'https://demo.example.test/',
      method: 'POST',
      grant: baseGrant,
      resolver: publicResolver,
      firewall,
      transport: async () => ({
        statusCode: 200,
        headers: {},
        body: 'ok',
        connectedSocketPeerIp: '93.184.216.34'
      })
    });
    assert.equal(postRes.allowed, false);
    assert.equal(postRes.reason, 'disallowed_method');
    assert.equal(postRes.hopsExecuted, 0);

    const oversizedRes = await executeBoundedPassiveRequest({
      url: 'https://demo.example.test/',
      method: 'GET',
      grant: baseGrant,
      resolver: publicResolver,
      firewall,
      maxResponseBytes: 1024,
      transport: async () => ({
        statusCode: 200,
        headers: {},
        body: 'x'.repeat(2048),
        connectedSocketPeerIp: '93.184.216.34'
      })
    });
    assert.equal(oversizedRes.allowed, false);
    assert.equal(oversizedRes.reason, 'response_body_exceeded_limit');

    const abortCtrl = new AbortController();
    abortCtrl.abort();
    const cancelledRes = await executeBoundedPassiveRequest({
      url: 'https://demo.example.test/',
      method: 'GET',
      grant: baseGrant,
      resolver: publicResolver,
      firewall,
      signal: abortCtrl.signal,
      transport: async () => ({
        statusCode: 200,
        headers: {},
        body: 'ok',
        connectedSocketPeerIp: '93.184.216.34'
      })
    });
    assert.equal(cancelledRes.allowed, false);
    assert.equal(cancelledRes.reason, 'scan_cancelled');

    const redirectSsrfRes = await executeBoundedPassiveRequest({
      url: 'https://demo.example.test/',
      method: 'GET',
      grant: baseGrant,
      resolver: publicResolver,
      firewall,
      transport: async () => ({
        statusCode: 302,
        headers: { location: 'https://169.254.169.254/latest/meta-data/' },
        body: '',
        connectedSocketPeerIp: '93.184.216.34'
      })
    });
    assert.equal(redirectSsrfRes.allowed, false);
    assert.equal(redirectSsrfRes.reason, 'out_of_scope_redirect');
    assert.equal(firewall.getProhibitedAllowedCount(), 0);
  });

  it('Out-of-worker TrustedEgressBroker enforces deny-by-default policy, SignedRemoteExecutionGrant, SSRF/rebind/redirect drops, header stripping, and hash-chained audit logs (EGR-001..EGR-006)', async () => {
    const now = new Date('2026-11-04T20:00:00.000Z');
    const secret = 'broker-control-plane-hmac-secret-2026';
    const trustedSigners = { 'hegosentinel-control-plane-signer-v1': secret };

    const broker = new TrustedEgressBroker({
      trustedSigners,
      resolver: {
        async resolve4(hostname: string) {
          if (hostname === 'demo.example.test') return ['93.184.216.34'];
          if (hostname === 'metadata.internal.test') return ['169.254.169.254'];
          return [];
        },
        async resolve6(hostname: string) {
          if (hostname === 'ipv6-metadata.internal.test') return ['fd00:ec2::254'];
          return [];
        }
      }
    });

    const netRes = await generatePerRunNetworkPolicy({
      runId: 'RUN-BROKER-001',
      grant: baseGrant,
      resolver: publicResolver,
      now
    });
    assert.ok(netRes.policy);

    const makeSignedGrant = (nonce: string, overrides: Record<string, unknown> = {}) =>
      signRemoteExecutionGrant(
        {
          signer_id: 'hegosentinel-control-plane-signer-v1',
          run_id: 'RUN-BROKER-001',
          organization_id: baseGrant.organization_id,
          project_id: baseGrant.project_id,
          grant_id: baseGrant.grant_id,
          scope_version: baseGrant.scope_version,
          target_scheme: 'https',
          target_host: 'demo.example.test',
          target_port: 443,
          target_path_prefix: '/',
          allowed_methods: ['GET', 'HEAD'],
          max_request_budget: 5,
          network_policy_id: netRes.policy!.policy_digest,
          emergency_stop_token_id: 'ESTOP-BROKER-001',
          nonce,
          issued_at: '2026-11-04T19:59:00.000Z',
          expires_at: '2026-11-04T20:03:00.000Z',
          ...overrides
        },
        secret
      );

    // EGR-001: Deny-by-default before PerRunNetworkPolicy is registered
    const unregRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-001',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: makeSignedGrant('nonce-broker-0001'),
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 200,
        headers: {},
        body: 'should-not-run',
        connectedSocketPeerIp: '93.184.216.34'
      })
    );
    assert.equal(unregRes.allowed, false);
    assert.equal(unregRes.action, 'DROP');
    assert.equal(unregRes.reason, 'broker_policy_drop');

    // Now register the PerRunNetworkPolicy on the broker
    broker.registerPerRunNetworkPolicy(netRes.policy);

    // Valid GET request succeeds and strips Authorization / Cookie headers
    const validGrant = makeSignedGrant('nonce-broker-0002');
    const allowRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-002',
        url: 'https://demo.example.test/',
        method: 'GET',
        headers: {
          Authorization: 'Bearer secret-jwt-token',
          Cookie: 'session=secret',
          'X-Custom-Trace': 'trace-1'
        },
        signedExecutionGrant: validGrant,
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: '<html lang="en">ok</html>',
        connectedSocketPeerIp: '93.184.216.34',
        tlsServername: 'demo.example.test'
      })
    );
    assert.equal(allowRes.allowed, true);
    assert.equal(allowRes.action, 'ALLOW');
    assert.equal(allowRes.sanitizedRequestHeaders?.['authorization'], undefined);
    assert.equal(allowRes.sanitizedRequestHeaders?.['cookie'], undefined);
    assert.equal(allowRes.sanitizedRequestHeaders?.['x-custom-trace'], 'trace-1');

    // EGR-002: Replay of same signed grant nonce is dropped
    const replayRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-003',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: validGrant,
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 200,
        headers: {},
        body: 'ok',
        connectedSocketPeerIp: '93.184.216.34'
      })
    );
    assert.equal(replayRes.allowed, false);
    assert.equal(replayRes.action, 'DROP');

    // EGR-004: TOCTOU DNS rebinding socket peer IP mismatch (127.0.0.1 vs pinned 93.184.216.34) is dropped
    const rebindRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-004',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: makeSignedGrant('nonce-broker-0004'),
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 200,
        headers: {},
        body: 'rebind',
        connectedSocketPeerIp: '127.0.0.1'
      })
    );
    assert.equal(rebindRes.allowed, false);
    assert.equal(rebindRes.reason, 'dns_rebind_detected');

    // EGR-005: Redirect to cloud metadata 169.254.169.254 is dropped without following
    const redirectDropRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-005',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: makeSignedGrant('nonce-broker-0005'),
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data/' },
        body: '',
        connectedSocketPeerIp: '93.184.216.34'
      })
    );
    assert.equal(redirectDropRes.allowed, false);
    assert.equal(redirectDropRes.reason, 'protocol_downgrade');

    // EGR-006: Revoking emergency_stop_token_id immediately drops subsequent requests
    broker.getEmergencyStopRegistry().revokeEmergencyStopToken({
      tokenId: 'ESTOP-BROKER-001',
      revokedBy: 'sec-ops@example.test',
      reason: 'Emergency stop during broker negative test',
      now
    });
    const killedRes = await broker.executeBrokeredPassiveRequest(
      {
        requestId: 'REQ-006',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: makeSignedGrant('nonce-broker-0006'),
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-BROKER-001',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netRes.policy.policy_digest,
        now
      },
      async () => ({
        statusCode: 200,
        headers: {},
        body: 'should-not-run',
        connectedSocketPeerIp: '93.184.216.34'
      })
    );
    assert.equal(killedRes.allowed, false);
    assert.equal(killedRes.reason, 'scan_cancelled');

    const metrics = broker.getBrokerMetrics();
    assert.equal(metrics.allowedCount, 1);
    assert.equal(metrics.droppedCount, 5);
    assert.equal(metrics.prohibitedAllowedCount, 0);

    const auditIntegrity = broker.verifyAuditLogIntegrity();
    assert.equal(auditIntegrity.valid, true);
    assert.equal(auditIntegrity.entriesChecked, 6);
  });
});

describe('Sprint C (P1): Real scanner binary probes, source drift re-test, and TLS/HTML boundary matrix', () => {
  it('Real Semgrep binary execution against repository fixture (or SKIP not verified if binary not installed)', async (t) => {
    const semgrepProbe = await probeInstalledBinaryVersion('semgrep');
    if (!semgrepProbe.installed) {
      t.skip(`SKIP (not verified): semgrep binary not installed on host (${semgrepProbe.reason})`);
      return;
    }
    const sampleRepo = resolve(process.cwd(), 'examples/synthetic-targets/laravel-app');
    const rulepackPath = resolve(process.cwd(), 'examples/synthetic-targets/semgrep-rules.yml');
    const repoGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      profile: 'source',
      allowed_checks: ['CODE-001'],
      allowed_repositories: [sampleRepo]
    };
    const res = await runSemgrepAdapter({
      grant: repoGrant,
      repositoryPath: sampleRepo,
      rulepackRef: rulepackPath,
      timeoutMs: 30000
    });
    assert.equal(res.coverage.tool_status, 'exited');
    assert.equal(res.coverage.status, 'executed');
    assert.equal(res.findings.length >= 1, true);
  });

  it('Real Trivy binary execution against repository fixture (or SKIP not verified if binary not installed)', async (t) => {
    const trivyProbe = await probeInstalledBinaryVersion('trivy');
    if (!trivyProbe.installed) {
      t.skip(`SKIP (not verified): trivy binary not installed on host (${trivyProbe.reason})`);
      return;
    }
    const sampleRepo = resolve(process.cwd(), 'examples/synthetic-targets/laravel-app');
    const repoGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      profile: 'source',
      allowed_checks: ['DEP-001'],
      allowed_repositories: [sampleRepo]
    };
    const res = await runTrivyAdapter({
      grant: repoGrant,
      repositoryPath: sampleRepo,
      timeoutMs: 30000
    });
    assert.equal(res.coverage.tool_status, 'exited');
    assert.equal(res.coverage.status, 'executed');
  });

  it('Semgrep and Trivy subprocess runners enforce shell:false, offline flags, timeout failures, and Trivy DB freshness', async () => {
    const repoGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      profile: 'source',
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: [process.cwd()]
    };

    let capturedSemgrepArgs: readonly string[] = [];
    let capturedSemgrepShell: boolean | undefined;
    const semgrepTimeoutRes = await runSemgrepAdapter({
      grant: repoGrant,
      repositoryPath: process.cwd(),
      rulepackRef: 'p/security-audit',
      execRunner: (_file, args, opts, cb) => {
        capturedSemgrepArgs = args;
        capturedSemgrepShell = opts.shell;
        const err = new Error('Command timed out after 15000ms') as NodeJS.ErrnoException;
        err.code = 'ETIMEDOUT';
        cb(err, '', '');
      }
    });
    assert.equal(capturedSemgrepShell, false);
    assert.equal(capturedSemgrepArgs.includes('--metrics=off'), true);
    assert.equal(capturedSemgrepArgs.includes('--disable-version-check'), true);
    assert.equal(capturedSemgrepArgs.includes('p/security-audit'), true);
    assert.equal(semgrepTimeoutRes.coverage.status, 'failed');
    assert.equal(semgrepTimeoutRes.coverage.tool_status, 'timed_out');
    assert.equal(semgrepTimeoutRes.coverage.timed_out, true);

    let capturedTrivyArgs: readonly string[] = [];
    const staleTrivyRes = await runTrivyAdapter({
      grant: repoGrant,
      repositoryPath: process.cwd(),
      now: new Date('2026-11-04T20:00:00.000Z'),
      execRunner: (_file, args, _opts, cb) => {
        capturedTrivyArgs = args;
        cb(
          null,
          JSON.stringify({
            SchemaVersion: 2,
            Metadata: {
              Version: '0.57.0',
              NextUpdate: '2026-10-01T00:00:00.000Z'
            },
            Results: []
          }),
          ''
        );
      }
    });
    assert.equal(capturedTrivyArgs.includes('--skip-db-update'), true);
    assert.equal(capturedTrivyArgs.includes('--offline-scan'), true);
    assert.equal(staleTrivyRes.coverage.status, 'failed');
    assert.equal(staleTrivyRes.coverage.db_freshness, 'stale');
    assert.equal(staleTrivyRes.coverage.positive_validation_passed, false);
  });

  it('compareScanReports detects Semgrep rulepack_version drift, stale Trivy DB, and notes db_version drift', async () => {
    const repoGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      profile: 'source',
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: [process.cwd()]
    };

    const baselineExec = await executeScan({
      grant: repoGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-SRC-BASE',
      repositoryPath: process.cwd(),
      fixture: {
        fixture_id: 'SRC-BASE-FIXTURE',
        description: 'Baseline source and dependency findings',
        endpoints: [],
        semgrep_fixture: {
          version: '1.96.0',
          results: [
            {
              check_id: 'javascript.express.security.audit.xss.direct-response-write',
              path: 'src/app.ts',
              start: { line: 42, col: 5 },
              extra: {
                message: 'Unescaped user input written directly to response',
                severity: 'WARNING'
              }
            }
          ]
        },
        trivy_fixture: {
          SchemaVersion: 2,
          Metadata: { Version: '0.57.0', NextUpdate: '2026-12-01T00:00:00.000Z' },
          Results: [
            {
              Target: 'package-lock.json',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'CVE-2026-12345',
                  PkgName: 'legacy-parser',
                  InstalledVersion: '1.0.0',
                  FixedVersion: '1.0.1',
                  Severity: 'HIGH',
                  Title: 'Prototype pollution in legacy-parser'
                }
              ]
            }
          ]
        }
      }
    });
    const targetCleanExec = await executeScan({
      grant: repoGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-SRC-TARGET',
      repositoryPath: process.cwd(),
      fixture: {
        fixture_id: 'SRC-CLEAN-FIXTURE',
        description: 'Remediated source and dependency fixture',
        endpoints: [],
        semgrep_fixture: { version: '1.96.0', results: [] },
        trivy_fixture: {
          SchemaVersion: 2,
          Metadata: { Version: '0.57.0', NextUpdate: '2026-12-31T00:00:00.000Z' },
          Results: []
        }
      }
    });

    // 1. Rulepack version drift -> not_comparable for CODE-001
    const driftedRulepackTarget: ScanReport = {
      ...targetCleanExec.report,
      coverage: {
        ...targetCleanExec.report.coverage,
        checks: targetCleanExec.report.coverage.checks.map((c) =>
          c.rule_id === 'CODE-001'
            ? { ...c, rulepack_version: 'p/different-rulepack-v2' }
            : c
        )
      }
    };
    const rulepackDiff = compareScanReports(baselineExec.report, driftedRulepackTarget);
    const codeItem = rulepackDiff.items.find((i) => i.rule_id === 'CODE-001');
    assert.ok(codeItem);
    assert.equal(codeItem.recheck_state, 'not_comparable');
    assert.equal(codeItem.explanation.includes('Scanner rulepack version drifted'), true);

    // 2. Stale DB -> not_comparable for DEP-001
    const staleDbTarget: ScanReport = {
      ...targetCleanExec.report,
      coverage: {
        ...targetCleanExec.report.coverage,
        checks: targetCleanExec.report.coverage.checks.map((c) =>
          c.rule_id === 'DEP-001' ? { ...c, db_freshness: 'stale' } : c
        )
      }
    };
    const staleDiff = compareScanReports(baselineExec.report, staleDbTarget);
    const depStaleItem = staleDiff.items.find((i) => i.rule_id === 'DEP-001');
    assert.ok(depStaleItem);
    assert.equal(depStaleItem.recheck_state, 'not_comparable');

    // 3. Fresh DB with updated db_version -> verified_fixed with drift note
    const updatedDbTarget: ScanReport = {
      ...targetCleanExec.report,
      coverage: {
        ...targetCleanExec.report.coverage,
        checks: targetCleanExec.report.coverage.checks.map((c) =>
          c.rule_id === 'DEP-001'
            ? { ...c, db_freshness: 'fresh', db_version: '2026-12-31T00:00:00.000Z' }
            : c
        )
      }
    };
    const updatedDbDiff = compareScanReports(baselineExec.report, updatedDbTarget);
    const depFixedItem = updatedDbDiff.items.find((i) => i.rule_id === 'DEP-001');
    assert.ok(depFixedItem);
    assert.equal(depFixedItem.recheck_state, 'verified_fixed');
    assert.equal(depFixedItem.explanation.includes('Scanner DB version drift noted'), true);
  });

  it('WEB-TLS-001 evaluates handshake errors as failed coverage, detects expired/weak/mismatch TLS, and verifies fixes on re-test', async () => {
    const tlsGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      allowed_checks: ['WEB-HEADER-001', 'WEB-TLS-001']
    };

    // 1. Handshake error -> status: 'failed' & global_status: 'completed_with_gaps'
    const handshakeErrExec = await executeScan({
      grant: tlsGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-TLS-ERR',
      fixture: {
        fixture_id: 'TLS-HANDSHAKE-ERROR-FIXTURE',
        description: 'TLS handshake timeout / reset',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: { 'content-type': 'text/html' },
            tls: {
              protocol: 'TLSv1.3',
              certificate_valid: false,
              hostname_matches: false,
              days_until_expiry: 0,
              trust_context_verified: false,
              handshake_error: 'ERR_TLS_HANDSHAKE_TIMEOUT'
            }
          }
        ]
      }
    });
    assert.equal(handshakeErrExec.report.coverage.global_status, 'completed_with_gaps');
    const tlsErrCov = handshakeErrExec.report.coverage.checks.find(
      (c) => c.rule_id === 'WEB-TLS-001'
    );
    assert.ok(tlsErrCov);
    assert.equal(tlsErrCov.status, 'failed');
    assert.equal(tlsErrCov.positive_validation_passed, false);

    // 2. Expired certificate (days_until_expiry <= 0), TLSv1.1, hostname mismatch -> findings -> re-test fix -> verified_fixed
    const weakTlsExec = await executeScan({
      grant: tlsGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-TLS-WEAK',
      fixture: {
        fixture_id: 'TLS-WEAK-FIXTURE',
        description: 'Expired cert, TLSv1.1, hostname mismatch',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: { 'content-type': 'text/html' },
            tls: {
              protocol: 'TLSv1.1',
              certificate_valid: false,
              hostname_matches: false,
              days_until_expiry: -5,
              trust_context_verified: true
            }
          }
        ]
      }
    });
    const tlsFindings = weakTlsExec.report.findings.filter((f) => f.rule_id === 'WEB-TLS-001');
    assert.equal(tlsFindings.length >= 1, true);
    assert.equal(
      tlsFindings.some((f) => f.observed_condition.includes('certificate expired')),
      true
    );

    const fixedTlsExec = await executeScan({
      grant: tlsGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-TLS-FIXED',
      fixture: {
        fixture_id: 'TLS-FIXED-FIXTURE',
        description: 'Remediated TLSv1.3 endpoint',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: { 'content-type': 'text/html' },
            tls: {
              protocol: 'TLSv1.3',
              certificate_valid: true,
              hostname_matches: true,
              days_until_expiry: 90,
              trust_context_verified: true
            }
          }
        ]
      }
    });
    const tlsDiff = compareScanReports(weakTlsExec.report, fixedTlsExec.report);
    const tlsDiffItems = tlsDiff.items.filter((i) => i.rule_id === 'WEB-TLS-001');
    assert.equal(tlsDiffItems.length >= 1, true);
    assert.equal(
      tlsDiffItems.every((i) => i.recheck_state === 'verified_fixed'),
      true
    );
  });

  it('HTML report escapes XSS payloads in headers/URLs and failed checks produce completed_with_gaps', async () => {
    const xssExec = await executeScan({
      grant: baseGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-XSS-TEST-001',
      fixture: {
        fixture_id: 'XSS-NEGATIVE-FIXTURE',
        description: 'Adversarial header values with HTML/JS injection',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: {
              'content-type': 'text/html',
              'set-cookie': ['session_id=secret123; Path=/"><script>alert(1)</script>']
            }
          }
        ]
      }
    });

    const html = renderHtmlReport(xssExec.report);
    assert.equal(html.includes('<script>alert(1)</script>'), false);
    assert.equal(html.includes('secret123'), false);
  });
});

describe('Sprint 7: Docker outcome analysis, Synthetic Laravel/Next.js/Node.js targets, Egress Broker HTTP Server, Production Hardening & Release Gate', () => {
  it('analyzeDockerRunOutcome never mistakes Docker CLI / missing-image errors (125/126/127) for security success', () => {
    // 1. Docker CLI exit 125 (missing image / daemon error) -> MUST NOT be securityControlVerified
    const missingImg = analyzeDockerRunOutcome({
      executed: true,
      exitCode: 125,
      stdout: '',
      stderr: 'Unable to find image hegosentinel-worker:0.1.0-alpha.4 locally',
      expectation: { expectZeroExit: false, requiredErrorMarkerPattern: /EROFS/ }
    });
    assert.equal(missingImg.dockerCliError, true);
    assert.equal(missingImg.securityControlVerified, false);

    // 2. Command not found inside container (exit 127) -> MUST NOT be securityControlVerified
    const missingBin = analyzeDockerRunOutcome({
      executed: true,
      exitCode: 127,
      stdout: '',
      stderr: 'sh: 1: wget: not found',
      expectation: { expectZeroExit: false }
    });
    assert.equal(missingBin.dockerCliError, true);
    assert.equal(missingBin.securityControlVerified, false);

    // 3. Genuine kernel EROFS inside container -> securityControlVerified = true
    const realErofs = analyzeDockerRunOutcome({
      executed: true,
      exitCode: 1,
      stdout: '',
      stderr: "Error: EROFS: read-only file system, open '/workspace/target-repo/escape'",
      expectation: { expectZeroExit: false, requiredErrorMarkerPattern: /EROFS/ }
    });
    assert.equal(realErofs.dockerCliError, false);
    assert.equal(realErofs.securityControlVerified, true);

    // 4. Genuine WKR001_VERIFIED stdout probe -> securityControlVerified = true
    const wkr001Probe = analyzeDockerRunOutcome({
      executed: true,
      exitCode: 0,
      stdout: 'WKR001_VERIFIED uid=65532 gid=65532 capEff=0000000000000000 noNewPrivs=1 netErr=ENETUNREACH\n',
      stderr: '',
      expectation: { expectZeroExit: true, requiredStdoutPattern: /WKR001_VERIFIED/ }
    });
    assert.equal(wkr001Probe.dockerCliError, false);
    assert.equal(wkr001Probe.securityControlVerified, true);
  });

  it('normalizes synthetic Laravel, Next.js, and Node.js source vulnerabilities, dependency CVEs, and misconfigurations', async () => {
    const syntheticRaw = JSON.parse(
      readFileSync(
        resolve(process.cwd(), 'examples/synthetic-targets/recorded-scanner-outputs.json'),
        'utf8'
      )
    );
    const targetsRoot = resolve(process.cwd(), 'examples/synthetic-targets');
    const synthGrant: ScopeAuthorizationGrant = {
      ...baseGrant,
      stack: ['laravel', 'nextjs', 'generic-web'],
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: [targetsRoot]
    };

    for (const stackKey of ['laravel', 'nextjs', 'nodejs'] as const) {
      const repoDir = resolve(targetsRoot, `${stackKey}-app`);
      const sgRes = await runSemgrepAdapter({
        grant: synthGrant,
        repositoryPath: repoDir,
        rulepackRef: 'hegosentinel-local-ruleset@1.2.0',
        fixtureOutput: syntheticRaw[stackKey].semgrep
      });
      assert.equal(sgRes.coverage.status, 'executed');
      assert.equal(sgRes.coverage.tool_version, 'semgrep-1.183.0');
      assert.equal(sgRes.coverage.rulepack_version, 'hegosentinel-local-ruleset@1.2.0');
      assert.equal(sgRes.findings.length, 2);

      const tvRes = await runTrivyAdapter({
        grant: synthGrant,
        repositoryPath: repoDir,
        fixtureOutput: syntheticRaw[stackKey].trivy,
        now: new Date('2026-11-05T00:00:00.000Z')
      });
      assert.equal(tvRes.coverage.status, 'executed');
      assert.equal(tvRes.coverage.tool_version, 'trivy-0.76.1');
      assert.equal(tvRes.coverage.db_freshness, 'fresh');
      assert.equal(tvRes.findings.length >= 1, true);
    }
  });

  it('runs out-of-process createTrustedEgressBrokerServer over HTTP and enforces EGR-001..006 & control-plane auth', async () => {
    const controlSecret = 'control-plane-broker-http-secret-2026';
    const signerSecret = 'grant-signer-broker-http-secret-2026';
    const broker = new TrustedEgressBroker({
      trustedSigners: { 'hegosentinel-control-plane-signer-v1': signerSecret },
      resolver: publicResolver
    });

    const serverOptions = {
      broker,
      controlPlaneSecret: controlSecret,
      upstreamTransport: async (params: { url: string; pinnedIp: string }) => ({
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: `<html lang="en">brokered:${params.url}</html>`,
        connectedSocketPeerIp: params.pinnedIp
      })
    };

    const server = createTrustedEgressBrokerServer(serverOptions);
    assert.ok(server);

    const invokeHttp = async (params: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
    }): Promise<{ status: number; json: Record<string, unknown> }> => {
      const bodyStr = params.body !== undefined ? JSON.stringify(params.body) : '';
      const mockReq = {
        method: params.method,
        url: params.url,
        headers: params.headers ?? {},
        on(event: string, listener: (...args: unknown[]) => void) {
          if (event === 'data' && bodyStr.length > 0) {
            listener(bodyStr);
          }
          if (event === 'end') {
            listener();
          }
          return this;
        }
      } as unknown as IncomingMessage;

      let status = 200;
      let rawResponse = '{}';
      const mockRes = {
        statusCode: 200,
        setHeader() {},
        writeHead(code: number) {
          status = code;
          return this;
        },
        end(data?: string) {
          if (data) rawResponse = data;
          return this;
        }
      } as unknown as ServerResponse;

      await handleTrustedEgressBrokerHttpRequest(mockReq, mockRes, serverOptions);
      return { status, json: JSON.parse(rawResponse) as Record<string, unknown> };
    };

    // 1. Unauthorized policy registration without X-HegoSentinel-Control-Secret -> 403
    const unauthPolicyRes = await invokeHttp({
      method: 'POST',
      url: '/v1/egress/policy',
      body: {}
    });
    assert.equal(unauthPolicyRes.status, 403);

    // 2. Register valid PerRunNetworkPolicy with control secret -> 200
    const netPol = await generatePerRunNetworkPolicy({
      runId: 'RUN-HTTP-BROKER-01',
      grant: baseGrant,
      resolver: publicResolver,
      now: new Date('2026-11-04T20:00:00.000Z')
    });
    assert.ok(netPol.policy);

    const regRes = await invokeHttp({
      method: 'POST',
      url: '/v1/egress/policy',
      headers: { 'x-hegosentinel-control-secret': controlSecret },
      body: netPol.policy
    });
    assert.equal(regRes.status, 200);

    // 3. Valid passive GET via POST /v1/egress/fetch -> 200 ALLOW
    const signedGrant = signRemoteExecutionGrant(
      {
        signer_id: 'hegosentinel-control-plane-signer-v1',
        run_id: 'RUN-HTTP-BROKER-01',
        organization_id: baseGrant.organization_id,
        project_id: baseGrant.project_id,
        grant_id: baseGrant.grant_id,
        scope_version: baseGrant.scope_version,
        target_scheme: 'https',
        target_host: 'demo.example.test',
        target_port: 443,
        target_path_prefix: '/',
        allowed_methods: ['GET', 'HEAD'],
        max_request_budget: 5,
        network_policy_id: netPol.policy.policy_digest,
        emergency_stop_token_id: 'ESTOP-HTTP-01',
        nonce: 'nonce-http-broker-0001',
        // The broker clock is authoritative over HTTP (a worker-supplied clock value is ignored), so the grant
        // must be valid in real time.
        issued_at: new Date(Date.now() - 60_000).toISOString(),
        expires_at: new Date(Date.now() + 180_000).toISOString()
      },
      signerSecret
    );

    const fetchRes = await invokeHttp({
      method: 'POST',
      url: '/v1/egress/fetch',
      body: {
        requestId: 'HTTP-REQ-1',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: signedGrant,
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-HTTP-BROKER-01',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netPol.policy.policy_digest
      }
    });
    assert.equal(fetchRes.status, 200);
    assert.equal(fetchRes.json.allowed, true);
    assert.equal(fetchRes.json.action, 'ALLOW');

    // 4. Replay of same nonce over HTTP -> 403 DROP
    const replayRes = await invokeHttp({
      method: 'POST',
      url: '/v1/egress/fetch',
      body: {
        requestId: 'HTTP-REQ-2',
        url: 'https://demo.example.test/',
        method: 'GET',
        signedExecutionGrant: signedGrant,
        scopeGrant: baseGrant,
        expectedRunId: 'RUN-HTTP-BROKER-01',
        expectedOrganizationId: baseGrant.organization_id,
        expectedProjectId: baseGrant.project_id,
        expectedGrantId: baseGrant.grant_id,
        expectedScopeVersion: baseGrant.scope_version,
        expectedNetworkPolicyId: netPol.policy.policy_digest
      }
    });
    assert.equal(replayRes.status, 403);

    // 5. Verify audit log integrity via GET /v1/egress/audit
    const auditRes = await invokeHttp({
      method: 'GET',
      url: '/v1/egress/audit',
      headers: { 'x-hegosentinel-control-secret': controlSecret }
    });
    assert.equal(auditRes.status, 200);
    const auditJson = auditRes.json as {
      integrity: { valid: boolean };
      metrics: { prohibitedAllowedCount: number };
    };
    assert.equal(auditJson.integrity.valid, true);
    assert.equal(auditJson.metrics.prohibitedAllowedCount, 0);
  });

  it('enforces Production Security: report tenant isolation, TamperEvidentAuditLog, extended secret scrubbing, safe output paths, and release gate blocker', async () => {
    // 1. TamperEvidentAuditLog + authorizeReportTenantAccess
    const auditLog = new TamperEvidentAuditLog();
    const contaminatedDecision = authorizeReportTenantAccess({
      principal: {
        user_id: 'owner-1',
        organization_id: 'org-alpha',
        project_ids: ['proj-1'],
        role: 'owner'
      },
      report: {
        report_id: 'REP-ALPHA-1',
        organization_id: 'org-alpha',
        project_id: 'proj-1',
        findings: [{ id: 'F-LEAK', organization_id: 'org-beta', project_id: 'proj-9' }]
      },
      action: 'export_artifact',
      auditLog
    });
    assert.equal(contaminatedDecision.allowed, false);
    assert.equal(auditLog.verifyIntegrity().valid, true);

    // 2. executeScan aborts immediately when EmergencyStopRegistry has cancelled the run
    const stopRegistry = new EmergencyStopRegistry();
    stopRegistry.cancelRun({
      runId: 'SCAN-CANCELLED-RUN',
      cancelledBy: 'sec-ops',
      reason: 'Emergency halt'
    });
    const cancelledScan = await executeScan({
      grant: baseGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-CANCELLED-RUN',
      emergencyStopRegistry: stopRegistry
    });
    assert.equal(cancelledScan.policyDecision.allowed, false);
    assert.equal(cancelledScan.report.coverage.global_status, 'denied');

    // 3. Extended redactSensitiveText (PEM private key, DB URI, APP_KEY, NEXTAUTH_SECRET)
    const sensitiveSample = [
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
      'postgres://dbadmin:SuperSecretPass123@db.internal.local:5432/hegosentinel',
      'APP_KEY=base64:YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
      'NEXTAUTH_SECRET="my-ultra-secret-nextauth-signing-key"'
    ].join('\n');
    const redacted = redactSensitiveText(sensitiveSample);
    assert.equal(redacted.includes('MIIEpAIBAAKCAQEA'), false);
    assert.equal(redacted.includes('SuperSecretPass123'), false);
    assert.equal(redacted.includes('YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo='), false);
    assert.equal(redacted.includes('my-ultra-secret-nextauth-signing-key'), false);

    // 4. validateSafeReportOutputPath blocks traversal and non-report extensions
    const rootOut = resolve(process.cwd(), 'reports');
    assert.equal(validateSafeReportOutputPath('demo-baseline.json', rootOut).allowed, true);
    assert.equal(validateSafeReportOutputPath('../package.json', rootOut).allowed, false);
    assert.equal(validateSafeReportOutputPath('exploit.sh', rootOut).allowed, false);

    // 5. evaluateProductionReleaseReadiness blocks release if any gate is SKIP or FAIL
    const blockedEval = evaluateProductionReleaseReadiness([
      {
        gate_id: 'SEC-001',
        category: 'SEC',
        execution_layer: 'host-deterministic',
        verdict: 'PASS',
        title: 'ok',
        code_reference: 'ref',
        test_reference: 'test',
        test_environment: 'env',
        tool_version: 'v1',
        log_evidence: 'ok',
        residual_risk: 'None',
        reproducible_command: 'npm test'
      },
      {
        gate_id: 'WKR-001-RUNTIME',
        category: 'WKR',
        execution_layer: 'linux-docker-runtime',
        verdict: 'SKIP',
        title: 'docker',
        code_reference: 'ref',
        test_reference: 'test',
        test_environment: 'env',
        tool_version: 'v1',
        log_evidence: 'SKIP â€” NOT VERIFIED',
        residual_risk: 'Requires Linux Docker',
        reproducible_command: 'bash ./scripts/linux-docker-verify.sh'
      }
    ]);
    assert.equal(blockedEval.release_allowed, false);
    assert.deepEqual(blockedEval.skipped_unverified_gates, ['WKR-001-RUNTIME']);
  });
});

