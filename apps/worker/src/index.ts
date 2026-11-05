import { execFile } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AllowedHttpMethod, ScopeAuthorizationGrant } from '../../../packages/findings-schema/src/index.ts';
import {
  classifyIpAddress,
  parseAndValidateCanonicalUrl,
  resolveAndPinDestination,
  validateRedirectTransition,
  validateScopeAuthorizationGrant,
  verifyConnectedSocketPeer,
  type DnsResolver,
  type PolicyDecision
} from '../../../packages/policy-engine/src/index.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKER_ROOT = resolve(__dirname, '..');

export const DENIED_IPV4_CIDRS: readonly string[] = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '169.254.169.254/32',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '255.255.255.255/32'
];

export const DENIED_IPV6_CIDRS: readonly string[] = [
  '::/128',
  '::1/128',
  '::ffff:0:0/96',
  '64:ff9b::/96',
  '100::/64',
  '2001::/32',
  '2001:2::/48',
  '2001:db8::/32',
  '2002::/16',
  'fc00::/7',
  'fd00:ec2::254/128',
  'fe80::/10',
  'ff00::/8'
];

export interface WorkerMountRule {
  target: string;
  type: 'bind' | 'tmpfs';
  read_only: boolean;
  max_size_bytes?: number;
  options: string[];
}

export interface WorkerContainerPolicy {
  schema_version: '1.0.0';
  workload_name: string;
  separated_from_api_container: boolean;
  user: string;
  privileged: boolean;
  host_docker_socket_mounted: boolean;
  read_only_root_filesystem: boolean;
  no_new_privileges: boolean;
  cap_drop: string[];
  cap_add: string[];
  seccomp_profile: string;
  default_network_mode: 'none' | 'restricted-netns';
  limits: {
    max_cpu_cores: number;
    max_memory_bytes: number;
    max_pids: number;
    max_run_time_seconds: number;
    max_open_files: number;
  };
  mounts: WorkerMountRule[];
}

export function loadDefaultWorkerContainerPolicy(): WorkerContainerPolicy {
  const raw = readFileSync(resolve(WORKER_ROOT, 'container-policy.json'), 'utf8');
  return JSON.parse(raw) as WorkerContainerPolicy;
}

export function computeCanonicalSha256(payload: unknown): string {
  return createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex');
}

/**
 * Validates that the scanner worker container policy enforces strict unprivileged isolation (Sprint 1 — P0).
 */
export function validateWorkerContainerPolicy(policy: WorkerContainerPolicy): {
  valid: boolean;
  policyDigest: string;
  errors: string[];
} {
  const errors: string[] = [];

  if (!policy.separated_from_api_container) {
    errors.push('Worker workload must be separated from the API container');
  }
  if (policy.privileged) {
    errors.push('Privileged container mode is strictly forbidden');
  }
  if (policy.host_docker_socket_mounted) {
    errors.push('Mounting host Docker socket (/var/run/docker.sock) is strictly forbidden');
  }
  if (!policy.read_only_root_filesystem) {
    errors.push('Root filesystem must be mounted read-only');
  }
  if (!policy.no_new_privileges) {
    errors.push('security-opt no-new-privileges:true is required');
  }

  const userParts = String(policy.user ?? '').split(':');
  const uid = Number.parseInt(userParts[0] ?? '0', 10);
  const gid = Number.parseInt(userParts[1] ?? userParts[0] ?? '0', 10);
  if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || gid <= 0) {
    errors.push(`Worker user "${policy.user}" must be non-root (UID > 0 and GID > 0)`);
  }

  if (!Array.isArray(policy.cap_drop) || !policy.cap_drop.includes('ALL')) {
    errors.push('cap_drop must include "ALL"');
  }
  if (Array.isArray(policy.cap_add) && policy.cap_add.length > 0) {
    errors.push('Unprivileged worker container must not add Linux capabilities');
  }
  if (policy.default_network_mode !== 'none') {
    errors.push('Default worker network mode must be "none" (disabled networking by default)');
  }

  const limits = policy.limits;
  if (!limits || limits.max_cpu_cores <= 0 || limits.max_cpu_cores > 4) {
    errors.push('limits.max_cpu_cores must be bounded between (0, 4]');
  }
  if (!limits || limits.max_memory_bytes <= 0 || limits.max_memory_bytes > 2 * 1024 * 1024 * 1024) {
    errors.push('limits.max_memory_bytes must be bounded and <= 2 GiB');
  }
  if (!limits || limits.max_pids <= 0 || limits.max_pids > 256) {
    errors.push('limits.max_pids must be bounded between [1, 256]');
  }
  if (!limits || limits.max_run_time_seconds <= 0 || limits.max_run_time_seconds > 300) {
    errors.push('limits.max_run_time_seconds must be bounded between [1, 300]');
  }

  for (const m of policy.mounts ?? []) {
    if (m.target.includes('docker.sock')) {
      errors.push(`Forbidden mount target "${m.target}"`);
    }
    if (m.target === '/workspace/target-repo' && !m.read_only) {
      errors.push('Target repository mount (/workspace/target-repo) must be read-only');
    }
    if (!m.options.includes('nosuid') || !m.options.includes('nodev') || !m.options.includes('noexec')) {
      errors.push(`Mount "${m.target}" must enforce nosuid, nodev, and noexec options`);
    }
  }

  return {
    valid: errors.length === 0,
    policyDigest: computeCanonicalSha256(policy),
    errors
  };
}

export interface AllowedEgressEndpoint {
  hostname: string;
  ip: string;
  ipFamily: 4 | 6;
  port: number;
  protocol: 'tcp';
}

export interface PerRunNetworkPolicy {
  run_id: string;
  grant_id: string;
  scope_version: number;
  default_action: 'DROP';
  denied_ipv4_cidrs: readonly string[];
  denied_ipv6_cidrs: readonly string[];
  allowed_egress_endpoints: AllowedEgressEndpoint[];
  policy_digest: string;
}

/**
 * Generates an explicit per-run network egress policy from a validated ScopeAuthorizationGrant (Sprint 1 — P0).
 * Denies all private/loopback/link-local/metadata/IPv6-transition ranges and allows only resolved, public
 * pinned IP + approved port tuples.
 */
export async function generatePerRunNetworkPolicy(params: {
  runId: string;
  grant: ScopeAuthorizationGrant;
  resolver: DnsResolver;
  now?: Date;
}): Promise<{ decision: PolicyDecision; policy?: PerRunNetworkPolicy }> {
  const grantDecision = validateScopeAuthorizationGrant(params.grant, params.now);
  if (!grantDecision.allowed) {
    return { decision: grantDecision };
  }

  const allowedEndpoints: AllowedEgressEndpoint[] = [];

  for (const target of params.grant.targets) {
    const candidateUrl = `${target.scheme}://${target.hostname}:${target.port}${target.path_prefix || '/'}`;
    const urlCheck = parseAndValidateCanonicalUrl(candidateUrl, params.grant, 'GET');
    if (!urlCheck.decision.allowed || !urlCheck.target) {
      return { decision: urlCheck.decision };
    }

    const pinCheck = await resolveAndPinDestination(urlCheck.target, params.resolver);
    if (!pinCheck.decision.allowed || !pinCheck.pinned) {
      return { decision: pinCheck.decision };
    }

    for (const resolvedIp of pinCheck.pinned.allResolvedIps) {
      const ipClass = classifyIpAddress(resolvedIp);
      if (!ipClass.allowed) {
        return {
          decision: {
            allowed: false,
            reason: 'blocked_destination',
            detail: `Host ${target.hostname} resolved to disallowed IP ${resolvedIp} (${ipClass.category})`
          }
        };
      }
      const ipFamily: 4 | 6 = resolvedIp.includes(':') ? 6 : 4;
      const alreadyExists = allowedEndpoints.some(
        (e) =>
          e.ip === resolvedIp &&
          e.port === target.port &&
          e.hostname === target.hostname.toLowerCase()
      );
      if (!alreadyExists) {
        allowedEndpoints.push({
          hostname: target.hostname.toLowerCase(),
          ip: resolvedIp,
          ipFamily,
          port: target.port,
          protocol: 'tcp'
        });
      }
    }
  }

  const unsignedPolicy = {
    run_id: params.runId,
    grant_id: params.grant.grant_id,
    scope_version: params.grant.scope_version,
    default_action: 'DROP' as const,
    denied_ipv4_cidrs: DENIED_IPV4_CIDRS,
    denied_ipv6_cidrs: DENIED_IPV6_CIDRS,
    allowed_egress_endpoints: allowedEndpoints
  };

  const policyDigest = computeCanonicalSha256(unsignedPolicy);

  return {
    decision: {
      allowed: true,
      detail: `Generated per-run network policy ${policyDigest.slice(0, 12)} with ${allowedEndpoints.length} pinned endpoint(s)`
    },
    policy: {
      ...unsignedPolicy,
      policy_digest: policyDigest
    }
  };
}

/**
 * Renders the deterministic nftables ruleset for a PerRunNetworkPolicy.
 */
export function renderNftablesRuleset(policy: PerRunNetworkPolicy): string {
  const ipv4AllowRules = policy.allowed_egress_endpoints
    .filter((e) => e.ipFamily === 4)
    .map((e) => `    ip daddr ${e.ip} tcp dport ${e.port} ct state new,established accept`)
    .join('\n');

  const ipv6AllowRules = policy.allowed_egress_endpoints
    .filter((e) => e.ipFamily === 6)
    .map((e) => `    ip6 daddr ${e.ip} tcp dport ${e.port} ct state new,established accept`)
    .join('\n');

  return [
    `# HegoSentinel Per-Run Egress Ruleset (run_id=${policy.run_id}, digest=${policy.policy_digest})`,
    'table inet hegosentinel_egress {',
    '  chain output {',
    '    type filter hook output priority 0; policy drop;',
    '    ct state invalid drop',
    `    ip daddr { ${policy.denied_ipv4_cidrs.join(', ')} } counter drop`,
    `    ip6 daddr { ${policy.denied_ipv6_cidrs.join(', ')} } counter drop`,
    '    ct state established,related accept',
    ipv4AllowRules,
    ipv6AllowRules,
    '  }',
    '}'
  ]
    .filter((line) => line.length > 0)
    .join('\n');
}

export interface NetworkNamespaceConnectionLog {
  timestamp: string;
  hostname: string;
  peerIp: string;
  port: number;
  protocol: 'tcp';
  action: 'ALLOW' | 'DROP';
  reason: string;
}

/**
 * Simulated network-namespace packet/socket filter that enforces PerRunNetworkPolicy independently
 * of application-level URL checks and records a verifiable audit log of all connection attempts.
 */
export class SimulatedNetworkNamespaceFirewall {
  private readonly policy: PerRunNetworkPolicy;
  private readonly logs: NetworkNamespaceConnectionLog[] = [];

  constructor(policy: PerRunNetworkPolicy) {
    this.policy = policy;
  }

  public checkAndRecordConnection(params: {
    hostname: string;
    peerIp: string;
    port: number;
    now?: Date;
  }): PolicyDecision {
    const timestamp = (params.now ?? new Date()).toISOString();
    const cleanIp = params.peerIp.trim().replace(/^\[|\]$/g, '');
    const ipClassification = classifyIpAddress(cleanIp);

    if (!ipClassification.allowed) {
      const reason = `netns_egress_drop: destination IP ${cleanIp} belongs to prohibited range (${ipClassification.category})`;
      this.logs.push({
        timestamp,
        hostname: params.hostname,
        peerIp: cleanIp,
        port: params.port,
        protocol: 'tcp',
        action: 'DROP',
        reason
      });
      return {
        allowed: false,
        reason: 'blocked_destination',
        detail: reason
      };
    }

    const matchedRule = this.policy.allowed_egress_endpoints.find(
      (ep) =>
        ep.ip === cleanIp &&
        ep.port === params.port &&
        ep.hostname === params.hostname.toLowerCase()
    );

    if (!matchedRule) {
      const reason = `netns_egress_drop: peer (${ params.hostname } -> ${cleanIp}:${params.port}) is not in per-run pinned allowlist`;
      this.logs.push({
        timestamp,
        hostname: params.hostname,
        peerIp: cleanIp,
        port: params.port,
        protocol: 'tcp',
        action: 'DROP',
        reason
      });
      return {
        allowed: false,
        reason: 'dns_rebind_detected',
        detail: reason
      };
    }

    const reason = `netns_egress_allow: matched pinned endpoint ${cleanIp}:${params.port}`;
    this.logs.push({
      timestamp,
      hostname: params.hostname,
      peerIp: cleanIp,
      port: params.port,
      protocol: 'tcp',
      action: 'ALLOW',
      reason
    });

    return {
      allowed: true,
      detail: reason
    };
  }

  public getLogs(): readonly NetworkNamespaceConnectionLog[] {
    return this.logs;
  }

  public getAllowedConnections(): NetworkNamespaceConnectionLog[] {
    return this.logs.filter((l) => l.action === 'ALLOW');
  }

  public getDroppedConnections(): NetworkNamespaceConnectionLog[] {
    return this.logs.filter((l) => l.action === 'DROP');
  }

  public getProhibitedAllowedCount(): number {
    return this.getAllowedConnections().filter((conn) => {
      const ipCheck = classifyIpAddress(conn.peerIp);
      if (!ipCheck.allowed) return true;
      return !this.policy.allowed_egress_endpoints.some(
        (ep) => ep.ip === conn.peerIp && ep.port === conn.port
      );
    }).length;
  }
}

export interface WorkerCapabilityAttestation {
  worker_id: string;
  run_id: string;
  grant_id: string;
  scope_version: number;
  container_policy_digest: string;
  network_policy_digest: string;
  os_netns_enforced: boolean;
  issued_at: string;
  expires_at: string;
  signature: string;
}

function serializeAttestationPayload(
  att: Omit<WorkerCapabilityAttestation, 'signature'>
): string {
  return [
    att.worker_id,
    att.run_id,
    att.grant_id,
    String(att.scope_version),
    att.container_policy_digest,
    att.network_policy_digest,
    att.os_netns_enforced ? '1' : '0',
    att.issued_at,
    att.expires_at
  ].join('|');
}

/**
 * Signs a WorkerCapabilityAttestation using a supervisor-held HMAC-SHA256 secret (Sprint 1 — Item 4).
 * A caller-provided boolean is never accepted in place of a cryptographically signed attestation.
 */
export function signWorkerCapabilityAttestation(
  payload: Omit<WorkerCapabilityAttestation, 'signature'>,
  supervisorSecret: string
): WorkerCapabilityAttestation {
  if (!supervisorSecret || supervisorSecret.length < 16) {
    throw new Error('Supervisor attestation secret must be at least 16 characters');
  }
  const canonical = serializeAttestationPayload(payload);
  const signature = createHmac('sha256', supervisorSecret).update(canonical, 'utf8').digest('hex');
  return {
    ...payload,
    signature
  };
}

/**
 * Verifies a signed WorkerCapabilityAttestation against the active grant, container policy, and per-run network policy.
 */
export function verifyWorkerCapabilityAttestation(params: {
  attestation: unknown;
  supervisorSecret: string;
  grant: ScopeAuthorizationGrant;
  expectedRunId: string;
  expectedContainerPolicyDigest: string;
  expectedNetworkPolicyDigest: string;
  now?: Date;
}): PolicyDecision {
  if (!params.attestation || typeof params.attestation !== 'object') {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Missing or non-object worker capability attestation; caller-supplied booleans are never accepted'
    };
  }

  const att = params.attestation as Partial<WorkerCapabilityAttestation>;
  if (
    typeof att.worker_id !== 'string' ||
    typeof att.run_id !== 'string' ||
    typeof att.grant_id !== 'string' ||
    typeof att.scope_version !== 'number' ||
    typeof att.container_policy_digest !== 'string' ||
    typeof att.network_policy_digest !== 'string' ||
    typeof att.os_netns_enforced !== 'boolean' ||
    typeof att.issued_at !== 'string' ||
    typeof att.expires_at !== 'string' ||
    typeof att.signature !== 'string'
  ) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Malformed worker capability attestation structure'
    };
  }

  const expectedSignature = createHmac('sha256', params.supervisorSecret)
    .update(
      serializeAttestationPayload({
        worker_id: att.worker_id,
        run_id: att.run_id,
        grant_id: att.grant_id,
        scope_version: att.scope_version,
        container_policy_digest: att.container_policy_digest,
        network_policy_digest: att.network_policy_digest,
        os_netns_enforced: att.os_netns_enforced,
        issued_at: att.issued_at,
        expires_at: att.expires_at
      }),
      'utf8'
    )
    .digest('hex');

  if (att.signature !== expectedSignature) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Invalid HMAC-SHA256 signature on worker capability attestation'
    };
  }

  if (att.grant_id !== params.grant.grant_id || att.scope_version !== params.grant.scope_version) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker attestation grant_id or scope_version does not match active authorization grant'
    };
  }

  if (att.run_id !== params.expectedRunId) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker attestation run_id mismatch (replay blocked)'
    };
  }

  if (att.container_policy_digest !== params.expectedContainerPolicyDigest) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker attestation container_policy_digest does not match validated container policy'
    };
  }

  if (att.network_policy_digest !== params.expectedNetworkPolicyDigest) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker attestation network_policy_digest does not match per-run network policy'
    };
  }

  const nowMs = (params.now ?? new Date()).getTime();
  const expiresMs = Date.parse(att.expires_at);
  if (Number.isNaN(expiresMs) || nowMs >= expiresMs) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker capability attestation has expired'
    };
  }

  if (!att.os_netns_enforced) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Worker attestation reports os_netns_enforced=false; fail-closed'
    };
  }

  return {
    allowed: true,
    detail: `Verified cryptographic worker attestation for ${att.worker_id} (run ${att.run_id})`
  };
}

export interface ControlledTransportHopInput {
  url: string;
  method: AllowedHttpMethod;
  pinnedIp: string;
  port: number;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface ControlledTransportHopOutput {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
  connectedSocketPeerIp: string;
  tlsProtocol?: string;
}

export type ControlledPassiveTransport = (
  input: ControlledTransportHopInput
) => Promise<ControlledTransportHopOutput>;

export interface BoundedPassiveRequestOptions {
  url: string;
  method?: string;
  grant: ScopeAuthorizationGrant;
  resolver: DnsResolver;
  firewall: SimulatedNetworkNamespaceFirewall;
  transport: ControlledPassiveTransport;
  maxTimeoutMs?: number;
  maxResponseBytes?: number;
  maxRedirects?: number;
  maxRetries?: number;
  signal?: AbortSignal;
  now?: Date;
}

export interface BoundedPassiveRequestResult {
  allowed: boolean;
  aborted: boolean;
  reason?: string;
  detail: string;
  hopsExecuted: number;
  finalResponse?: ControlledTransportHopOutput;
}

/**
 * Executes a strictly bounded passive HTTP/TLS request (GET/HEAD only) with:
 * - Method allowlist (GET/HEAD only, zero active payloads)
 * - Per-hop URL & scope validation
 * - DNS resolution + IP pinning
 * - Independent Network Namespace Firewall check
 * - Connected socket peer IP verification (DNS rebinding guard)
 * - Bounded body size (maxResponseBytes <= 65,536)
 * - Bounded timeout (maxTimeoutMs <= 10,000) & retries (maxRetries <= 1)
 * - AbortSignal kill-switch cancellation
 */
export async function executeBoundedPassiveRequest(
  options: BoundedPassiveRequestOptions
): Promise<BoundedPassiveRequestResult> {
  const methodUpper = (options.method ?? 'GET').toUpperCase();
  if (methodUpper !== 'GET' && methodUpper !== 'HEAD') {
    return {
      allowed: false,
      aborted: true,
      reason: 'disallowed_method',
      detail: `Passive scanner worker only permits GET or HEAD requests; blocked "${methodUpper}"`,
      hopsExecuted: 0
    };
  }
  const method = methodUpper as AllowedHttpMethod;

  const maxTimeoutMs = Math.min(Math.max(options.maxTimeoutMs ?? 5000, 100), 10_000);
  const maxResponseBytes = Math.min(Math.max(options.maxResponseBytes ?? 32_768, 512), 65_536);
  const maxRedirects = Math.min(Math.max(options.maxRedirects ?? 3, 0), 3);
  const maxRetries = Math.min(Math.max(options.maxRetries ?? 0, 0), 1);
  const utf8Encoder = new TextEncoder();

  let currentUrl = options.url;
  let redirectDepth = 0;

  while (true) {
    if (options.signal?.aborted) {
      return {
        allowed: false,
        aborted: true,
        reason: 'scan_cancelled',
        detail: 'Passive request aborted by kill-switch signal before connection',
        hopsExecuted: redirectDepth
      };
    }

    const urlValidation = parseAndValidateCanonicalUrl(currentUrl, options.grant, method);
    if (!urlValidation.decision.allowed || !urlValidation.target) {
      return {
        allowed: false,
        aborted: true,
        reason: urlValidation.decision.reason ?? 'invalid_url',
        detail: urlValidation.decision.detail,
        hopsExecuted: redirectDepth
      };
    }

    const pinResult = await resolveAndPinDestination(urlValidation.target, options.resolver);
    if (!pinResult.decision.allowed || !pinResult.pinned) {
      return {
        allowed: false,
        aborted: true,
        reason: pinResult.decision.reason ?? 'private_or_reserved_ip',
        detail: pinResult.decision.detail,
        hopsExecuted: redirectDepth
      };
    }

    // Pre-connect Network Namespace Firewall check on pinned IP
    const preNetnsCheck = options.firewall.checkAndRecordConnection({
      hostname: urlValidation.target.hostname,
      peerIp: pinResult.pinned.pinnedIp,
      port: urlValidation.target.port,
      now: options.now
    });
    if (!preNetnsCheck.allowed) {
      return {
        allowed: false,
        aborted: true,
        reason: preNetnsCheck.reason ?? 'private_or_reserved_ip',
        detail: preNetnsCheck.detail,
        hopsExecuted: redirectDepth
      };
    }

    let hopOutput: ControlledTransportHopOutput | undefined;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (options.signal?.aborted) {
        return {
          allowed: false,
          aborted: true,
          reason: 'scan_cancelled',
          detail: 'Passive request aborted by kill-switch signal during attempt',
          hopsExecuted: redirectDepth
        };
      }
      try {
        hopOutput = await options.transport({
          url: urlValidation.target.url,
          method,
          pinnedIp: pinResult.pinned.pinnedIp,
          port: urlValidation.target.port,
          timeoutMs: maxTimeoutMs,
          signal: options.signal
        });
        break;
      } catch (err) {
        lastError = err as Error;
        if (options.signal?.aborted) {
          return {
            allowed: false,
            aborted: true,
            reason: 'scan_cancelled',
            detail: 'Passive request aborted by kill-switch signal',
            hopsExecuted: redirectDepth
          };
        }
      }
    }

    if (!hopOutput) {
      return {
        allowed: false,
        aborted: true,
        reason: 'transport_error',
        detail: `Transport failed after ${maxRetries + 1} attempt(s): ${lastError?.message ?? 'unknown error'}`,
        hopsExecuted: redirectDepth
      };
    }

    // Verify actual socket peer IP against both the Network Namespace Firewall and pinned IP (TOCTOU DNS rebind guard)
    if (hopOutput.connectedSocketPeerIp !== pinResult.pinned.pinnedIp) {
      options.firewall.checkAndRecordConnection({
        hostname: urlValidation.target.hostname,
        peerIp: hopOutput.connectedSocketPeerIp,
        port: urlValidation.target.port,
        now: options.now
      });
    }
    const peerDecision = verifyConnectedSocketPeer(
      pinResult.pinned,
      hopOutput.connectedSocketPeerIp
    );
    if (!peerDecision.allowed) {
      return {
        allowed: false,
        aborted: true,
        reason: peerDecision.reason ?? 'dns_rebind_detected',
        detail: peerDecision.detail,
        hopsExecuted: redirectDepth + 1
      };
    }

    // Enforce bounded response body size
    const bodyBytes = utf8Encoder.encode(hopOutput.body ?? '').byteLength;
    if (bodyBytes > maxResponseBytes) {
      return {
        allowed: false,
        aborted: true,
        reason: 'response_body_exceeded_limit',
        detail: `Response body size (${bodyBytes} bytes) exceeds maximum allowed (${maxResponseBytes} bytes)`,
        hopsExecuted: redirectDepth + 1
      };
    }

    // Check if response is a redirect (301, 302, 303, 307, 308)
    const isRedirect =
      hopOutput.statusCode === 301 ||
      hopOutput.statusCode === 302 ||
      hopOutput.statusCode === 303 ||
      hopOutput.statusCode === 307 ||
      hopOutput.statusCode === 308;

    const rawLocation = hopOutput.headers['location'] ?? hopOutput.headers['Location'];
    const locationHeader = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;

    if (isRedirect && typeof locationHeader === 'string' && locationHeader.length > 0) {
      const redirectCheck = await validateRedirectTransition({
        fromUrl: urlValidation.target,
        locationHeader,
        redirectDepth,
        maxRedirects,
        grant: options.grant,
        resolver: options.resolver
      });

      if (!redirectCheck.decision.allowed || !redirectCheck.nextPinned) {
        // Also record the blocked redirect target in the firewall log if it resolved to a disallowed IP
        return {
          allowed: false,
          aborted: true,
          reason: redirectCheck.decision.reason ?? 'out_of_scope_redirect',
          detail: redirectCheck.decision.detail,
          hopsExecuted: redirectDepth + 1
        };
      }

      currentUrl = redirectCheck.nextPinned.canonicalUrl.url;
      redirectDepth += 1;
      continue;
    }

    return {
      allowed: true,
      aborted: false,
      detail: `Completed bounded passive ${method} request in ${redirectDepth + 1} hop(s)`,
      hopsExecuted: redirectDepth + 1,
      finalResponse: hopOutput
    };
  }
}

// ============================================================================
// Sprint A (P0 — G0.5): source-offline Runtime Manifest & Real Docker Runner
// ============================================================================

export interface SourceOfflineRuntimeManifest {
  schema_version: '1.0.0';
  profile: 'source-offline';
  description: string;
  image: string;
  user: string;
  privileged: boolean;
  read_only_root_filesystem: boolean;
  no_new_privileges: boolean;
  cap_drop: string[];
  cap_add: string[];
  network_mode: 'none';
  seccomp_profile: string;
  host_docker_socket_mounted: boolean;
  allow_repo_hooks_or_scripts: boolean;
  forbidden_mount_substrings: string[];
  forbidden_env_keys: string[];
  limits: {
    cpus: string;
    memory_bytes: number;
    pids_limit: number;
    timeout_ms: number;
    sigkill_grace_ms: number;
  };
  mounts: {
    target_repo_container_path: string;
    target_repo_options: string[];
    scratch_tmpfs_path: string;
    scratch_tmpfs_size_bytes: number;
    scratch_tmpfs_options: string[];
  };
}

export function loadSourceOfflineManifest(): SourceOfflineRuntimeManifest {
  const raw = readFileSync(resolve(WORKER_ROOT, 'source-offline-manifest.json'), 'utf8');
  return JSON.parse(raw) as SourceOfflineRuntimeManifest;
}

/**
 * Builds the deterministic `docker run` argument vector for the `source-offline` worker profile (Sprint A / G0.5).
 * Enforces:
 * - `--network=none` (HTTP/remote scans cannot run under source-offline)
 * - `--user=65532:65532`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`
 * - `--pids-limit`, `--memory`, `--cpus`
 * - Read-only repository bind mount (`readonly`) and bounded `noexec,nosuid,nodev` tmpfs scratch space
 * - Rejects any forbidden host mount (`docker.sock`, `.ssh`, `.aws`, `/etc/shadow`) or secret env var
 */
export function buildDockerRunArgsForSourceOffline(params: {
  manifest: SourceOfflineRuntimeManifest;
  authorizedRepoHostPath: string;
  seccompProfileHostPath?: string;
  extraEnv?: Record<string, string>;
  commandArgs?: string[];
}): { allowed: boolean; args?: string[]; reason?: string } {
  const { manifest } = params;
  if (manifest.profile !== 'source-offline' || manifest.network_mode !== 'none') {
    return {
      allowed: false,
      reason: 'source-offline profile requires network_mode="none" (zero network access)'
    };
  }
  if (manifest.privileged || manifest.host_docker_socket_mounted || !manifest.read_only_root_filesystem) {
    return {
      allowed: false,
      reason: 'source-offline manifest violates unprivileged read-only container policy'
    };
  }
  if (manifest.cap_add.length > 0 || !manifest.cap_drop.includes('ALL')) {
    return {
      allowed: false,
      reason: 'source-offline worker must drop ALL capabilities and never add capabilities (no CAP_NET_ADMIN)'
    };
  }

  const normalizedHostRepo = params.authorizedRepoHostPath.replace(/\\/g, '/');
  for (const forbidden of manifest.forbidden_mount_substrings) {
    if (normalizedHostRepo.toLowerCase().includes(forbidden.toLowerCase())) {
      return {
        allowed: false,
        reason: `Forbidden host mount path "${params.authorizedRepoHostPath}" matched "${forbidden}" (WKR-002)`
      };
    }
  }

  if (params.extraEnv) {
    for (const envKey of Object.keys(params.extraEnv)) {
      if (
        manifest.forbidden_env_keys.some((k) => k.toLowerCase() === envKey.toLowerCase()) ||
        /secret|token|password|private_key/i.test(envKey)
      ) {
        return {
          allowed: false,
          reason: `Forbidden secret or proxy environment variable "${envKey}" rejected for source-offline worker (WKR-002)`
        };
      }
    }
  }

  const seccompPath =
    params.seccompProfileHostPath ?? resolve(WORKER_ROOT, manifest.seccomp_profile);
  const tmpfsOpts = [
    ...manifest.mounts.scratch_tmpfs_options,
    `size=${manifest.mounts.scratch_tmpfs_size_bytes}`
  ].join(',');

  const args: string[] = [
    'run',
    '--rm',
    '--init',
    '--network=none',
    `--user=${manifest.user}`,
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true',
    `--security-opt=seccomp=${seccompPath}`,
    `--cpus=${manifest.limits.cpus}`,
    `--memory=${manifest.limits.memory_bytes}`,
    `--memory-swap=${manifest.limits.memory_bytes}`,
    `--pids-limit=${manifest.limits.pids_limit}`,
    '--mount',
    `type=bind,src=${params.authorizedRepoHostPath},dst=${manifest.mounts.target_repo_container_path},readonly`,
    '--tmpfs',
    `${manifest.mounts.scratch_tmpfs_path}:${tmpfsOpts}`,
    '-e',
    'HEGOSENTINEL_PROFILE=source-offline',
    '-e',
    'SEMGREP_SEND_METRICS=off',
    '-e',
    'SEMGREP_ENABLE_VERSION_CHECK=0',
    '-e',
    'TRIVY_NO_PROGRESS=true',
    '-e',
    'HTTP_PROXY=',
    '-e',
    'HTTPS_PROXY=',
    '-e',
    'ALL_PROXY=',
    manifest.image,
    ...(params.commandArgs ?? [])
  ];

  return { allowed: true, args };
}

/**
 * Probes whether a real Docker Engine daemon is installed and responsive on the current host.
 * Used by WKR-001..WKR-006 runtime tests so missing Docker environments report `SKIP (not verified)`
 * and NEVER a false `PASS`.
 */
export async function probeDockerRuntimeAvailability(): Promise<{
  available: boolean;
  serverVersion?: string;
  reason?: string;
}> {
  return new Promise((resolvePromise) => {
    execFile(
      'docker',
      ['info', '--format', '{{.ServerVersion}}'],
      { shell: false, timeout: 4000, windowsHide: true },
      (error, stdout) => {
        if (error) {
          resolvePromise({
            available: false,
            reason: `Docker Engine not available on host (${error.code ?? error.message})`
          });
          return;
        }
        const ver = stdout.trim();
        if (!ver) {
          resolvePromise({
            available: false,
            reason: 'Docker CLI returned empty ServerVersion'
          });
          return;
        }
        resolvePromise({ available: true, serverVersion: ver });
      }
    );
  });
}

/**
 * Resolves the executable path and augmented PATH for `semgrep` or `trivy`,
 * supporting both global system PATH and portable `.tools/` installations.
 */
export function resolveLocalScannerBinary(binary: 'semgrep' | 'trivy'): {
  executable: string;
  augmentedPath: string;
} {
  const repoRoot = resolve(WORKER_ROOT, '../..');
  const toolsBin = resolve(repoRoot, '.tools/bin');
  const venvScriptsWin = resolve(repoRoot, '.tools/semgrep-venv/Scripts');
  const venvBinPosix = resolve(repoRoot, '.tools/semgrep-venv/bin');
  const pathSep = process.platform === 'win32' ? ';' : ':';
  const augmentedPath = [
    toolsBin,
    venvScriptsWin,
    venvBinPosix,
    process.env.PATH ?? ''
  ].join(pathSep);

  const candidates =
    binary === 'trivy'
      ? [
          resolve(toolsBin, process.platform === 'win32' ? 'trivy.exe' : 'trivy'),
          resolve(toolsBin, 'trivy')
        ]
      : [
          resolve(venvScriptsWin, 'semgrep.exe'),
          resolve(venvBinPosix, 'semgrep'),
          resolve(toolsBin, process.platform === 'win32' ? 'semgrep.exe' : 'semgrep')
        ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return { executable: candidate, augmentedPath };
    }
  }
  return { executable: binary, augmentedPath };
}

/**
 * Probes whether a real scanner binary (`semgrep` or `trivy`) is installed in PATH or `.tools/`.
 */
export async function probeInstalledBinaryVersion(
  binary: 'semgrep' | 'trivy'
): Promise<{ installed: boolean; version?: string; reason?: string }> {
  const { executable, augmentedPath } = resolveLocalScannerBinary(binary);
  return new Promise((resolvePromise) => {
    execFile(
      executable,
      ['--version'],
      {
        shell: false,
        timeout: 10000,
        windowsHide: true,
        env: {
          PATH: augmentedPath,
          SYSTEMROOT: process.env.SYSTEMROOT ?? 'C:\\Windows',
          TEMP: process.env.TEMP ?? process.env.TMP ?? '/tmp',
          TMP: process.env.TMP ?? process.env.TEMP ?? '/tmp',
          HOME: process.env.HOME ?? process.env.USERPROFILE ?? '/tmp',
          USERPROFILE: process.env.USERPROFILE ?? '/tmp',
          APPDATA: process.env.APPDATA ?? '',
          LOCALAPPDATA: process.env.LOCALAPPDATA ?? '',
          PYTHONUTF8: '1',
          SEMGREP_SEND_METRICS: 'off',
          SEMGREP_ENABLE_VERSION_CHECK: '0'
        }
      },
      (error, stdout) => {
        if (error) {
          resolvePromise({
            installed: false,
            reason: `${binary} binary not installed in PATH (${error.code ?? error.message})`
          });
          return;
        }
        resolvePromise({ installed: true, version: stdout.trim().split('\n')[0]?.trim() ?? 'unknown' });
      }
    );
  });
}

// ============================================================================
// Sprint B (P0 — G0.6): External Egress Broker & Short-Lived Signed Grant
// ============================================================================
// ARCHITECTURAL TRUST BOUNDARY NOTE:
// 1. `source-offline` uses `--network=none`; HTTP/TLS requests cannot work under `--network=none`.
// 2. `remote-web` workers NEVER receive `CAP_NET_ADMIN`. Network policy is enforced by an external
//    Trusted Egress Broker / Host Orchestrator outside the worker container.
// 3. An HMAC signature (`SignedRemoteExecutionGrant`) is NOT proof of kernel/netns enforcement.
//    It proves only that an authorized control-plane signer (`signer_id`) issued a short-lived,
//    single-use (`nonce`) execution grant bound to a specific project, target, scope_version, and policy ID.

export const MAX_REMOTE_GRANT_TTL_MS = 300_000; // 5 minutes maximum TTL

export interface SignedRemoteExecutionGrant {
  signer_id: string;
  run_id: string;
  organization_id: string;
  project_id: string;
  grant_id: string;
  scope_version: number;
  target_scheme: 'https' | 'http';
  target_host: string;
  target_port: number;
  target_path_prefix: string;
  allowed_methods: AllowedHttpMethod[];
  max_request_budget: number;
  network_policy_id: string;
  emergency_stop_token_id: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  signature: string;
}

export class NonceReplayRegistry {
  private readonly consumedNonces = new Set<string>();

  public checkAndConsume(nonce: string): boolean {
    if (!nonce || nonce.trim().length < 8) return false;
    if (this.consumedNonces.has(nonce)) {
      return false;
    }
    this.consumedNonces.add(nonce);
    return true;
  }

  public has(nonce: string): boolean {
    return this.consumedNonces.has(nonce);
  }
}

function serializeRemoteExecutionGrant(
  g: Omit<SignedRemoteExecutionGrant, 'signature'>
): string {
  return [
    g.signer_id,
    g.run_id,
    g.organization_id,
    g.project_id,
    g.grant_id,
    String(g.scope_version),
    g.target_scheme,
    g.target_host.toLowerCase(),
    String(g.target_port),
    g.target_path_prefix,
    g.allowed_methods.join(','),
    String(g.max_request_budget),
    g.network_policy_id,
    g.emergency_stop_token_id,
    g.nonce,
    g.issued_at,
    g.expires_at
  ].join('|');
}

export function signRemoteExecutionGrant(
  payload: Omit<SignedRemoteExecutionGrant, 'signature'>,
  signerSecret: string
): SignedRemoteExecutionGrant {
  if (!signerSecret || signerSecret.length < 16) {
    throw new Error('Control-plane signer secret must be at least 16 characters');
  }
  const signature = createHmac('sha256', signerSecret)
    .update(serializeRemoteExecutionGrant(payload), 'utf8')
    .digest('hex');
  return { ...payload, signature };
}

export function validateCleanProxyEnvironment(
  env: NodeJS.ProcessEnv = process.env
): PolicyDecision {
  const proxyKeys = [
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy'
  ];
  for (const key of proxyKeys) {
    const val = env[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      return {
        allowed: false,
        reason: 'remote_egress_isolation_unverified',
        detail: `Ambient proxy environment variable ${key} is set; remote worker execution blocked to prevent proxy egress escape`
      };
    }
  }
  return { allowed: true, detail: 'Ambient proxy environment variables are empty' };
}

/**
 * Verifies a short-lived SignedRemoteExecutionGrant issued by a trusted control-plane signer (Sprint B / G0.6).
 * Enforces:
 * - Trusted `signer_id` lookup (rejects self-signed or unknown signers)
 * - HMAC-SHA256 integrity
 * - Short TTL (`<= 300s`) and non-expired timestamp
 * - Single-use `nonce` via `NonceReplayRegistry` (blocks replay)
 * - Exact binding to `run_id`, `organization_id`, `project_id`, `grant_id`, `scope_version`, `target_host`, `target_port`, and `network_policy_id` (blocks grant substitution)
 * - Clean proxy environment check
 */
export function verifySignedRemoteExecutionGrant(params: {
  signedGrant: unknown;
  trustedSigners: Record<string, string>;
  replayRegistry: NonceReplayRegistry;
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
  const proxyCheck = validateCleanProxyEnvironment(params.env ?? {});
  if (!proxyCheck.allowed) {
    return proxyCheck;
  }

  if (!params.signedGrant || typeof params.signedGrant !== 'object') {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Missing or invalid SignedRemoteExecutionGrant object'
    };
  }

  const g = params.signedGrant as Partial<SignedRemoteExecutionGrant>;
  if (
    typeof g.signer_id !== 'string' ||
    typeof g.run_id !== 'string' ||
    typeof g.organization_id !== 'string' ||
    typeof g.project_id !== 'string' ||
    typeof g.grant_id !== 'string' ||
    typeof g.scope_version !== 'number' ||
    (g.target_scheme !== 'https' && g.target_scheme !== 'http') ||
    typeof g.target_host !== 'string' ||
    typeof g.target_port !== 'number' ||
    typeof g.target_path_prefix !== 'string' ||
    !Array.isArray(g.allowed_methods) ||
    typeof g.max_request_budget !== 'number' ||
    typeof g.network_policy_id !== 'string' ||
    typeof g.emergency_stop_token_id !== 'string' ||
    typeof g.nonce !== 'string' ||
    typeof g.issued_at !== 'string' ||
    typeof g.expires_at !== 'string' ||
    typeof g.signature !== 'string'
  ) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Malformed SignedRemoteExecutionGrant structure'
    };
  }

  const signerSecret = params.trustedSigners[g.signer_id];
  if (!signerSecret) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `Untrusted or unknown grant signer_id "${g.signer_id}" (self-signed grants are forbidden)`
    };
  }

  const expectedSig = createHmac('sha256', signerSecret)
    .update(
      serializeRemoteExecutionGrant({
        signer_id: g.signer_id,
        run_id: g.run_id,
        organization_id: g.organization_id,
        project_id: g.project_id,
        grant_id: g.grant_id,
        scope_version: g.scope_version,
        target_scheme: g.target_scheme,
        target_host: g.target_host,
        target_port: g.target_port,
        target_path_prefix: g.target_path_prefix,
        allowed_methods: g.allowed_methods,
        max_request_budget: g.max_request_budget,
        network_policy_id: g.network_policy_id,
        emergency_stop_token_id: g.emergency_stop_token_id,
        nonce: g.nonce,
        issued_at: g.issued_at,
        expires_at: g.expires_at
      }),
      'utf8'
    )
    .digest('hex');

  if (g.signature !== expectedSig) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Invalid HMAC-SHA256 signature on SignedRemoteExecutionGrant'
    };
  }

  const nowMs = (params.now ?? new Date()).getTime();
  const issuedMs = Date.parse(g.issued_at);
  const expiresMs = Date.parse(g.expires_at);
  if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs) || expiresMs <= issuedMs) {
    return {
      allowed: false,
      reason: 'scope_expired',
      detail: 'SignedRemoteExecutionGrant has invalid issued_at / expires_at timestamps'
    };
  }
  if (expiresMs - issuedMs > MAX_REMOTE_GRANT_TTL_MS) {
    return {
      allowed: false,
      reason: 'scope_expired',
      detail: `SignedRemoteExecutionGrant TTL (${expiresMs - issuedMs}ms) exceeds maximum allowed (${MAX_REMOTE_GRANT_TTL_MS}ms)`
    };
  }
  if (nowMs >= expiresMs || nowMs < issuedMs) {
    return {
      allowed: false,
      reason: 'scope_expired',
      detail: 'SignedRemoteExecutionGrant is expired or not yet active (stale grant rejected)'
    };
  }

  if (
    g.run_id !== params.expectedRunId ||
    g.organization_id !== params.expectedOrganizationId ||
    g.project_id !== params.expectedProjectId ||
    g.grant_id !== params.expectedGrantId ||
    g.scope_version !== params.expectedScopeVersion ||
    g.target_host.toLowerCase() !== params.expectedTargetHost.toLowerCase() ||
    g.target_port !== params.expectedTargetPort ||
    g.network_policy_id !== params.expectedNetworkPolicyId
  ) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail:
        'Grant substitution blocked: SignedRemoteExecutionGrant context (run/org/project/grant/scope_version/target/network_policy_id) does not match current execution'
    };
  }

  if (!g.allowed_methods.every((m) => m === 'GET' || m === 'HEAD')) {
    return {
      allowed: false,
      reason: 'disallowed_method',
      detail: 'SignedRemoteExecutionGrant contains non-passive HTTP methods'
    };
  }

  if (!params.replayRegistry.checkAndConsume(g.nonce)) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `Grant replay blocked: nonce "${g.nonce}" has already been consumed or is invalid`
    };
  }

  return {
    allowed: true,
    detail: `Verified short-lived SignedRemoteExecutionGrant from trusted signer "${g.signer_id}" (run=${g.run_id}, nonce=${g.nonce})`
  };
}

export const PINNED_SEMGREP_VERSION = '1.183.0';
export const PINNED_TRIVY_VERSION = '0.76.1';

export interface DockerRunOutcomeAnalysis {
  dockerCliError: boolean;
  securityControlVerified: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  reason: string;
}

const DOCKER_CLI_FAILURE_PATTERNS = [
  /Unable to find image/i,
  /pull access denied/i,
  /Cannot connect to the Docker daemon/i,
  /Error response from daemon/i,
  /OCI runtime create failed/i,
  /executable file not found/i,
  /unknown flag:/i,
  /flag provided but not defined/i,
  /invalid argument/i
];

/**
 * Sprint 7 (WKR-001..005): Analyzes exitCode, stdout, and stderr from a `docker run` invocation.
 * Strictly prevents Docker CLI / missing-image / command-not-found errors (exit codes 125, 126, 127)
 * from ever being misinterpreted as a container security block success.
 */
export function analyzeDockerRunOutcome(params: {
  executed: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  expectation: {
    expectZeroExit: boolean;
    requiredStdoutPattern?: RegExp;
    requiredErrorMarkerPattern?: RegExp;
  };
}): DockerRunOutcomeAnalysis {
  if (!params.executed || params.exitCode === null) {
    return {
      dockerCliError: true,
      securityControlVerified: false,
      exitCode: params.exitCode,
      stdout: params.stdout,
      stderr: params.stderr,
      reason: 'Docker command was not executed on host'
    };
  }

  // Exit codes 125 (docker daemon/cli failure), 126 (cannot invoke), 127 (command not found)
  const isExitCodeCliFailure =
    params.exitCode === 125 || params.exitCode === 126 || params.exitCode === 127;
  const matchedDaemonError = DOCKER_CLI_FAILURE_PATTERNS.find((re) => re.test(params.stderr));

  if (isExitCodeCliFailure || matchedDaemonError) {
    return {
      dockerCliError: true,
      securityControlVerified: false,
      exitCode: params.exitCode,
      stdout: params.stdout,
      stderr: params.stderr,
      reason: `Docker CLI or container launch failure (exitCode=${params.exitCode}): ${params.stderr.trim() || 'daemon/CLI error'}; failed commands are never treated as security success`
    };
  }

  if (params.expectation.expectZeroExit) {
    if (params.exitCode !== 0) {
      return {
        dockerCliError: false,
        securityControlVerified: false,
        exitCode: params.exitCode,
        stdout: params.stdout,
        stderr: params.stderr,
        reason: `Expected exitCode=0 inside container, got ${params.exitCode} (stderr=${params.stderr.trim()})`
      };
    }
    if (
      params.expectation.requiredStdoutPattern &&
      !params.expectation.requiredStdoutPattern.test(params.stdout)
    ) {
      return {
        dockerCliError: false,
        securityControlVerified: false,
        exitCode: params.exitCode,
        stdout: params.stdout,
        stderr: params.stderr,
        reason: `Container exited 0, but stdout "${params.stdout.trim()}" did not match expected pattern ${params.expectation.requiredStdoutPattern}`
      };
    }
    return {
      dockerCliError: false,
      securityControlVerified: true,
      exitCode: params.exitCode,
      stdout: params.stdout,
      stderr: params.stderr,
      reason: `Verified container security invariant (exitCode=0, stdout=${params.stdout.trim()})`
    };
  }

  // Expecting a non-zero exit caused by kernel/container security enforcement (e.g., EROFS, ENETUNREACH, EAGAIN)
  if (params.exitCode === 0) {
    return {
      dockerCliError: false,
      securityControlVerified: false,
      exitCode: 0,
      stdout: params.stdout,
      stderr: params.stderr,
      reason: 'Forbidden operation unexpectedly succeeded inside container (exitCode=0)'
    };
  }

  const combinedOutput = `${params.stdout}\n${params.stderr}`;
  if (
    params.expectation.requiredErrorMarkerPattern &&
    !params.expectation.requiredErrorMarkerPattern.test(combinedOutput)
  ) {
    return {
      dockerCliError: false,
      securityControlVerified: false,
      exitCode: params.exitCode,
      stdout: params.stdout,
      stderr: params.stderr,
      reason: `Process exited non-zero (${params.exitCode}), but output "${combinedOutput.trim()}" did not contain expected security enforcement marker ${params.expectation.requiredErrorMarkerPattern}`
    };
  }

  return {
    dockerCliError: false,
    securityControlVerified: true,
    exitCode: params.exitCode,
    stdout: params.stdout,
    stderr: params.stderr,
    reason: `Verified kernel/container security block (exitCode=${params.exitCode}, output=${combinedOutput.trim().slice(0, 160)})`
  };
}

/**
 * Executes a real `docker run` command using `buildDockerRunArgsForSourceOffline` when a live
 * Linux Docker Engine daemon is present on the host (WKR-001..WKR-005 runtime verification).
 */
export async function executeRealDockerWorkerCommand(params: {
  authorizedRepoHostPath: string;
  commandArgs: string[];
  timeoutMs?: number;
}): Promise<{
  executed: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  dockerCliError?: boolean;
  reason?: string;
}> {
  const probe = await probeDockerRuntimeAvailability();
  if (!probe.available) {
    return {
      executed: false,
      exitCode: null,
      stdout: '',
      stderr: '',
      reason: probe.reason ?? 'Docker Engine not available on host'
    };
  }

  const normalizedCommandArgs =
    params.commandArgs[0] === '-e' ? ['node', ...params.commandArgs] : params.commandArgs;

  const manifest = loadSourceOfflineManifest();
  const buildRes = buildDockerRunArgsForSourceOffline({
    manifest,
    authorizedRepoHostPath: params.authorizedRepoHostPath,
    commandArgs: normalizedCommandArgs
  });
  if (!buildRes.allowed || !buildRes.args) {
    return {
      executed: false,
      exitCode: null,
      stdout: '',
      stderr: '',
      reason: buildRes.reason ?? 'Failed to build source-offline docker run arguments'
    };
  }

  return new Promise((resolvePromise) => {
    const child = execFile(
      'docker',
      buildRes.args!,
      {
        shell: false,
        timeout: params.timeoutMs ?? manifest.limits.timeout_ms,
        windowsHide: true
      },
      (error, stdout, stderr) => {
        if (error) {
          const rawCode = (error as { code?: unknown }).code;
          const numericExitCode =
            typeof child.exitCode === 'number'
              ? child.exitCode
              : typeof rawCode === 'number'
                ? rawCode
                : 1;
          const isCliError =
            numericExitCode === 125 ||
            numericExitCode === 126 ||
            numericExitCode === 127 ||
            DOCKER_CLI_FAILURE_PATTERNS.some((re) => re.test(stderr));
          resolvePromise({
            executed: true,
            exitCode: numericExitCode,
            stdout,
            stderr,
            dockerCliError: isCliError,
            reason: error.message
          });
          return;
        }
        resolvePromise({
          executed: true,
          exitCode: 0,
          stdout,
          stderr,
          dockerCliError: false
        });
      }
    );
  });
}

if (process.argv.includes('--self-check')) {
  const uid = typeof process.getuid === 'function' ? process.getuid() : -1;
  const gid = typeof process.getgid === 'function' ? process.getgid() : -1;
  console.log(
    JSON.stringify({
      worker: 'hegosentinel-worker',
      uid,
      gid,
      profile: process.env.HEGOSENTINEL_PROFILE ?? 'source-offline'
    })
  );
}


