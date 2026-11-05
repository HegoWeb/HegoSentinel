import { createHash, createHmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { resolve as resolvePath } from 'node:path';
import { pathToFileURL } from 'node:url';
import type {
  AllowedHttpMethod,
  ScopeAuthorizationGrant
} from '../../../packages/findings-schema/src/index.ts';
import {
  classifyIpAddress,
  EmergencyStopRegistry,
  parseAndValidateCanonicalUrl,
  resolveAndPinDestination,
  validateRedirectTransition,
  verifyConnectedSocketPeer,
  type DnsResolver
} from '../../../packages/policy-engine/src/index.ts';
import { redactSensitiveText } from '../../../packages/report-engine/src/index.ts';
import {
  NonceReplayRegistry,
  verifySignedRemoteExecutionGrant,
  type PerRunNetworkPolicy,
  type SignedRemoteExecutionGrant
} from '../../worker/src/index.ts';

export interface BrokerUpstreamResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
  connectedSocketPeerIp: string;
  tlsServername?: string;
}

export type BrokerUpstreamTransport = (params: {
  url: string;
  method: AllowedHttpMethod;
  pinnedIp: string;
  port: number;
  sanitizedHeaders: Record<string, string>;
  timeoutMs: number;
  maxResponseBytes: number;
  signal?: AbortSignal;
  /**
   * Contract: the transport MUST NOT follow redirects. The broker inspects every redirect
   * (SEC-003) and a follow-up hop is a brand-new brokered request that is re-authorized and
   * carries none of the previous hop's headers.
   */
  followRedirects: false;
}) => Promise<BrokerUpstreamResponse>;

export interface BrokerProxyRequest {
  requestId: string;
  url: string;
  method: string;
  headers?: Record<string, string>;
  signedExecutionGrant: unknown;
  scopeGrant: ScopeAuthorizationGrant;
  expectedRunId: string;
  expectedOrganizationId: string;
  expectedProjectId: string;
  expectedGrantId: string;
  expectedScopeVersion: number;
  expectedNetworkPolicyId: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
  now?: Date;
}

export interface BrokerAuditLogEntry {
  seq: number;
  timestamp: string;
  request_id: string;
  run_id: string;
  organization_id: string;
  project_id: string;
  target_url: string;
  method: string;
  pinned_ip?: string;
  connected_peer_ip?: string;
  action: 'ALLOW' | 'DROP';
  reason: string;
  detail: string;
  prev_hash: string;
  entry_hash: string;
}

export interface BrokerProxyResult {
  allowed: boolean;
  action: 'ALLOW' | 'DROP';
  reason: string;
  detail: string;
  pinnedIp?: string;
  sanitizedRequestHeaders?: Record<string, string>;
  response?: {
    statusCode: number;
    headers: Record<string, string | string[]>;
    body: string;
    connectedSocketPeerIp: string;
  };
  auditEntry: BrokerAuditLogEntry;
}

const FORBIDDEN_OUTBOUND_REQUEST_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-forwarded-for',
  'x-real-ip',
  'forwarded'
]);

/**
 * Deny-by-default outbound request headers. The worker is untrusted: ONLY these optional headers can
 * ever be forwarded to a target (in addition to the two broker-controlled defaults). Everything
 * else (Authorization, Cookie, Origin, Referer, Host, X-Forwarded-*, arbitrary X-* ...) is dropped.
 */
export const BROKER_OUTBOUND_HEADER_ALLOWLIST: ReadonlySet<string> = new Set(['accept-language', 'x-custom-trace']);

const SENSITIVE_QUERY_PARAM_NAME =
  /(token|secret|pass(word|wd)?|pwd|key|auth|sess(ion)?|sid|jwt|bearer|sig(nature)?|cred(ential)?s?|otp|pin|code|nonce|csrf|xsrf|state|cookie|ticket|access|refresh|private|salt|hash|dsn|connection)/i;

function neutralizeLogText(value: string): string {
  // Strip control characters (log injection) and the canonical-hash field separator.
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\|/g, '%7C');
}

/**
 * Produces the ONLY representation of a URL that may ever be logged: no userinfo, no fragment,
 * sensitive query values masked, opaque/long values masked, remaining text secret-scrubbed.
 * Masking happens here, BEFORE the first audit record is created and hashed.
 */
export function sanitizeUrlForAudit(value: string): string {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '[INVALID_URL]';
    const pairs: string[] = [];
    parsed.searchParams.forEach((rawValue: string, rawName: string) => {
      const name = neutralizeLogText(redactSensitiveText(rawName)).slice(0, 48);
      const looksPlain = /^[A-Za-z0-9._~-]{0,32}$/.test(rawValue) && redactSensitiveText(rawValue) === rawValue;
      const masked = SENSITIVE_QUERY_PARAM_NAME.test(rawName) || !looksPlain;
      pairs.push(`${name}=${masked ? '[REDACTED]' : rawValue}`);
    });
    const base = `${parsed.origin}${redactSensitiveText(parsed.pathname)}`;
    // Every component was already masked/scrubbed individually; the final string is NOT re-scrubbed
    // as a whole because broad secret regexes would swallow the remaining (harmless) parameters.
    return neutralizeLogText(pairs.length > 0 ? `${base}?${pairs.join('&')}` : base).slice(0, 1024);
  } catch {
    return '[INVALID_URL]';
  }
}

/** Free-text (decisions, upstream error messages, redirect locations) is untrusted: scrub before logging. */
export function sanitizeAuditText(value: string): string {
  const withUrlsMasked = String(value).replace(/https?:\/\/[^\s"'<>)]+/gi, (m) => sanitizeUrlForAudit(m));
  const scrubbed = redactSensitiveText(withUrlsMasked)
    // Authorization-style credentials that appear inline in error messages
    .replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [REDACTED]')
    // key=value / key: value pairs whose key names a secret
    .replace(
      /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|set-cookie|cookie)\b(\s*[:=]\s*)(?!\[REDACTED)[^\s&;,"')]+/gi,
      '$1$2[REDACTED]'
    );
  return neutralizeLogText(scrubbed).slice(0, 512);
}

function sanitizeAuditId(value: unknown): string {
  return String(value ?? '').replace(/[^A-Za-z0-9._:@-]/g, '_').slice(0, 128);
}

/** Masks sensitive query values of a redirect Location (absolute or relative) returned to the worker. */
function redactLocationHeader(value: string): string {
  try {
    if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return sanitizeUrlForAudit(value);
    const parsed = new URL(value, 'https://placeholder.invalid');
    const sanitized = sanitizeUrlForAudit(parsed.toString());
    return sanitized.replace('https://placeholder.invalid', '');
  } catch {
    return '[REDACTED_LOCATION]';
  }
}

/**
 * Out-of-worker Trusted Egress Broker (Sprint B / G0.6).
 *
 * Security invariants:
 * 1. Runs outside the worker container; the worker NEVER holds CAP_NET_ADMIN or signing keys.
 * 2. Enforces deny-by-default (`DEFAULT_POLICY = DROP`): every request is dropped unless a
 *    registered `PerRunNetworkPolicy` explicitly pins `(ip, port, tcp)` and passes CIDR blocks.
 * 3. Verifies short-lived (`TTL <= 300s`), single-use (`NonceReplayRegistry`) `SignedRemoteExecutionGrant`
 *    signed by a trusted control-plane `signer_id`.
 * 4. Enforces `EmergencyStopRegistry` (`SEC-012`) kill-switch before and during upstream transport.
 * 5. Performs independent DNS `A`/`AAAA` resolution, blocks all private/loopback/metadata/IPv6 ranges,
 *    verifies connected socket peer IP (anti-DNS-rebinding), strips credential headers, caps response
 *    body size, and refuses to follow out-of-scope or HTTP-downgrade redirects.
 */
export class TrustedEgressBroker {
  public readonly defaultAction = 'DROP' as const;
  private readonly trustedSigners: Record<string, string>;
  private readonly replayRegistry: NonceReplayRegistry;
  private readonly emergencyStopRegistry: EmergencyStopRegistry;
  private readonly resolver: DnsResolver;
  private readonly registeredPolicies = new Map<string, PerRunNetworkPolicy>();
  private readonly runRequestCounts = new Map<string, number>();
  private readonly auditLog: BrokerAuditLogEntry[] = [];

  public constructor(params: {
    trustedSigners: Record<string, string>;
    resolver: DnsResolver;
    replayRegistry?: NonceReplayRegistry;
    emergencyStopRegistry?: EmergencyStopRegistry;
  }) {
    this.trustedSigners = { ...params.trustedSigners };
    this.resolver = params.resolver;
    this.replayRegistry = params.replayRegistry ?? new NonceReplayRegistry();
    this.emergencyStopRegistry = params.emergencyStopRegistry ?? new EmergencyStopRegistry();
  }

  public registerPerRunNetworkPolicy(policy: PerRunNetworkPolicy): void {
    if (policy.default_action !== 'DROP') {
      throw new Error('TrustedEgressBroker requires PerRunNetworkPolicy with default_action="DROP"');
    }
    for (const dest of policy.allowed_egress_endpoints) {
      const ipClass = classifyIpAddress(dest.ip);
      if (!ipClass.allowed) {
        throw new Error(
          `Cannot register prohibited destination IP ${dest.ip} (${ipClass.category}) in TrustedEgressBroker`
        );
      }
    }
    this.registeredPolicies.set(policy.policy_digest, policy);
  }

  public getEmergencyStopRegistry(): EmergencyStopRegistry {
    return this.emergencyStopRegistry;
  }

  public getReplayRegistry(): NonceReplayRegistry {
    return this.replayRegistry;
  }

  public getAuditLog(): readonly BrokerAuditLogEntry[] {
    return this.auditLog;
  }

  public verifyAuditLogIntegrity(): { valid: boolean; entriesChecked: number } {
    let expectedPrev = 'GENESIS';
    for (const entry of this.auditLog) {
      if (entry.prev_hash !== expectedPrev) {
        return { valid: false, entriesChecked: entry.seq };
      }
      const canonical = [
        String(entry.seq),
        entry.timestamp,
        entry.request_id,
        entry.run_id,
        entry.organization_id,
        entry.project_id,
        entry.target_url,
        entry.method,
        entry.pinned_ip ?? '',
        entry.connected_peer_ip ?? '',
        entry.action,
        entry.reason,
        entry.detail,
        entry.prev_hash
      ].join('|');
      const computed = createHash('sha256').update(canonical, 'utf8').digest('hex');
      if (computed !== entry.entry_hash) {
        return { valid: false, entriesChecked: entry.seq };
      }
      expectedPrev = entry.entry_hash;
    }
    return { valid: true, entriesChecked: this.auditLog.length };
  }

  public getBrokerMetrics(): {
    totalRequests: number;
    allowedCount: number;
    droppedCount: number;
    prohibitedAllowedCount: number;
  } {
    let allowedCount = 0;
    let droppedCount = 0;
    let prohibitedAllowedCount = 0;
    for (const entry of this.auditLog) {
      if (entry.action === 'ALLOW') {
        allowedCount += 1;
        if (entry.connected_peer_ip) {
          const check = classifyIpAddress(entry.connected_peer_ip);
          if (!check.allowed) {
            prohibitedAllowedCount += 1;
          }
        }
      } else {
        droppedCount += 1;
      }
    }
    return {
      totalRequests: this.auditLog.length,
      allowedCount,
      droppedCount,
      prohibitedAllowedCount
    };
  }

  private recordAudit(params: {
    now: Date;
    requestId: string;
    runId: string;
    organizationId: string;
    projectId: string;
    targetUrl: string;
    method: string;
    pinnedIp?: string;
    connectedPeerIp?: string;
    action: 'ALLOW' | 'DROP';
    reason: string;
    detail: string;
  }): BrokerAuditLogEntry {
    const seq = this.auditLog.length + 1;
    const prevHash =
      this.auditLog.length > 0 ? this.auditLog[this.auditLog.length - 1]!.entry_hash : 'GENESIS';
    const timestamp = params.now.toISOString();
    // SECURITY (B2): every caller-influenced field is neutralized/masked HERE, before the hash chain
    // is computed and before anything is stored â€” raw values never exist in the audit log.
    const requestId = sanitizeAuditId(params.requestId);
    const runId = sanitizeAuditId(params.runId);
    const organizationId = sanitizeAuditId(params.organizationId);
    const projectId = sanitizeAuditId(params.projectId);
    const targetUrl = sanitizeUrlForAudit(params.targetUrl);
    const method = sanitizeAuditId(params.method).toUpperCase();
    const reason = sanitizeAuditId(params.reason);
    const detail = sanitizeAuditText(params.detail);
    const canonical = [
      String(seq),
      timestamp,
      requestId,
      runId,
      organizationId,
      projectId,
      targetUrl,
      method,
      params.pinnedIp ?? '',
      params.connectedPeerIp ?? '',
      params.action,
      reason,
      detail,
      prevHash
    ].join('|');
    const entryHash = createHash('sha256').update(canonical, 'utf8').digest('hex');
    const entry: BrokerAuditLogEntry = {
      seq,
      timestamp,
      request_id: requestId,
      run_id: runId,
      organization_id: organizationId,
      project_id: projectId,
      target_url: targetUrl,
      method,
      pinned_ip: params.pinnedIp,
      connected_peer_ip: params.connectedPeerIp,
      action: params.action,
      reason,
      detail,
      prev_hash: prevHash,
      entry_hash: entryHash
    };
    this.auditLog.push(entry);
    return entry;
  }

  /**
   * Public entry point. Every result returned to the caller carries ONLY the already-sanitized audit
   * detail (never raw URLs / upstream error text), and redirect `Location` values have sensitive
   * query parameters masked before they leave the broker.
   */
  public async executeBrokeredPassiveRequest(
    req: BrokerProxyRequest,
    upstreamTransport: BrokerUpstreamTransport
  ): Promise<BrokerProxyResult> {
    const result = await this.evaluateBrokeredPassiveRequest(req, upstreamTransport);
    const safe: BrokerProxyResult = { ...result, detail: result.auditEntry.detail };
    if (result.response && [301, 302, 303, 307, 308].includes(result.response.statusCode)) {
      const headers: Record<string, string | string[]> = { ...result.response.headers };
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === 'location') {
          const raw = headers[key];
          headers[key] = Array.isArray(raw) ? raw.map(redactLocationHeader) : redactLocationHeader(String(raw));
        }
      }
      safe.response = { ...result.response, headers };
    }
    return safe;
  }

  private async evaluateBrokeredPassiveRequest(
    req: BrokerProxyRequest,
    upstreamTransport: BrokerUpstreamTransport
  ): Promise<BrokerProxyResult> {
    const now =
      req.now instanceof Date
        ? req.now
        : typeof req.now === 'string'
          ? new Date(req.now)
          : new Date();
    const upperMethod = req.method.toUpperCase();

    // 1. Passive HTTP method check (GET / HEAD only)
    if (upperMethod !== 'GET' && upperMethod !== 'HEAD') {
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method: upperMethod,
        action: 'DROP',
        reason: 'disallowed_method',
        detail: `Broker rejected non-passive HTTP method "${upperMethod}"; only GET and HEAD are permitted`
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'disallowed_method',
        detail: auditEntry.detail,
        auditEntry
      };
    }

    const method = upperMethod as AllowedHttpMethod;

    // 2. Canonical URL & ScopeAuthorizationGrant validation
    const urlCheck = parseAndValidateCanonicalUrl(req.url, req.scopeGrant, method);
    if (!urlCheck.decision.allowed || !urlCheck.target) {
      const reason = urlCheck.decision.reason ?? 'invalid_url';
      const detail = urlCheck.decision.detail;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason,
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason,
        detail,
        auditEntry
      };
    }

    // 3. Emergency stop / Kill-switch check before grant consumption (SEC-012)
    const candidateGrant = req.signedExecutionGrant as Partial<SignedRemoteExecutionGrant> | undefined;
    const stopCheck = this.emergencyStopRegistry.checkExecutionAllowed({
      runId: req.expectedRunId,
      emergencyStopTokenId: candidateGrant?.emergency_stop_token_id,
      signal: req.signal
    });
    if (!stopCheck.allowed) {
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason: 'scan_cancelled',
        detail: stopCheck.detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'scan_cancelled',
        detail: stopCheck.detail,
        auditEntry
      };
    }

    // 4. Short-lived SignedRemoteExecutionGrant & NonceReplayRegistry verification (G0.6)
    const grantVerify = verifySignedRemoteExecutionGrant({
      signedGrant: req.signedExecutionGrant,
      trustedSigners: this.trustedSigners,
      replayRegistry: this.replayRegistry,
      expectedRunId: req.expectedRunId,
      expectedOrganizationId: req.expectedOrganizationId,
      expectedProjectId: req.expectedProjectId,
      expectedGrantId: req.expectedGrantId,
      expectedScopeVersion: req.expectedScopeVersion,
      expectedTargetHost: urlCheck.target.hostname,
      expectedTargetPort: urlCheck.target.port,
      expectedNetworkPolicyId: req.expectedNetworkPolicyId,
      env: req.env ?? {},
      now
    });
    if (!grantVerify.allowed) {
      const reason = grantVerify.reason ?? 'unauthorized';
      const detail = grantVerify.detail;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason,
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason,
        detail,
        auditEntry
      };
    }

    const verifiedGrant = req.signedExecutionGrant as SignedRemoteExecutionGrant;

    // 5. Enforce per-run request budget
    const usedCount = this.runRequestCounts.get(req.expectedRunId) ?? 0;
    const budgetCap = Math.min(req.scopeGrant.max_request_budget, verifiedGrant.max_request_budget);
    if (usedCount >= budgetCap) {
      const detail = `Per-run request budget exhausted (${usedCount}/${budgetCap}) for run ${req.expectedRunId}`;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason: 'budget_exhausted',
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'budget_exhausted',
        detail,
        auditEntry
      };
    }

    // 6. Deny-by-default PerRunNetworkPolicy lookup
    const netPolicy = this.registeredPolicies.get(req.expectedNetworkPolicyId);
    if (!netPolicy || netPolicy.run_id !== req.expectedRunId || netPolicy.grant_id !== req.expectedGrantId) {
      const detail = `Deny-by-default DROP: no active PerRunNetworkPolicy matching ${req.expectedNetworkPolicyId} for run ${req.expectedRunId}`;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason: 'broker_policy_drop',
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'broker_policy_drop',
        detail,
        auditEntry
      };
    }

    // 7. Broker-side independent DNS resolution & IPv4/IPv6/Metadata SSRF check
    const pinRes = await resolveAndPinDestination(urlCheck.target, this.resolver);
    if (!pinRes.decision.allowed || !pinRes.pinned) {
      const reason = pinRes.decision.reason ?? 'blocked_destination';
      const detail = pinRes.decision.detail;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        action: 'DROP',
        reason,
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason,
        detail,
        auditEntry
      };
    }

    const pinnedIp = pinRes.pinned.pinnedIp;

    // 8. Verify (hostname, pinnedIp, port, 'tcp') against registered deny-by-default PerRunNetworkPolicy
    const tupleAllowed = netPolicy.allowed_egress_endpoints.some(
      (d) =>
        d.hostname.toLowerCase() === urlCheck.target!.hostname.toLowerCase() &&
        d.ip === pinnedIp &&
        d.port === urlCheck.target!.port &&
        d.protocol === 'tcp'
    );
    if (!tupleAllowed) {
      const detail = `Deny-by-default DROP: tuple (${urlCheck.target.hostname}, ${pinnedIp}:${urlCheck.target.port}/tcp) is not in PerRunNetworkPolicy ${netPolicy.policy_digest}`;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        action: 'DROP',
        reason: 'broker_policy_drop',
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'broker_policy_drop',
        detail,
        pinnedIp,
        auditEntry
      };
    }

    // 9. Deny-by-default outbound headers: broker-controlled defaults + a tiny validated allowlist.
    //    Worker-supplied credential/cookie/forwarding/arbitrary headers are NEVER forwarded and their
    //    VALUES are never recorded (only the dropped header NAMES are noted in the audit trail).
    const sanitizedHeaders: Record<string, string> = {
      'user-agent': 'HegoSentinel-Passive-Broker/0.1.0-alpha.4',
      accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
    };
    const droppedHeaderNames: string[] = [];
    let credentialClassHeaderSeen = false;
    if (req.headers && typeof req.headers === 'object') {
      for (const [k, v] of Object.entries(req.headers)) {
        const lower = String(k).toLowerCase().trim();
        const allowed =
          BROKER_OUTBOUND_HEADER_ALLOWLIST.has(lower) &&
          !FORBIDDEN_OUTBOUND_REQUEST_HEADERS.has(lower) &&
          typeof v === 'string' &&
          v.length > 0 &&
          v.length <= 128 &&
          !/[\u0000-\u001f\u007f]/.test(v) &&
          redactSensitiveText(v) === v &&
          (lower !== 'x-custom-trace' || /^[A-Za-z0-9._-]+$/.test(v)) &&
          (lower !== 'accept-language' || /^[A-Za-z0-9,;=._ -]+$/.test(v));
        if (allowed) {
          sanitizedHeaders[lower] = v as string;
        } else {
          if (FORBIDDEN_OUTBOUND_REQUEST_HEADERS.has(lower)) credentialClassHeaderSeen = true;
          droppedHeaderNames.push(sanitizeAuditId(lower));
        }
      }
    }
    const droppedHeadersNote =
      droppedHeaderNames.length > 0
        ? ` dropped_request_headers=[${droppedHeaderNames.slice(0, 12).join(',')}]${credentialClassHeaderSeen ? ' (credential-class header from worker discarded)' : ''}`
        : '';

    this.runRequestCounts.set(req.expectedRunId, usedCount + 1);
    const maxResponseBytes = req.maxResponseBytes ?? 262_144;
    const timeoutMs = req.timeoutMs ?? 8_000;

    // 10. Execute upstream transport bound to pinnedIp
    let upstreamRes: BrokerUpstreamResponse;
    try {
      upstreamRes = await upstreamTransport({
        url: urlCheck.target.url,
        method,
        pinnedIp,
        port: urlCheck.target.port,
        sanitizedHeaders,
        timeoutMs,
        maxResponseBytes,
        signal: req.signal,
        followRedirects: false
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const isCancelled = req.signal?.aborted || /abort|cancel/i.test(msg);
      const reason = isCancelled ? 'scan_cancelled' : 'upstream_transport_error';
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        action: 'DROP',
        reason,
        detail: `Upstream transport failed: ${msg}`
      });
      return {
        allowed: false,
        action: 'DROP',
        reason,
        detail: auditEntry.detail,
        pinnedIp,
        auditEntry
      };
    }

    // 11. Re-check kill-switch after transport return
    const postStopCheck = this.emergencyStopRegistry.checkExecutionAllowed({
      runId: req.expectedRunId,
      emergencyStopTokenId: verifiedGrant.emergency_stop_token_id,
      signal: req.signal
    });
    if (!postStopCheck.allowed) {
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        connectedPeerIp: upstreamRes.connectedSocketPeerIp,
        action: 'DROP',
        reason: 'scan_cancelled',
        detail: postStopCheck.detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'scan_cancelled',
        detail: postStopCheck.detail,
        pinnedIp,
        auditEntry
      };
    }

    // 12. Verify connected socket peer IP against pinnedIp (TOCTOU DNS rebinding guard â€” SEC-004)
    const peerCheck = verifyConnectedSocketPeer(pinRes.pinned, upstreamRes.connectedSocketPeerIp);
    if (!peerCheck.allowed) {
      const reason = peerCheck.reason ?? 'dns_rebind_detected';
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        connectedPeerIp: upstreamRes.connectedSocketPeerIp,
        action: 'DROP',
        reason,
        detail: peerCheck.detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason,
        detail: peerCheck.detail,
        pinnedIp,
        auditEntry
      };
    }

    // 13. Verify TLS SNI / servername alignment when provided
    if (
      upstreamRes.tlsServername &&
      upstreamRes.tlsServername.toLowerCase() !== urlCheck.target.hostname.toLowerCase()
    ) {
      const detail = `TLS SNI/hostname mismatch: expected "${urlCheck.target.hostname}", observed "${upstreamRes.tlsServername}"`;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        connectedPeerIp: upstreamRes.connectedSocketPeerIp,
        action: 'DROP',
        reason: 'tls_hostname_mismatch',
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'tls_hostname_mismatch',
        detail,
        pinnedIp,
        auditEntry
      };
    }

    // 14. Enforce response body size cap
    const bodyBytes = new TextEncoder().encode(upstreamRes.body).byteLength;
    if (bodyBytes > maxResponseBytes) {
      const detail = `Response body (${bodyBytes} bytes) exceeded broker cap (${maxResponseBytes} bytes)`;
      const auditEntry = this.recordAudit({
        now,
        requestId: req.requestId,
        runId: req.expectedRunId,
        organizationId: req.expectedOrganizationId,
        projectId: req.expectedProjectId,
        targetUrl: req.url,
        method,
        pinnedIp,
        connectedPeerIp: upstreamRes.connectedSocketPeerIp,
        action: 'DROP',
        reason: 'response_body_exceeded_limit',
        detail
      });
      return {
        allowed: false,
        action: 'DROP',
        reason: 'response_body_exceeded_limit',
        detail,
        pinnedIp,
        auditEntry
      };
    }

    // 15. Inspect redirect responses without following out-of-scope or HTTP-downgrade targets (SEC-003)
    const isRedirect = [301, 302, 303, 307, 308].includes(upstreamRes.statusCode);
    const rawLocation = upstreamRes.headers['location'] ?? upstreamRes.headers['Location'];
    const locationHeader = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;
    if (isRedirect && typeof locationHeader === 'string' && locationHeader.trim().length > 0) {
      const redirectCheck = await validateRedirectTransition({
        fromUrl: urlCheck.target,
        locationHeader,
        redirectDepth: 1,
        grant: req.scopeGrant,
        resolver: this.resolver
      });
      if (!redirectCheck.decision.allowed) {
        const reason = redirectCheck.decision.reason ?? 'out_of_scope_redirect';
        const detail = redirectCheck.decision.detail;
        const auditEntry = this.recordAudit({
          now,
          requestId: req.requestId,
          runId: req.expectedRunId,
          organizationId: req.expectedOrganizationId,
          projectId: req.expectedProjectId,
          targetUrl: req.url,
          method,
          pinnedIp,
          connectedPeerIp: upstreamRes.connectedSocketPeerIp,
          action: 'DROP',
          reason,
          detail
        });
        return {
          allowed: false,
          action: 'DROP',
          reason,
          detail,
          pinnedIp,
          auditEntry
        };
      }
    }

    const auditEntry = this.recordAudit({
      now,
      requestId: req.requestId,
      runId: req.expectedRunId,
      organizationId: req.expectedOrganizationId,
      projectId: req.expectedProjectId,
      targetUrl: urlCheck.target.url,
      method,
      pinnedIp,
      connectedPeerIp: upstreamRes.connectedSocketPeerIp,
      action: 'ALLOW',
      reason: 'broker_policy_allow',
      detail: `Broker verified grant, policy ${netPolicy.policy_digest}, and peer ${pinnedIp}:${urlCheck.target.port}${droppedHeadersNote}`
    });

    return {
      allowed: true,
      action: 'ALLOW',
      reason: 'broker_policy_allow',
      detail: auditEntry.detail,
      pinnedIp,
      sanitizedRequestHeaders: sanitizedHeaders,
      response: {
        statusCode: upstreamRes.statusCode,
        headers: upstreamRes.headers,
        body: upstreamRes.body,
        connectedSocketPeerIp: upstreamRes.connectedSocketPeerIp
      },
      auditEntry
    };
  }
}

export const MAX_BROKER_REQUEST_BYTES = 16_384;

export interface TrustedEgressBrokerServerOptions {
  broker: TrustedEgressBroker;
  controlPlaneSecret: string;
  upstreamTransport: BrokerUpstreamTransport;
}

function constantTimeSecretMatch(headerVal: string | undefined, expectedSecret: string): boolean {
  if (!headerVal || !expectedSecret || expectedSecret.length < 16) return false;
  const h1 = createHmac('sha256', expectedSecret).update(headerVal, 'utf8').digest('hex');
  const h2 = createHmac('sha256', expectedSecret).update(expectedSecret, 'utf8').digest('hex');
  if (h1.length !== h2.length) return false;
  let diff = 0;
  for (let i = 0; i < h1.length; i++) {
    diff |= h1.charCodeAt(i) ^ h2.charCodeAt(i);
  }
  return diff === 0;
}

function readBoundedJsonBody(
  req: IncomingMessage,
  maxBytes = MAX_BROKER_REQUEST_BYTES
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  return new Promise((resolvePromise) => {
    let raw = '';
    let total = 0;
    let settled = false;
    const utf8Encoder = new TextEncoder();

    req.on('data', (chunk: unknown) => {
      if (settled) return;
      const strChunk = String(chunk);
      total += utf8Encoder.encode(strChunk).byteLength;
      if (total > maxBytes) {
        settled = true;
        resolvePromise({
          ok: false,
          status: 413,
          error: `Request payload exceeds ${maxBytes} bytes limit`
        });
        req.destroy?.();
        return;
      }
      raw += strChunk;
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          resolvePromise({ ok: false, status: 400, error: 'JSON body must be an object' });
          return;
        }
        resolvePromise({ ok: true, data: parsed as Record<string, unknown> });
      } catch {
        resolvePromise({ ok: false, status: 400, error: 'Malformed JSON body' });
      }
    });

    req.on('error', (err: unknown) => {
      if (settled) return;
      settled = true;
      resolvePromise({
        ok: false,
        status: 400,
        error: err instanceof Error ? err.message : 'Request stream error'
      });
    });
  });
}

export const MAX_BROKER_TIMEOUT_MS = 15_000;
export const MAX_BROKER_RESPONSE_BYTES = 1_048_576;

/**
 * The /v1/egress/fetch body comes from the (untrusted) worker. Only the fields that the signed grant
 * binds are accepted. The caller can NOT choose the broker's clock (`now` â€” would allow replaying an
 * expired grant), the attested environment (`env`), an abort signal, nor raise size/time limits above
 * broker-side ceilings.
 */
export function buildTrustedProxyRequestFromWorkerPayload(data: Record<string, unknown>): BrokerProxyRequest {
  const num = (v: unknown, fallback: number, max: number): number => {
    const n = typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
    return Math.min(n, max);
  };
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');
  const headersIn = data.headers && typeof data.headers === 'object' && !Array.isArray(data.headers)
    ? (data.headers as Record<string, unknown>)
    : undefined;
  const headers: Record<string, string> | undefined = headersIn
    ? Object.fromEntries(Object.entries(headersIn).filter(([, v]) => typeof v === 'string') as Array<[string, string]>)
    : undefined;
  return {
    requestId: str(data.requestId),
    url: str(data.url),
    method: str(data.method),
    headers,
    signedExecutionGrant: data.signedExecutionGrant,
    scopeGrant: data.scopeGrant as ScopeAuthorizationGrant,
    expectedRunId: str(data.expectedRunId),
    expectedOrganizationId: str(data.expectedOrganizationId),
    expectedProjectId: str(data.expectedProjectId),
    expectedGrantId: str(data.expectedGrantId),
    expectedScopeVersion: typeof data.expectedScopeVersion === 'number' ? data.expectedScopeVersion : Number.NaN,
    expectedNetworkPolicyId: str(data.expectedNetworkPolicyId),
    timeoutMs: num(data.timeoutMs, 8_000, MAX_BROKER_TIMEOUT_MS),
    maxResponseBytes: num(data.maxResponseBytes, 262_144, MAX_BROKER_RESPONSE_BYTES)
    // intentionally omitted: now, env, signal
  };
}

function writeJsonResponse(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'x-content-type-options': 'nosniff',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

export async function handleTrustedEgressBrokerHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: TrustedEgressBrokerServerOptions
): Promise<void> {
  const urlPath = (req.url ?? '/').split('?')[0];
  const method = (req.method ?? 'GET').toUpperCase();

  if (method === 'GET' && urlPath === '/v1/egress/health') {
    writeJsonResponse(res, 200, {
      status: 'ok',
      defaultAction: options.broker.defaultAction,
      auditIntegrity: options.broker.verifyAuditLogIntegrity()
    });
    return;
  }

  if (
    urlPath === '/v1/egress/policy' ||
    urlPath === '/v1/egress/kill-switch' ||
    urlPath === '/v1/egress/audit'
  ) {
    const providedSecretRaw = req.headers['x-hegosentinel-control-secret'];
    const providedSecret = Array.isArray(providedSecretRaw)
      ? providedSecretRaw[0]
      : providedSecretRaw;
    if (!constantTimeSecretMatch(providedSecret, options.controlPlaneSecret)) {
      writeJsonResponse(res, 403, {
        allowed: false,
        reason: 'unauthorized_control_plane',
        detail: 'Missing or invalid X-HegoSentinel-Control-Secret header'
      });
      return;
    }
  }

  if (method === 'GET' && urlPath === '/v1/egress/audit') {
    writeJsonResponse(res, 200, {
      metrics: options.broker.getBrokerMetrics(),
      integrity: options.broker.verifyAuditLogIntegrity(),
      entries: options.broker.getAuditLog()
    });
    return;
  }

  if (method === 'POST' && urlPath === '/v1/egress/policy') {
    const bodyRes = await readBoundedJsonBody(req);
    if (!bodyRes.ok) {
      writeJsonResponse(res, bodyRes.status, { allowed: false, error: bodyRes.error });
      return;
    }
    try {
      options.broker.registerPerRunNetworkPolicy(bodyRes.data as unknown as PerRunNetworkPolicy);
      writeJsonResponse(res, 200, { registered: true });
    } catch (err) {
      writeJsonResponse(res, 400, {
        registered: false,
        error: (err as Error).message
      });
    }
    return;
  }

  if (method === 'POST' && urlPath === '/v1/egress/kill-switch') {
    const bodyRes = await readBoundedJsonBody(req);
    if (!bodyRes.ok) {
      writeJsonResponse(res, bodyRes.status, { allowed: false, error: bodyRes.error });
      return;
    }
    const { runId, tokenId, cancelledBy, reason } = bodyRes.data as {
      runId?: string;
      tokenId?: string;
      cancelledBy?: string;
      reason?: string;
    };
    if (runId) {
      options.broker.getEmergencyStopRegistry().cancelRun({
        runId,
        cancelledBy: cancelledBy ?? 'control-plane',
        reason: reason ?? 'Emergency stop via broker API'
      });
    }
    if (tokenId) {
      options.broker.getEmergencyStopRegistry().revokeEmergencyStopToken({
        tokenId,
        revokedBy: cancelledBy ?? 'control-plane',
        reason: reason ?? 'Token revoked via broker API'
      });
    }
    writeJsonResponse(res, 200, { revoked: true });
    return;
  }

  if (method === 'POST' && urlPath === '/v1/egress/fetch') {
    const bodyRes = await readBoundedJsonBody(req);
    if (!bodyRes.ok) {
      writeJsonResponse(res, bodyRes.status, {
        allowed: false,
        action: 'DROP',
        reason: 'invalid_broker_payload',
        detail: bodyRes.error
      });
      return;
    }
    const proxyReq = buildTrustedProxyRequestFromWorkerPayload(bodyRes.data);
    const proxyResult = await options.broker.executeBrokeredPassiveRequest(
      proxyReq,
      options.upstreamTransport
    );
    writeJsonResponse(res, proxyResult.allowed ? 200 : 403, proxyResult);
    return;
  }

  writeJsonResponse(res, 404, {
    allowed: false,
    action: 'DROP',
    reason: 'unknown_broker_endpoint'
  });
}

/**
 * Out-of-process HTTP daemon wrapper for TrustedEgressBroker (Sprint 7 â€” Section 3).
 * Exposes:
 * - `GET /v1/egress/health` (liveness check)
 * - `POST /v1/egress/policy` (control-plane authenticated PerRunNetworkPolicy registration)
 * - `POST /v1/egress/kill-switch` (control-plane authenticated EmergencyStopRegistry cancellation)
 * - `GET /v1/egress/audit` (control-plane authenticated hash-chained audit log + metrics)
 * - `POST /v1/egress/fetch` (worker proxy endpoint enforcing EGR-001..EGR-006)
 */
export function createTrustedEgressBrokerServer(
  options: TrustedEgressBrokerServerOptions
): Server {
  if (!options.controlPlaneSecret || options.controlPlaneSecret.length < 16) {
    throw new Error('TrustedEgressBrokerServer requires controlPlaneSecret >= 16 chars');
  }

  const server = createServer((req, res) => handleTrustedEgressBrokerHttpRequest(req, res, options));
  // Slow-request (slowloris) resistance for the worker-facing endpoint.
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  return server;
}

const isBrokerMainModule =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(resolvePath(process.argv[1])).href;

if (isBrokerMainModule || process.argv.includes('--serve')) {
  const host = process.env.HEGOSENTINEL_BROKER_HOST || process.env.HOST || '127.0.0.1';
  const port = Number(process.env.HEGOSENTINEL_BROKER_PORT || process.env.PORT || 8473);
  const controlPlaneSecret =
    process.env.HEGOSENTINEL_BROKER_CONTROL_SECRET ||
    process.env.HEGOSENTINEL_BROKER_SECRET ||
    'hegosentinel-local-broker-control-secret-2026';
  const signerSecret =
    process.env.HEGOSENTINEL_GRANT_SIGNER_SECRET ||
    'hegosentinel-local-grant-signer-secret-2026';

  const broker = new TrustedEgressBroker({
    trustedSigners: {
      'hegosentinel-control-plane-signer-v1': signerSecret
    },
    resolver: {
      async resolve4(hostname: string) {
        if (hostname.toLowerCase() === 'demo.example.test') {
          return ['93.184.216.34'];
        }
        return [];
      },
      async resolve6() {
        return [];
      }
    }
  });

  const server = createTrustedEgressBrokerServer({
    broker,
    controlPlaneSecret,
    upstreamTransport: async ({ pinnedIp }) => ({
      statusCode: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff'
      },
      body: '<!doctype html><html lang="en"><body>HegoSentinel Brokered Target Fixture</body></html>',
      connectedSocketPeerIp: pinnedIp
    })
  });

  server.listen(port, host, () => {
    console.log(`[HegoSentinel TrustedEgressBroker] Listening on http://${host}:${port}`);
  });
}

