import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import type {
  AllowedHttpMethod,
  ScopeAuthorizationGrant,
  ScopeTarget
} from '../../findings-schema/src/index.ts';

export type PolicyDenyReason =
  | 'unauthorized'
  | 'missing_written_permission'
  | 'scope_expired'
  | 'outside_window'
  | 'wildcard_forbidden'
  | 'invalid_url'
  | 'disallowed_scheme'
  | 'embedded_credentials_forbidden'
  | 'ip_literal_forbidden'
  | 'out_of_scope_target'
  | 'disallowed_method'
  | 'disallowed_check'
  | 'budget_exhausted'
  | 'blocked_destination'
  | 'dns_resolution_failed'
  | 'dns_rebind_detected'
  | 'out_of_scope_redirect'
  | 'redirect_limit_exceeded'
  | 'protocol_downgrade'
  | 'remote_egress_isolation_unverified'
  | 'egress_escape_detected';

export interface PolicyDecision {
  allowed: boolean;
  reason?: PolicyDenyReason;
  detail: string;
}

export interface CanonicalTargetUrl {
  url: string;
  scheme: 'https' | 'http';
  hostname: string;
  port: number;
  pathname: string;
  search: string;
  matchedScopeTarget: ScopeTarget;
}

export interface DnsResolver {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
}

export interface PinnedDestination {
  canonicalUrl: CanonicalTargetUrl;
  pinnedIp: string;
  ipFamily: 4 | 6;
  allResolvedIps: string[];
}

export interface EgressSandboxAttestation {
  sandboxActive: boolean;
  allowlistedDestinationsOnly: boolean;
  internalPlaneReachable: boolean;
  ambientProxyDisabled: boolean;
}

const ALLOWED_METHODS_SET = new Set<string>(['GET', 'HEAD']);
const ALLOWED_CHECKS_SET = new Set<string>([
  'WEB-TLS-001',
  'WEB-HEADER-001',
  'WEB-COOKIE-001',
  'WEB-REDIRECT-001',
  'CODE-001',
  'DEP-001'
]);

const FORBIDDEN_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.intranet',
  '.corp',
  '.home',
  '.lan',
  'metadata.google.internal',
  'instance-data'
];

/**
 * Validates the authorization grant and scope record before any scan can start (S0-01 / HSR-02 / SEC-001).
 */
export function validateScopeAuthorizationGrant(
  grant: unknown,
  now: Date = new Date()
): PolicyDecision {
  if (!grant || typeof grant !== 'object') {
    return { allowed: false, reason: 'unauthorized', detail: 'Missing or non-object scope authorization grant' };
  }

  const g = grant as Partial<ScopeAuthorizationGrant>;

  if (g.schema_version !== '1.0.0') {
    return { allowed: false, reason: 'unauthorized', detail: 'Unsupported or missing schema_version (expected 1.0.0)' };
  }
  if (!g.grant_id || typeof g.grant_id !== 'string' || g.grant_id.trim().length < 4) {
    return { allowed: false, reason: 'unauthorized', detail: 'Missing valid grant_id' };
  }
  if (typeof g.scope_version !== 'number' || !Number.isInteger(g.scope_version) || g.scope_version < 1) {
    return { allowed: false, reason: 'unauthorized', detail: 'Invalid scope_version' };
  }
  if (!g.organization_id || !g.project_id || !g.project_name || !g.owner) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'organization_id, project_id, project_name, and owner are required'
    };
  }
  if (!g.authorization_statement || g.authorization_statement.trim().length < 15) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Explicit authorization_statement is required'
    };
  }
  // Domain ownership proof is NOT a substitute for written permission (HSR-02 / README Safety Policy)
  if (!g.written_permission_ref || typeof g.written_permission_ref !== 'string' || g.written_permission_ref.trim().length < 5) {
    return {
      allowed: false,
      reason: 'missing_written_permission',
      detail: 'Domain control proof alone is insufficient; explicit written_permission_ref is required'
    };
  }
  if (!g.emergency_contact || typeof g.emergency_contact !== 'string' || g.emergency_contact.trim().length < 5) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Valid emergency_contact is required before scanning'
    };
  }

  const issuedMs = Date.parse(g.issued_at ?? '');
  const expiresMs = Date.parse(g.expires_at ?? '');
  const nowMs = now.getTime();
  if (Number.isNaN(issuedMs) || Number.isNaN(expiresMs) || expiresMs <= issuedMs) {
    return { allowed: false, reason: 'unauthorized', detail: 'Malformed issued_at or expires_at timestamp' };
  }
  if (nowMs >= expiresMs) {
    return { allowed: false, reason: 'scope_expired', detail: `Authorization grant expired at ${g.expires_at}` };
  }

  if (!g.time_window || typeof g.time_window !== 'object') {
    return { allowed: false, reason: 'unauthorized', detail: 'Missing testing time_window' };
  }
  const windowStartMs = Date.parse(g.time_window.start_at ?? '');
  const windowEndMs = Date.parse(g.time_window.end_at ?? '');
  if (Number.isNaN(windowStartMs) || Number.isNaN(windowEndMs) || windowEndMs <= windowStartMs) {
    return { allowed: false, reason: 'unauthorized', detail: 'Malformed time_window timestamps' };
  }
  if (nowMs < windowStartMs || nowMs > windowEndMs) {
    return {
      allowed: false,
      reason: 'outside_window',
      detail: `Current time ${now.toISOString()} is outside approved testing window (${g.time_window.start_at} .. ${g.time_window.end_at})`
    };
  }

  if (
    typeof g.max_request_budget !== 'number' ||
    !Number.isInteger(g.max_request_budget) ||
    g.max_request_budget < 1 ||
    g.max_request_budget > 100
  ) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'max_request_budget must be an integer between 1 and 100 in v0.1'
    };
  }

  if (!Array.isArray(g.allowed_methods) || g.allowed_methods.length === 0) {
    return { allowed: false, reason: 'disallowed_method', detail: 'allowed_methods must be a non-empty array' };
  }
  for (const m of g.allowed_methods) {
    if (!ALLOWED_METHODS_SET.has(m)) {
      return {
        allowed: false,
        reason: 'disallowed_method',
        detail: `HTTP method "${String(m)}" is not permitted in v0.1 (only GET and HEAD allowed)`
      };
    }
  }

  if (!Array.isArray(g.allowed_checks) || g.allowed_checks.length === 0) {
    return { allowed: false, reason: 'disallowed_check', detail: 'allowed_checks must be a non-empty array' };
  }
  for (const c of g.allowed_checks) {
    if (!ALLOWED_CHECKS_SET.has(c)) {
      return { allowed: false, reason: 'disallowed_check', detail: `Unknown or unapproved check ID "${String(c)}"` };
    }
  }

  if (!Array.isArray(g.targets) || g.targets.length === 0) {
    return { allowed: false, reason: 'unauthorized', detail: 'At least one explicit target must be specified' };
  }

  for (const t of g.targets) {
    if (!t || (t.scheme !== 'https' && t.scheme !== 'http')) {
      return { allowed: false, reason: 'disallowed_scheme', detail: 'Target scheme must be http or https' };
    }
    if (!t.hostname || typeof t.hostname !== 'string') {
      return { allowed: false, reason: 'invalid_url', detail: 'Target hostname is required' };
    }
    if (t.hostname.includes('*') || (t.path_prefix && t.path_prefix.includes('*'))) {
      return {
        allowed: false,
        reason: 'wildcard_forbidden',
        detail: `Wildcard targets ("${t.hostname}${t.path_prefix ?? ''}") are forbidden in v0.1`
      };
    }
    if (looksLikeIpLiteral(t.hostname)) {
      return {
        allowed: false,
        reason: 'ip_literal_forbidden',
        detail: `IP literal target "${t.hostname}" is forbidden by default`
      };
    }
    if (!t.path_prefix || !t.path_prefix.startsWith('/')) {
      return { allowed: false, reason: 'invalid_url', detail: 'Target path_prefix must start with "/"' };
    }
    if (typeof t.port !== 'number' || !Number.isInteger(t.port) || t.port < 1 || t.port > 65535) {
      return { allowed: false, reason: 'invalid_url', detail: 'Target port must be between 1 and 65535' };
    }
    if (g.profile === 'local-demo' && t.hostname.toLowerCase() !== 'demo.example.test') {
      return {
        allowed: false,
        reason: 'out_of_scope_target',
        detail: 'local-demo profile is strictly locked to synthetic host demo.example.test'
      };
    }
  }

  return {
    allowed: true,
    detail: `Scope grant ${g.grant_id} (v${g.scope_version}) validated for project ${g.project_id}`
  };
}

/**
 * Detects standard, integer, hex, octal, or bracketed IPv4/IPv6 literals (S0-02).
 */
export function looksLikeIpLiteral(hostname: string): boolean {
  const clean = hostname.trim().replace(/^\[|\]$/g, '');
  if (isIP(clean) !== 0) {
    return true;
  }
  // Pure decimal integer IP (e.g., 2130706433) or hex IP (0x7f000001)
  if (/^(0x[0-9a-f]+|\d+)$/i.test(clean)) {
    return true;
  }
  // Dotted octal/hex/decimal mixture (e.g., 0177.0.0.1 or 127.1)
  const parts = clean.split('.');
  if (parts.length >= 2 && parts.every((p) => /^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(p))) {
    return true;
  }
  return false;
}

function parseIpv4Octets(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function expandIpv6Words(ip: string): number[] | null {
  const zoneStripped = ip.split('%')[0].toLowerCase();

  // Check if last segment is dotted IPv4 (e.g. ::ffff:127.0.0.1)
  let normalized = zoneStripped;
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    if (lastColon === -1) return null;
    const ipv4Part = normalized.slice(lastColon + 1);
    const octets = parseIpv4Octets(ipv4Part);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColonParts = normalized.split('::');
  if (doubleColonParts.length > 2) return null;

  const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const right = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];

  if (doubleColonParts.length === 1 && left.length !== 8) return null;
  if (left.length + right.length > 8) return null;

  const missing = 8 - (left.length + right.length);
  const full = [...left, ...Array<string>(doubleColonParts.length === 2 ? missing : 0).fill('0'), ...right];
  if (full.length !== 8) return null;

  const words: number[] = [];
  for (const group of full) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    words.push( Number.parseInt(group, 16));
  }
  return words;
}

/**
 * Classifies whether an IPv4 or IPv6 address is non-global, reserved, loopback, private,
 * link-local, or cloud metadata (S0-02 / HSR-01 / SEC-002).
 */
export function classifyIpAddress(rawIp: string): { allowed: boolean; category: string } {
  const cleaned = rawIp.trim().replace(/^\[|\]$/g, '');
  const version = isIP(cleaned.split('%')[0]);

  if (version === 4) {
    const octets = parseIpv4Octets(cleaned);
    if (!octets) return { allowed: false, category: 'malformed_ipv4' };
    const [a, b, c] = octets;

    if (a === 0) return { allowed: false, category: 'ipv4_unspecified' };
    if (a === 10) return { allowed: false, category: 'ipv4_private_rfc1918' };
    if (a === 100 && b >= 64 && b <= 127) return { allowed: false, category: 'ipv4_cgnat_or_metadata' };
    if (a === 127) return { allowed: false, category: 'ipv4_loopback' };
    if (a === 169 && b === 254) return { allowed: false, category: 'ipv4_link_local_or_cloud_metadata' };
    if (a === 172 && b >= 16 && b <= 31) return { allowed: false, category: 'ipv4_private_rfc1918' };
    if (a === 192 && b === 0 && c === 0) return { allowed: false, category: 'ipv4_ietf_reserved' };
    if (a === 192 && b === 0 && c === 2) return { allowed: false, category: 'ipv4_testnet_1' };
    if (a === 192 && b === 88 && c === 99) return { allowed: false, category: 'ipv4_6to4_relay' };
    if (a === 192 && b === 168) return { allowed: false, category: 'ipv4_private_rfc1918' };
    if (a === 198 && (b === 18 || b === 19)) return { allowed: false, category: 'ipv4_benchmark' };
    if (a === 198 && b === 51 && c === 100) return { allowed: false, category: 'ipv4_testnet_2' };
    if (a === 203 && b === 0 && c === 113) return { allowed: false, category: 'ipv4_testnet_3' };
    if (a >= 224) return { allowed: false, category: 'ipv4_multicast_or_reserved' };

    return { allowed: true, category: 'ipv4_global_unicast' };
  }

  if (version === 6) {
    if (cleaned.includes('%')) {
      return { allowed: false, category: 'ipv6_zone_index_forbidden' };
    }
    const words = expandIpv6Words(cleaned);
    if (!words) return { allowed: false, category: 'malformed_ipv6' };

    const allZeroPrefix = words.slice(0, 5).every((w) => w === 0);
    // Unspecified :: or Loopback ::1
    if (allZeroPrefix && words[5] === 0 && words[6] === 0 && (words[7] === 0 || words[7] === 1)) {
      return { allowed: false, category: words[7] === 1 ? 'ipv6_loopback' : 'ipv6_unspecified' };
    }
    // IPv4-mapped ::ffff:w6:w7 or IPv4-compatible ::w6:w7
    if (allZeroPrefix && (words[5] === 0xffff || words[5] === 0)) {
      const a = (words[6] >> 8) & 0xff;
      const b = words[6] & 0xff;
      const c = (words[7] >> 8) & 0xff;
      const d = words[7] & 0xff;
      const embeddedCheck = classifyIpAddress(`${a}.${b}.${c}.${d}`);
      if (!embeddedCheck.allowed) {
        return { allowed: false, category: `ipv6_mapped_${embeddedCheck.category}` };
      }
      return { allowed: false, category: 'ipv6_ipv4_mapped_transition' };
    }
    // NAT64 64:ff9b::/96 or 64:ff9b:1::/48
    if (words[0] === 0x0064 && words[1] === 0xff9b) {
      return { allowed: false, category: 'ipv6_nat64_translation' };
    }
    // Discard-only 100::/64
    if (words[0] === 0x0100 && words[1] === 0 && words[2] === 0 && words[3] === 0) {
      return { allowed: false, category: 'ipv6_discard_range' };
    }
    // Teredo 2001:0000::/32, Benchmarking 2001:0002::/48, Documentation 2001:0db8::/32
    if (words[0] === 0x2001) {
      if (words[1] === 0x0000) return { allowed: false, category: 'ipv6_teredo' };
      if (words[1] === 0x0002 && words[2] === 0x0000) return { allowed: false, category: 'ipv6_benchmark' };
      if (words[1] === 0x0db8) return { allowed: false, category: 'ipv6_documentation' };
    }
    // 6to4 2002::/16
    if (words[0] === 0x2002) {
      return { allowed: false, category: 'ipv6_6to4' };
    }
    // Unique Local fc00::/7 (includes fd00:ec2::254 AWS metadata)
    if ((words[0] & 0xfe00) === 0xfc00) {
      return { allowed: false, category: 'ipv6_unique_local_or_cloud_metadata' };
    }
    // Link-Local fe80::/10
    if ((words[0] & 0xffc0) === 0xfe80) {
      return { allowed: false, category: 'ipv6_link_local' };
    }
    // Multicast ff00::/8
    if ((words[0] & 0xff00) === 0xff00) {
      return { allowed: false, category: 'ipv6_multicast' };
    }

    return { allowed: true, category: 'ipv6_global_unicast' };
  }

  return { allowed: false, category: 'unrecognized_ip_format' };
}

/**
 * Canonically parses a target URL and validates it against the ScopeAuthorizationGrant (S0-02 / HSR-01).
 */
export function parseAndValidateCanonicalUrl(
  rawUrl: string,
  grant: ScopeAuthorizationGrant,
  method: AllowedHttpMethod = 'GET'
): { decision: PolicyDecision; target?: CanonicalTargetUrl } {
  const grantCheck = validateScopeAuthorizationGrant(grant);
  if (!grantCheck.allowed) {
    return { decision: grantCheck };
  }

  if (!grant.allowed_methods.includes(method)) {
    return {
      decision: {
        allowed: false,
        reason: 'disallowed_method',
        detail: `HTTP method ${method} is not authorized by grant ${grant.grant_id}`
      }
    };
  }

  if (!rawUrl || typeof rawUrl !== 'string' || /[\u0000-\u001f\u007f\s]/.test(rawUrl)) {
    return {
      decision: {
        allowed: false,
        reason: 'invalid_url',
        detail: 'URL contains control characters, whitespace, or is empty'
      }
    };
  }

  // Reject backslash tricks (e.g. https://approved.test\@169.254.169.254)
  if (rawUrl.includes('\\')) {
    return {
      decision: {
        allowed: false,
        reason: 'invalid_url',
        detail: 'URL contains ambiguous backslash characters'
      }
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      decision: {
        allowed: false,
        reason: 'invalid_url',
        detail: `Failed to parse canonical URL: ${rawUrl}`
      }
    };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return {
      decision: {
        allowed: false,
        reason: 'disallowed_scheme',
        detail: `Scheme "${parsed.protocol}" is disallowed; only http: and https: are permitted`
      }
    };
  }

  if (parsed.username !== '' || parsed.password !== '') {
    return {
      decision: {
        allowed: false,
        reason: 'embedded_credentials_forbidden',
        detail: 'Embedded URL credentials (user:pass@host) are forbidden'
      }
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname === 'localhost' || FORBIDDEN_HOST_SUFFIXES.some((s) => hostname === s || hostname.endsWith(s))) {
    return {
      decision: {
        allowed: false,
        reason: 'blocked_destination',
        detail: `Hostname "${hostname}" resolves to a forbidden local or internal domain`
      }
    };
  }

  if (looksLikeIpLiteral(hostname)) {
    return {
      decision: {
        allowed: false,
        reason: 'ip_literal_forbidden',
        detail: `Direct IP literal "${hostname}" is forbidden in URLs`
      }
    };
  }

  // Reject double-encoded or path-traversal encodings in pathname
  if (/%2e|%2f|%5c|%00/i.test(parsed.pathname) || parsed.pathname.includes('/..')) {
    return {
      decision: {
        allowed: false,
        reason: 'invalid_url',
        detail: 'Confusing percent-encoding or path traversal segment detected in URL path'
      }
    };
  }

  const scheme = parsed.protocol === 'https:' ? 'https' : 'http';
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : scheme === 'https' ? 443 : 80;
  const pathname = parsed.pathname || '/';

  const matchedScopeTarget = grant.targets.find(
    (t) =>
      t.scheme === scheme &&
      t.hostname.toLowerCase() === hostname &&
      t.port === port &&
      (pathname === t.path_prefix ||
        pathname.startsWith(t.path_prefix.endsWith('/') ? t.path_prefix : `${t.path_prefix}/`))
  );

  if (!matchedScopeTarget) {
    return {
      decision: {
        allowed: false,
        reason: 'out_of_scope_target',
        detail: `Target ${scheme}://${hostname}:${port}${pathname} is not in grant ${grant.grant_id} allowlist`
      }
    };
  }

  return {
    decision: {
      allowed: true,
      detail: `URL canonically validated against scope target ${matchedScopeTarget.hostname}:${matchedScopeTarget.port}${matchedScopeTarget.path_prefix}`
    },
    target: {
      url: parsed.toString(),
      scheme,
      hostname,
      port,
      pathname,
      search: parsed.search,
      matchedScopeTarget
    }
  };
}

/**
 * Resolves A/AAAA records, verifies every candidate IP is global unicast, and pins the destination IP (S0-02 / SEC-002 / SEC-004).
 */
export async function resolveAndPinDestination(
  canonicalUrl: CanonicalTargetUrl,
  resolver: DnsResolver
): Promise<{ decision: PolicyDecision; pinned?: PinnedDestination }> {
  let ipv4List: string[] = [];
  let ipv6List: string[] = [];

  try {
    ipv4List = await resolver.resolve4(canonicalUrl.hostname);
  } catch {
    ipv4List = [];
  }

  try {
    ipv6List = await resolver.resolve6(canonicalUrl.hostname);
  } catch {
    ipv6List = [];
  }

  const allIps = [...ipv4List, ...ipv6List];
  if (allIps.length === 0) {
    return {
      decision: {
        allowed: false,
        reason: 'dns_resolution_failed',
        detail: `No A or AAAA records resolved for ${canonicalUrl.hostname}`
      }
    };
  }

  for (const candidateIp of allIps) {
    const classification = classifyIpAddress(candidateIp);
    if (!classification.allowed) {
      return {
        decision: {
          allowed: false,
          reason: 'blocked_destination',
          detail: `DNS resolution for ${canonicalUrl.hostname} returned disallowed IP ${candidateIp} (${classification.category})`
        }
      };
    }
  }

  const pinnedIp = ipv4List.length > 0 ? ipv4List[0] : ipv6List[0];
  const ipFamily: 4 | 6 = ipv4List.length > 0 ? 4 : 6;

  return {
    decision: {
      allowed: true,
      detail: `Pinned ${canonicalUrl.hostname} to global unicast IP ${pinnedIp}`
    },
    pinned: {
      canonicalUrl,
      pinnedIp,
      ipFamily,
      allResolvedIps: allIps
    }
  };
}

/**
 * Verifies the actual connected socket peer IP matches the pinned IP and is not a DNS rebind (SEC-004).
 */
export function verifyConnectedSocketPeer(
  pinned: PinnedDestination,
  actualSocketRemoteAddress: string
): PolicyDecision {
  const cleanPeer = actualSocketRemoteAddress.trim().replace(/^\[|\]$/g, '');
  const peerClass = classifyIpAddress(cleanPeer);
  if (!peerClass.allowed) {
    return {
      allowed: false,
      reason: 'dns_rebind_detected',
      detail: `Connected socket peer ${cleanPeer} is disallowed (${peerClass.category})`
    };
  }
  if (cleanPeer !== pinned.pinnedIp) {
    return {
      allowed: false,
      reason: 'dns_rebind_detected',
      detail: `Connected socket peer ${cleanPeer} does not match pinned IP ${pinned.pinnedIp} (DNS rebind blocked)`
    };
  }
  return {
    allowed: true,
    detail: `Connected socket peer ${cleanPeer} matches pinned destination`
  };
}

/**
 * Validates a redirect transition without automatically following out-of-scope or downgraded targets (SEC-003).
 */
export async function validateRedirectTransition(params: {
  fromUrl: CanonicalTargetUrl;
  locationHeader: string;
  redirectDepth: number;
  maxRedirects?: number;
  grant: ScopeAuthorizationGrant;
  resolver: DnsResolver;
}): Promise<{ decision: PolicyDecision; nextPinned?: PinnedDestination }> {
  const maxRedirects = params.maxRedirects ?? 3;
  if (params.redirectDepth >= maxRedirects) {
    return {
      decision: {
        allowed: false,
        reason: 'redirect_limit_exceeded',
        detail: `Redirect depth ${params.redirectDepth + 1} exceeds maximum allowed (${maxRedirects})`
      }
    };
  }

  let resolvedRedirectUrl: string;
  try {
    resolvedRedirectUrl = new URL(params.locationHeader, params.fromUrl.url).toString();
  } catch {
    return {
      decision: {
        allowed: false,
        reason: 'invalid_url',
        detail: `Malformed redirect Location header: ${params.locationHeader}`
      }
    };
  }

  const parsedCandidate = new URL(resolvedRedirectUrl);
  if (params.fromUrl.scheme === 'https' && parsedCandidate.protocol === 'http:') {
    return {
      decision: {
        allowed: false,
        reason: 'protocol_downgrade',
        detail: `Redirect from HTTPS to HTTP (${resolvedRedirectUrl}) is a protocol downgrade and will not be followed`
      }
    };
  }

  const urlValidation = parseAndValidateCanonicalUrl(resolvedRedirectUrl, params.grant, 'GET');
  if (!urlValidation.decision.allowed || !urlValidation.target) {
    return {
      decision: {
        allowed: false,
        reason: 'out_of_scope_redirect',
        detail: `Redirect target ${resolvedRedirectUrl} rejected: ${urlValidation.decision.detail}`
      }
    };
  }

  const pinResult = await resolveAndPinDestination(urlValidation.target, params.resolver);
  if (!pinResult.decision.allowed || !pinResult.pinned) {
    return {
      decision: {
        allowed: false,
        reason: 'out_of_scope_redirect',
        detail: `Redirect target DNS/IP validation failed: ${pinResult.decision.detail}`
      }
    };
  }

  return {
    decision: {
      allowed: true,
      detail: `Redirect to ${urlValidation.target.url} validated and pinned to ${pinResult.pinned.pinnedIp}`
    },
    nextPinned: pinResult.pinned
  };
}

/**
 * Enforces HSR-01 / SEC-005: Application-level URL filtering is never treated as sufficient isolation
 * for remote scanning. Remote target execution fails closed unless the network-layer egress sandbox is attested.
 */
export function verifyRemoteEgressSandboxGate(
  attestation?: EgressSandboxAttestation
): PolicyDecision {
  if (!attestation || !attestation.sandboxActive || !attestation.allowlistedDestinationsOnly) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail:
        'Remote target mode is disabled (fail-closed): application-level URL filtering is not sufficient isolation without an active network-layer egress firewall/sandbox (HSR-01).'
    };
  }
  if (attestation.internalPlaneReachable) {
    return {
      allowed: false,
      reason: 'egress_escape_detected',
      detail: 'Worker network policy check failed: internal API/DB/metadata plane is reachable (SEC-005).'
    };
  }
  if (!attestation.ambientProxyDisabled) {
    return {
      allowed: false,
      reason: 'remote_egress_isolation_unverified',
      detail: 'Ambient proxy environment variables must be disabled before remote scanning (S0-02).'
    };
  }
  return {
    allowed: true,
    detail: 'Network-layer egress sandbox attestation verified'
  };
}

// ============================================================================
// SEC-011 / HSR-08: Multi-Tenant & RBAC Resource Boundary Enforcement
// ============================================================================

export type TenantRole = 'owner' | 'security_reviewer' | 'developer' | 'read_only_auditor';

export type TenantAction =
  | 'read_report'
  | 'export_artifact'
  | 'trigger_scan'
  | 'cancel_scan'
  | 'approve_scope_grant'
  | 'suppress_false_positive'
  | 'approve_external_notification';

export interface TenantPrincipal {
  user_id: string;
  organization_id: string;
  project_ids: string[];
  role: TenantRole;
}

export interface TenantScopedResource {
  resource_type: 'scan' | 'finding' | 'report' | 'artifact_url' | 'scope_grant' | 'notification';
  resource_id: string;
  organization_id: string;
  project_id: string;
}

const ROLE_ALLOWED_ACTIONS: Record<TenantRole, ReadonlySet<TenantAction>> = {
  owner: new Set([
    'read_report',
    'export_artifact',
    'trigger_scan',
    'cancel_scan',
    'approve_scope_grant',
    'suppress_false_positive',
    'approve_external_notification'
  ]),
  security_reviewer: new Set([
    'read_report',
    'export_artifact',
    'trigger_scan',
    'cancel_scan',
    'suppress_false_positive'
  ]),
  developer: new Set(['read_report', 'export_artifact', 'trigger_scan', 'cancel_scan']),
  read_only_auditor: new Set(['read_report', 'export_artifact'])
};

/**
 * SEC-011 / HSR-08: Enforces strict organization + project membership isolation and RBAC action matrix.
 * Cross-tenant or cross-project access attempts always fail closed with `unauthorized`.
 */
export function authorizeTenantResourceAccess(params: {
  principal: TenantPrincipal;
  resource: TenantScopedResource;
  action: TenantAction;
}): PolicyDecision {
  const { principal, resource, action } = params;
  if (
    !principal ||
    !principal.user_id?.trim() ||
    !principal.organization_id?.trim() ||
    !Array.isArray(principal.project_ids)
  ) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Missing or malformed tenant principal identity (SEC-011)'
    };
  }

  if (principal.organization_id !== resource.organization_id) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `Cross-tenant access denied: principal org "${principal.organization_id}" cannot access resource in org "${resource.organization_id}" (SEC-011 / HSR-08)`
    };
  }

  if (!principal.project_ids.includes(resource.project_id)) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `Cross-project access denied: principal "${principal.user_id}" is not a member of project "${resource.project_id}" (SEC-011)`
    };
  }

  const allowedActions = ROLE_ALLOWED_ACTIONS[principal.role];
  if (!allowedActions || !allowedActions.has(action)) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `RBAC denied: role "${principal.role}" is not permitted to perform "${action}" on ${resource.resource_type}:${resource.resource_id} (SEC-011)`
    };
  }

  return {
    allowed: true,
    detail: `Authorized ${principal.role} (${principal.user_id}) for ${action} on ${resource.resource_type}:${resource.resource_id}`
  };
}

// ============================================================================
// SEC-012 / G2: Emergency Stop (Kill-Switch) & Job Cancellation Registry
// ============================================================================

export interface RevokedStopRecord {
  id: string;
  revoked_by: string;
  reason: string;
  revoked_at: string;
}

/**
 * SEC-012: Central kill-switch registry that tracks revoked emergency_stop_token_id and run_id values,
 * triggers linked AbortControllers immediately, and blocks any subsequent request or subprocess launch.
 */
export class EmergencyStopRegistry {
  private readonly revokedTokens = new Map<string, RevokedStopRecord>();
  private readonly revokedRuns = new Map<string, RevokedStopRecord>();
  private readonly runControllers = new Map<string, AbortController[]>();

  public registerRunController(runId: string, controller: AbortController): void {
    if (this.revokedRuns.has(runId)) {
      controller.abort();
      return;
    }
    const list = this.runControllers.get(runId) ?? [];
    list.push(controller);
    this.runControllers.set(runId, list);
  }

  public revokeEmergencyStopToken(params: {
    tokenId: string;
    revokedBy: string;
    reason: string;
    now?: Date;
  }): RevokedStopRecord {
    const record: RevokedStopRecord = {
      id: params.tokenId,
      revoked_by: params.revokedBy,
      reason: params.reason,
      revoked_at: (params.now ?? new Date()).toISOString()
    };
    this.revokedTokens.set(params.tokenId, record);
    return record;
  }

  public cancelRun(params: {
    runId: string;
    cancelledBy: string;
    reason: string;
    now?: Date;
  }): RevokedStopRecord {
    const record: RevokedStopRecord = {
      id: params.runId,
      revoked_by: params.cancelledBy,
      reason: params.reason,
      revoked_at: (params.now ?? new Date()).toISOString()
    };
    this.revokedRuns.set(params.runId, record);
    const controllers = this.runControllers.get(params.runId) ?? [];
    for (const ctrl of controllers) {
      ctrl.abort();
    }
    return record;
  }

  public checkExecutionAllowed(params: {
    runId: string;
    emergencyStopTokenId?: string;
    signal?: AbortSignal;
  }): PolicyDecision {
    if (params.signal?.aborted) {
      return {
        allowed: false,
        reason: 'unauthorized',
        detail: `Execution aborted via AbortSignal for run ${params.runId} (SEC-012)`
      };
    }
    const revokedRun = this.revokedRuns.get(params.runId);
    if (revokedRun) {
      return {
        allowed: false,
        reason: 'unauthorized',
        detail: `Run ${params.runId} was cancelled by ${revokedRun.revoked_by}: ${revokedRun.reason} (SEC-012)`
      };
    }
    if (params.emergencyStopTokenId) {
      const revokedToken = this.revokedTokens.get(params.emergencyStopTokenId);
      if (revokedToken) {
        return {
          allowed: false,
          reason: 'unauthorized',
          detail: `Emergency stop token ${params.emergencyStopTokenId} was revoked by ${revokedToken.revoked_by}: ${revokedToken.reason} (SEC-012)`
        };
      }
    }
    return {
      allowed: true,
      detail: `Run ${params.runId} is active and not revoked`
    };
  }
}

// ============================================================================
// SEC-013 / HSR-11: Human-Approved, Private-by-Default External Disclosure Gate
// ============================================================================

export interface ExternalNotificationRequest {
  channel: 'smtp_email' | 'github_issue';
  organization_id: string;
  project_id: string;
  enabled_by_owner: boolean;
  human_approval_id: string;
  approved_by_principal: TenantPrincipal;
  recipient_or_repo: string;
  verified_recipient_allowlist: string[];
  sink_visibility: 'private' | 'public';
  sanitized_summary_only: boolean;
  payload_text: string;
}

/**
 * SEC-013 / HSR-11: Prevents default automatic external disclosure, blocks public issue trackers
 * and unverified recipients, requires owner human approval, and rejects unsanitized secret payloads.
 */
export function validateExternalNotificationRequest(
  req: ExternalNotificationRequest
): PolicyDecision {
  if (!req.enabled_by_owner) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'External notifications are disabled by default until explicitly enabled by the project owner (SEC-013 / HSR-11)'
    };
  }

  if (!req.human_approval_id || req.human_approval_id.trim().length < 6) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'External notification requires an explicit human_approval_id record (SEC-013)'
    };
  }

  const rbacCheck = authorizeTenantResourceAccess({
    principal: req.approved_by_principal,
    resource: {
      resource_type: 'notification',
      resource_id: req.human_approval_id,
      organization_id: req.organization_id,
      project_id: req.project_id
    },
    action: 'approve_external_notification'
  });
  if (!rbacCheck.allowed) {
    return rbacCheck;
  }

  if (req.sink_visibility !== 'private') {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Public issue trackers or public disclosure sinks are forbidden; sink_visibility must be "private" (SEC-013 / HSR-11)'
    };
  }

  const normalizedTarget = req.recipient_or_repo.trim().toLowerCase();
  const normalizedAllowlist = req.verified_recipient_allowlist.map((r) => r.trim().toLowerCase());
  if (!normalizedTarget || !normalizedAllowlist.includes(normalizedTarget)) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: `Recipient or repository "${req.recipient_or_repo}" is not in the verified recipient allowlist (SEC-013)`
    };
  }

  if (!req.sanitized_summary_only) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Full raw evidence dumps are forbidden in external notifications; sanitized_summary_only must be true (SEC-013)'
    };
  }

  if (
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|Set-Cookie:|APP_KEY=base64:|NEXTAUTH_SECRET=|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:postgres|mysql|redis):\/\/[^:\s/@]+:[^@\s/]+@/i.test(
      req.payload_text
    )
  ) {
    return {
      allowed: false,
      reason: 'unauthorized',
      detail: 'Unredacted secret or cookie header detected in outbound notification payload (SEC-007 / SEC-013)'
    };
  }

  return {
    allowed: true,
    detail: `External ${req.channel} notification to verified private sink "${req.recipient_or_repo}" approved (${req.human_approval_id})`
  };
}

// ============================================================================
// Sprint 7 Production Security: Tamper-Evident Audit Log & Report Tenant Guard
// ============================================================================

export interface SecurityAuditLogEntry {
  sequence: number;
  timestamp: string;
  event_type:
    | 'tenant_access'
    | 'emergency_stop'
    | 'external_notification'
    | 'scope_validation'
    | 'report_export';
  organization_id: string;
  project_id: string;
  actor_id: string;
  resource_id: string;
  decision: 'ALLOW' | 'DENY';
  reason: string;
  prev_hash: string;
  entry_hash: string;
}

/**
 * Append-only SHA-256 hash-chained security audit log for control-plane & tenant boundary events.
 * Any modification, deletion, or reordering of entries invalidates `verifyIntegrity()`.
 */
export class TamperEvidentAuditLog {
  private readonly entries: SecurityAuditLogEntry[] = [];

  public append(params: {
    eventType: SecurityAuditLogEntry['event_type'];
    organizationId: string;
    projectId: string;
    actorId: string;
    resourceId: string;
    decision: 'ALLOW' | 'DENY';
    reason: string;
    now?: Date;
  }): SecurityAuditLogEntry {
    const sequence = this.entries.length + 1;
    const timestamp = (params.now ?? new Date()).toISOString();
    const prevHash =
      this.entries.length > 0 ? this.entries[this.entries.length - 1]!.entry_hash : '0'.repeat(64);
    const canonical = [
      String(sequence),
      timestamp,
      params.eventType,
      params.organizationId,
      params.projectId,
      params.actorId,
      params.resourceId,
      params.decision,
      params.reason,
      prevHash
    ].join('|');
    const entryHash = createHash('sha256').update(canonical, 'utf8').digest('hex');
    const entry: SecurityAuditLogEntry = {
      sequence,
      timestamp,
      event_type: params.eventType,
      organization_id: params.organizationId,
      project_id: params.projectId,
      actor_id: params.actorId,
      resource_id: params.resourceId,
      decision: params.decision,
      reason: params.reason,
      prev_hash: prevHash,
      entry_hash: entryHash
    };
    this.entries.push(entry);
    return entry;
  }

  public getEntries(): readonly SecurityAuditLogEntry[] {
    return this.entries;
  }

  public verifyIntegrity(): { valid: boolean; failedSequence?: number; reason?: string } {
    let expectedPrev = '0'.repeat(64);
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i]!;
      if (e.sequence !== i + 1) {
        return {
          valid: false,
          failedSequence: e.sequence,
          reason: `Sequence gap or reordering at index ${i} (expected ${i + 1}, got ${e.sequence})`
        };
      }
      if (e.prev_hash !== expectedPrev) {
        return {
          valid: false,
          failedSequence: e.sequence,
          reason: `Broken prev_hash chain at sequence ${e.sequence}`
        };
      }
      const canonical = [
        String(e.sequence),
        e.timestamp,
        e.event_type,
        e.organization_id,
        e.project_id,
        e.actor_id,
        e.resource_id,
        e.decision,
        e.reason,
        e.prev_hash
      ].join('|');
      const recomputed = createHash('sha256').update(canonical, 'utf8').digest('hex');
      if (recomputed !== e.entry_hash) {
        return {
          valid: false,
          failedSequence: e.sequence,
          reason: `Entry hash mismatch at sequence ${e.sequence} (tampering detected)`
        };
      }
      expectedPrev = e.entry_hash;
    }
    return { valid: true };
  }
}

/**
 * Enforces strict multi-tenant isolation across both the report envelope and every embedded finding,
 * preventing cross-tenant data leakage during report read/export operations (SEC-011 / Sprint 7).
 */
export function authorizeReportTenantAccess(params: {
  principal: TenantPrincipal;
  report: {
    report_id: string;
    organization_id: string;
    project_id: string;
    findings?: ReadonlyArray<{ id?: string; organization_id: string; project_id: string }>;
  };
  action: 'read_report' | 'export_artifact';
  auditLog?: TamperEvidentAuditLog;
  now?: Date;
}): PolicyDecision {
  const envelopeDecision = authorizeTenantResourceAccess({
    principal: params.principal,
    resource: {
      resource_type: 'report',
      resource_id: params.report.report_id,
      organization_id: params.report.organization_id,
      project_id: params.report.project_id
    },
    action: params.action
  });

  if (!envelopeDecision.allowed) {
    params.auditLog?.append({
      eventType: 'tenant_access',
      organizationId: params.report.organization_id,
      projectId: params.report.project_id,
      actorId: params.principal?.user_id ?? 'anonymous',
      resourceId: params.report.report_id,
      decision: 'DENY',
      reason: envelopeDecision.detail,
      now: params.now
    });
    return envelopeDecision;
  }

  for (const finding of params.report.findings ?? []) {
    if (
      finding.organization_id !== params.report.organization_id ||
      finding.project_id !== params.report.project_id
    ) {
      const detail = `Cross-tenant finding contamination detected inside report ${params.report.report_id}: finding (${finding.organization_id}/${finding.project_id}) does not match report tenant (${params.report.organization_id}/${params.report.project_id}) (SEC-011)`;
      params.auditLog?.append({
        eventType: 'tenant_access',
        organizationId: params.report.organization_id,
        projectId: params.report.project_id,
        actorId: params.principal.user_id,
        resourceId: params.report.report_id,
        decision: 'DENY',
        reason: detail,
        now: params.now
      });
      return {
        allowed: false,
        reason: 'unauthorized',
        detail
      };
    }
  }

  params.auditLog?.append({
    eventType: 'tenant_access',
    organizationId: params.report.organization_id,
    projectId: params.report.project_id,
    actorId: params.principal.user_id,
    resourceId: params.report.report_id,
    decision: 'ALLOW',
    reason: envelopeDecision.detail,
    now: params.now
  });

  return envelopeDecision;
}



