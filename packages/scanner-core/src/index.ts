import {
  RULE_STANDARDS_CATALOG,
  SCANNER_VERSION,
  SCHEMA_VERSION,
  computeEvidenceHash,
  computeFindingFingerprint,
  normalizeAssetKey,
  type AllowedHttpMethod,
  type CheckCoverageRecord,
  type GlobalCoverageStatus,
  type InformationalNote,
  type NormalizedFinding,
  type RiskPriority,
  type ScanMode,
  type ScanReport,
  type ScopeAuthorizationGrant
} from '../../findings-schema/src/index.ts';
import {
  EmergencyStopRegistry,
  parseAndValidateCanonicalUrl,
  resolveAndPinDestination,
  validateRedirectTransition,
  validateScopeAuthorizationGrant,
  verifyConnectedSocketPeer,
  verifyRemoteEgressSandboxGate,
  type DnsResolver,
  type EgressSandboxAttestation,
  type PolicyDecision
} from '../../policy-engine/src/index.ts';
import { getRemediationGuidance } from '../../remediation-catalog/src/index.ts';
import { redactSensitiveText, sanitizeReport } from '../../report-engine/src/index.ts';
import { runSemgrepAdapter, type SemgrepRawOutput } from '../../../integrations/semgrep/src/index.ts';
import { runTrivyAdapter, type TrivyRawOutput } from '../../../integrations/trivy/src/index.ts';

export interface SyntheticTlsObservation {
  protocol: 'TLSv1.3' | 'TLSv1.2' | 'TLSv1.1' | 'TLSv1.0';
  certificate_valid: boolean;
  hostname_matches: boolean;
  days_until_expiry: number;
  trust_context_verified: boolean;
  handshake_error?: string;
}

export interface SyntheticEndpointFixture {
  url: string;
  method?: AllowedHttpMethod;
  status_code: number;
  headers: Record<string, string | string[]>;
  tls?: SyntheticTlsObservation;
  simulated_socket_peer_ip?: string;
}

export interface SyntheticDemoFixture {
  fixture_id: string;
  description: string;
  endpoints: SyntheticEndpointFixture[];
  semgrep_fixture?: SemgrepRawOutput;
  trivy_fixture?: TrivyRawOutput;
}

export interface ScanExecutionOptions {
  grant: ScopeAuthorizationGrant;
  mode: ScanMode;
  scanId?: string;
  fixture?: SyntheticDemoFixture;
  repositoryPath?: string;
  dnsResolver?: DnsResolver;
  egressAttestation?: EgressSandboxAttestation;
  emergencyStopRegistry?: EmergencyStopRegistry;
  emergencyStopTokenId?: string;
  signal?: AbortSignal;
  now?: Date;
}

const PUBLIC_NON_SENSITIVE_COOKIE_NAMES = new Set([
  'theme',
  'locale',
  'lang',
  'ui_lang',
  'color_mode',
  'timezone',
  'tz'
]);

const KNOWN_CSP_DIRECTIVES = new Set([
  'default-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'style-src',
  'style-src-elem',
  'style-src-attr',
  'img-src',
  'connect-src',
  'font-src',
  'object-src',
  'media-src',
  'frame-src',
  'child-src',
  'worker-src',
  'manifest-src',
  'Prefetch-src'.toLowerCase(),
  'base-uri',
  'form-action',
  'frame-ancestors',
  'sandbox',
  'upgrade-insecure-requests',
  'block-all-mixed-content',
  'require-trusted-types-for',
  'trusted-types',
  'report-uri',
  'report-to'
]);

const CORE_ENFORCING_CSP_DIRECTIVES = new Set([
  'default-src',
  'script-src',
  'object-src',
  'frame-ancestors'
]);

/**
 * Evaluates whether a Content-Security-Policy header contains valid, recognized W3C directives
 * and whether its script/default sources avoid wildcard or unsafe-inline/unsafe-eval fallbacks (NEW-02).
 */
export function evaluateCspPolicySemantics(rawCsp: string): {
  status: 'enforcing' | 'permissive' | 'invalid';
  positiveValidationPassed: boolean;
  reason: string;
} {
  const segments = rawCsp
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);

  if (segments.length === 0) {
    return {
      status: 'invalid',
      positiveValidationPassed: false,
      reason: 'Empty Content-Security-Policy header'
    };
  }

  const directives = new Map<string, string[]>();
  const unknownDirectives: string[] = [];
  const duplicateDirectives: string[] = [];

  // Multiple CSP headers are separate browser policies, not one comma-separated policy.
  // This observer cannot currently prove their combined behavior; fail conservatively.
  if (rawCsp.includes(',')) {
    return { status: 'invalid', positiveValidationPassed: false,
      reason: 'Multiple/comma-separated CSP policies require manual review' };
  }

  for (const seg of segments) {
    const tokens = seg.split(/\s+/).filter(Boolean);
    const name = (tokens[0] ?? '').toLowerCase();
    const values = tokens.slice(1);
    if (!KNOWN_CSP_DIRECTIVES.has(name)) {
      unknownDirectives.push(name);
    } else if (directives.has(name)) {
      // Browsers use the FIRST occurrence; last-wins could falsely certify an unsafe policy.
      duplicateDirectives.push(name);
    } else {
      directives.set(name, values);
    }
  }

  if (duplicateDirectives.length > 0) {
    return { status: 'invalid', positiveValidationPassed: false,
      reason: `Duplicate CSP directive(s): ${duplicateDirectives.join(', ')}` };
  }

  if (unknownDirectives.length > 0) {
    return {
      status: 'invalid',
      positiveValidationPassed: false,
      reason: `Unrecognized CSP directive(s): ${unknownDirectives.join(', ')}`
    };
  }

  const hasCoreDirective = [...directives.keys()].some((k) =>
    CORE_ENFORCING_CSP_DIRECTIVES.has(k)
  );
  if (!hasCoreDirective) {
    return {
      status: 'invalid',
      positiveValidationPassed: false,
      reason: 'CSP header lacks any core enforcing directive (default-src, script-src, object-src, or frame-ancestors)'
    };
  }

  const effectiveScriptSources =
    directives.get('script-src') ?? directives.get('default-src') ?? [];
  if (effectiveScriptSources.length === 0) {
    return {
      status: 'invalid',
      positiveValidationPassed: false,
      reason: 'CSP directive is missing source expression list'
    };
  }

  const lowerSources = effectiveScriptSources.map((s) => s.toLowerCase());
  const hasNonceOrHashOrStrictDynamic = lowerSources.some(
    (s) =>
      s.startsWith("'nonce-") ||
      s.startsWith("'sha256-") ||
      s.startsWith("'sha384-") ||
      s.startsWith("'sha512-") ||
      s === "'strict-dynamic'"
  );

  const unsafeReasons: string[] = [];
  if (lowerSources.includes('*') || lowerSources.includes('http:') || lowerSources.includes('https:')) {
    unsafeReasons.push('wildcard or scheme-wide script source (* / http: / https:)');
  }
  if (lowerSources.includes("'unsafe-eval'")) {
    unsafeReasons.push("'unsafe-eval'");
  }
  if (lowerSources.includes("'unsafe-inline'") && !hasNonceOrHashOrStrictDynamic) {
    unsafeReasons.push("unnonced 'unsafe-inline'");
  }
  if (lowerSources.includes('data:')) {
    unsafeReasons.push('data: script source');
  }

  // script-src-elem overrides script-src/default-src for script elements in CSP3;
  // it must not silently re-enable unsafe sources while a fallback looks strict.
  const effectiveElementSources = directives.get('script-src-elem');
  if (effectiveElementSources) {
    const lowerElementSources = effectiveElementSources.map((s) => s.toLowerCase());
    if (lowerElementSources.length === 0 || lowerElementSources.some(
      (source) => source === '*' || source.includes('*') || source === 'http:' ||
        source === 'https:' || source.startsWith('http://') ||
        source === 'data:' || source === "'unsafe-inline'" || source === "'unsafe-eval'"
    )) {
      unsafeReasons.push('permissive script-src-elem override');
    }
  }

  // script-src-attr overrides script-src/default-src for inline event handlers in CSP3
  const effectiveAttrSources = directives.get('script-src-attr');
  if (effectiveAttrSources) {
    const lowerAttrSources = effectiveAttrSources.map((s) => s.toLowerCase());
    if (lowerAttrSources.length === 0 || lowerAttrSources.some(
      (source) => source === '*' || source.includes('*') ||
        source === "'unsafe-inline'" || source === "'unsafe-hashes'"
    )) {
      unsafeReasons.push('permissive script-src-attr override');
    }
  }

  if (unsafeReasons.length > 0) {
    return {
      status: 'permissive',
      positiveValidationPassed: false,
      reason: `CSP header is present but permissive (${unsafeReasons.join(', ')}); manual review required`
    };
  }

  return {
    status: 'enforcing',
    positiveValidationPassed: true,
    reason: 'Valid enforcing Content-Security-Policy verified'
  };
}

const STANDARD_DISCLAIMER =
  'Automated assessment results are observations, not a certified penetration test or blanket guarantee of security. Absence of a finding does not prove absence of vulnerabilities.';

function getHeaderCaseInsensitive(
  headers: Record<string, string | string[]>,
  headerName: string
): string | undefined {
  const lower = headerName.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return Array.isArray(v) ? v.join(', ') : v;
    }
  }
  return undefined;
}

function getSetCookieHeaders(headers: Record<string, string | string[]>): string[] {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'set-cookie') {
      return Array.isArray(v) ? v : [v];
    }
  }
  return [];
}

/**
 * Parses a Set-Cookie header while IMMEDIATELY discarding the cookie value (Collection Minimization HSR-06).
 */
export function parseCookieMetadataWithoutValue(rawSetCookie: string): {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  path?: string;
  hasDomainAttribute: boolean;
  prefixViolations: string[];
  isPublicPreferenceCookie: boolean;
} {
  const segments = rawSetCookie.split(';').map((s) => s.trim()).filter(Boolean);
  const firstSegment = segments[0] ?? '';
  const eqIndex = firstSegment.indexOf('=');
  const rawName = (eqIndex >= 0 ? firstSegment.slice(0, eqIndex) : firstSegment).trim();
  const safeName = redactSensitiveText(rawName || 'unnamed_cookie');

  let secure = false;
  let httpOnly = false;
  let sameSite: string | undefined;
  let sameSiteCount = 0;
  let path: string | undefined;
  let hasDomainAttribute = false;

  for (let i = 1; i < segments.length; i += 1) {
    const attr = segments[i];
    const lower = attr.toLowerCase();
    if (lower === 'secure') {
      secure = true;
    } else if (lower === 'httponly') {
      httpOnly = true;
    } else if (lower.startsWith('samesite=')) {
      sameSiteCount += 1;
      const value = attr.slice('samesite='.length).trim().toLowerCase();
      // An arbitrary SameSite string is not a valid browser-enforced SameSite policy.
      sameSite = value === 'strict' ? 'Strict' : value === 'lax' ? 'Lax' :
        value === 'none' ? 'None' : undefined;
    } else if (lower.startsWith('path=')) {
      path = attr.slice('path='.length).trim();
    } else if (lower.startsWith('domain=')) {
      hasDomainAttribute = true;
    }
  }

  // Reject ambiguous duplicate SameSite attributes
  if (sameSiteCount > 1) {
    sameSite = undefined;
  }

  const prefixViolations: string[] = [];
  const lowerName = safeName.toLowerCase();
  if (lowerName.startsWith('__host-')) {
    if (!secure) {
      prefixViolations.push('__Host- prefix requires Secure');
    }
    if (path !== '/') {
      prefixViolations.push('__Host- prefix requires Path=/');
    }
    if (hasDomainAttribute) {
      prefixViolations.push('__Host- prefix forbids Domain attribute');
    }
  } else if (lowerName.startsWith('__secure-')) {
    if (!secure) {
      prefixViolations.push('__Secure- prefix requires Secure');
    }
  }

  return {
    name: safeName,
    secure,
    httpOnly,
    sameSite,
    path,
    hasDomainAttribute,
    prefixViolations,
    isPublicPreferenceCookie: PUBLIC_NON_SENSITIVE_COOKIE_NAMES.has(lowerName)
  };
}

/**
 * Evaluates WEB-HEADER-001 on a response (S1-01 / HSR-04).
 */
export function evaluateWebHeadersObserver(params: {
  grant: ScopeAuthorizationGrant;
  endpoint: SyntheticEndpointFixture;
  assetKey: string;
  now: Date;
  findingSeqStart: number;
}): {
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
  notes: InformationalNote[];
} {
  const { grant, endpoint, assetKey, now } = params;
  const standardsEntry = RULE_STANDARDS_CATALOG['WEB-HEADER-001'];
  const findings: NormalizedFinding[] = [];
  const notes: InformationalNote[] = [];

  const contentType = (getHeaderCaseInsensitive(endpoint.headers, 'content-type') ?? 'text/html').toLowerCase();
  const isHtmlDocument =
    contentType.includes('text/html') || contentType.includes('application/xhtml+xml');

  // An endpoint that no longer returns a successful HTML document has not proven
  // that the original HTML CSP exposure was fixed. Preserve non-applicability in coverage.
  if (endpoint.status_code < 200 || endpoint.status_code >= 300) {
    notes.push({
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      note: `HTTP ${endpoint.status_code} is not a successful HTML document response; CSP remediation cannot be verified on this response.`
    });
    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false,
        reason: `not_applicable: http_status_${endpoint.status_code}`
      },
      findings,
      notes
    };
  }

  // HSR-04 negative fixture: Do not claim missing CSP on non-HTML assets (e.g., JSON API or image)
  if (!isHtmlDocument) {
    notes.push({
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      note: `Non-HTML content-type (${contentType}) observed; document-level Content-Security-Policy check is not applicable.`
    });
    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false,
        reason: `not_applicable: non_html_content_type (${contentType})`
      },
      findings,
      notes
    };
  }

  const cspHeader = getHeaderCaseInsensitive(endpoint.headers, 'content-security-policy');
  const cspReportOnlyHeader = getHeaderCaseInsensitive(
    endpoint.headers,
    'content-security-policy-report-only'
  );
  const xContentType = getHeaderCaseInsensitive(endpoint.headers, 'x-content-type-options');

  if (xContentType?.toLowerCase() === 'nosniff') {
    notes.push({
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      note: 'X-Content-Type-Options: nosniff header is present on response.'
    });
  }

  // HSR-04 negative fixture: CSP Report-Only rollout is acknowledged as an active staging control, not an overstated vulnerability
  if (!cspHeader && cspReportOnlyHeader) {
    notes.push({
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      note: 'Content-Security-Policy-Report-Only header is present (staged rollout mode); promote to enforcing Content-Security-Policy after verifying violation reports.'
    });
    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false
      },
      findings,
      notes
    };
  }

  if (!cspHeader || cspHeader.trim().length === 0) {
    const evidenceSummary = `Response headers on ${assetKey} (HTTP ${endpoint.status_code}) did not include Content-Security-Policy.`;
    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      context_key: 'missing-content-security-policy'
    });

    findings.push({
      schema_version: SCHEMA_VERSION,
      id: `HS-${String(params.findingSeqStart).padStart(4, '0')}`,
      rule_id: 'WEB-HEADER-001',
      rule_version: standardsEntry.version,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      asset_key: assetKey,
      fingerprint,
      title: 'Content-Security-Policy header not observed',
      observed_condition:
        'The HTTP response for the HTML document did not include a Content-Security-Policy header.',
      evidence_summary: evidenceSummary,
      evidence_hash: computeEvidenceHash(evidenceSummary),
      inferred_risk:
        'An effective Content-Security-Policy adds a browser-enforced defense-in-depth layer that can restrict unauthorized script execution and framing.',
      limitations:
        'Absence of Content-Security-Policy alone does not prove an exploitable Cross-Site Scripting (XSS) or framing vulnerability.',
      confidence: 'high',
      risk_priority: 'medium',
      priority_basis: 'internal_priority',
      verification_status: 'observed',
      scanner_version: SCANNER_VERSION,
      observed_at: now.toISOString(),
      standards: standardsEntry.standards,
      remediation: getRemediationGuidance('WEB-HEADER-001', 'csp', grant.stack),
      validation_criterion:
        'Confirm an enforcing Content-Security-Policy header is emitted on the HTML endpoint and behaves as intended.'
    });

    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false
      },
      findings,
      notes
    };
  }

  const cspEval = evaluateCspPolicySemantics(cspHeader);

  if (cspEval.status === 'invalid') {
    const safeCsp = redactSensitiveText(cspHeader);
    const evidenceSummary = `Response on ${assetKey} emitted an invalid or unrecognized Content-Security-Policy ("${safeCsp}"): ${cspEval.reason}.`;
    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      context_key: 'invalid-content-security-policy'
    });

    findings.push({
      schema_version: SCHEMA_VERSION,
      id: `HS-${String(params.findingSeqStart).padStart(4, '0')}`,
      rule_id: 'WEB-HEADER-001',
      rule_version: standardsEntry.version,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      asset_key: assetKey,
      fingerprint,
      title: 'Content-Security-Policy header contains invalid or non-enforcing directives',
      observed_condition: `The response included a Content-Security-Policy header, but semantic validation failed (${cspEval.reason}).`,
      evidence_summary: evidenceSummary,
      evidence_hash: computeEvidenceHash(evidenceSummary),
      inferred_risk:
        'Browsers ignore unrecognized or malformed Content-Security-Policy directives, leaving the document without intended script or framing restrictions.',
      limitations:
        'Verify directive spelling and syntax against W3C CSP Level 3 specifications.',
      confidence: 'high',
      risk_priority: 'medium',
      priority_basis: 'internal_priority',
      verification_status: 'needs_review',
      scanner_version: SCANNER_VERSION,
      observed_at: now.toISOString(),
      standards: standardsEntry.standards,
      remediation: getRemediationGuidance('WEB-HEADER-001', 'csp', grant.stack),
      validation_criterion:
        'Emit a syntactically valid, enforcing Content-Security-Policy header with recognized directives (e.g., default-src, script-src, object-src, frame-ancestors).'
    });

    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false,
        reason: cspEval.reason
      },
      findings,
      notes
    };
  }

  if (cspEval.status === 'permissive') {
    notes.push({
      rule_id: 'WEB-HEADER-001',
      asset_key: assetKey,
      note: `${cspEval.reason}. Positive fix verification is withheld until permissive sources are restricted.`
    });

    return {
      coverage: {
        rule_id: 'WEB-HEADER-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: false,
        reason: cspEval.reason
      },
      findings,
      notes
    };
  }

  return {
    coverage: {
      rule_id: 'WEB-HEADER-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetKey,
      positive_validation_passed: true
    },
    findings,
    notes
  };
}

/**
 * Evaluates WEB-COOKIE-001 on response Set-Cookie headers without storing cookie values (S1-01 / HSR-04 / HSR-06).
 */
export function evaluateWebCookiesObserver(params: {
  grant: ScopeAuthorizationGrant;
  endpoint: SyntheticEndpointFixture;
  assetKey: string;
  now: Date;
  findingSeqStart: number;
}): {
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
  notes: InformationalNote[];
} {
  const { grant, endpoint, assetKey, now } = params;
  const standardsEntry = RULE_STANDARDS_CATALOG['WEB-COOKIE-001'];
  const findings: NormalizedFinding[] = [];
  const notes: InformationalNote[] = [];

  const setCookies = getSetCookieHeaders(endpoint.headers);
  let seq = params.findingSeqStart;
  const validatedCookieFingerprints: string[] = [];
  let inspectedSessionCookies = 0;

  for (const rawCookie of setCookies) {
    const meta = parseCookieMetadataWithoutValue(rawCookie);

    // HSR-04 negative fixture: Legitimate public UI preference cookies do not require HttpOnly
    if (meta.isPublicPreferenceCookie) {
      notes.push({
        rule_id: 'WEB-COOKIE-001',
        asset_key: assetKey,
        note: `Public UI preference cookie "${meta.name}" observed (value discarded); excluded from session cookie HttpOnly requirement.`
      });
      continue;
    }

    inspectedSessionCookies += 1;
    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'WEB-COOKIE-001',
      asset_key: assetKey,
      context_key: `cookie:${meta.name.toLowerCase()}`
    });

    const missingAttrs: string[] = [];
    if (!meta.secure) missingAttrs.push('Secure');
    if (!meta.httpOnly) missingAttrs.push('HttpOnly');
    if (!meta.sameSite) missingAttrs.push('SameSite (Lax, Strict, or None)');
    if (meta.sameSite === 'None' && !meta.secure) {
      missingAttrs.push('SameSite=None requires Secure');
    }
    for (const pv of meta.prefixViolations) {
      if (!missingAttrs.includes(pv)) {
        missingAttrs.push(pv);
      }
    }

    if (missingAttrs.length === 0) {
      validatedCookieFingerprints.push(fingerprint);
    } else {
      const evidenceSummary = `Cookie "${meta.name}" (value omitted) on ${assetKey} is missing or has invalid attribute(s): ${missingAttrs.join(', ')}.`;
      findings.push({
        schema_version: SCHEMA_VERSION,
        id: `HS-${String(seq).padStart(4, '0')}`,
        rule_id: 'WEB-COOKIE-001',
        rule_version: standardsEntry.version,
        organization_id: grant.organization_id,
        project_id: grant.project_id,
        asset_key: assetKey,
        fingerprint,
        title: `Session cookie attributes need review (${meta.name})`,
        observed_condition: `Set-Cookie header for "${meta.name}" did not include ${missingAttrs.join(', ')}.`,
        evidence_summary: evidenceSummary,
        evidence_hash: computeEvidenceHash(evidenceSummary),
        inferred_risk:
          'Session cookies without Secure, HttpOnly, or appropriate SameSite attributes may be exposed to cleartext transmission, client-side script access, or cross-site request inclusion.',
        limitations:
          'Whether each attribute is required depends on whether the cookie holds sensitive session state and the application cross-origin design.',
        confidence: 'medium',
        risk_priority: 'medium',
        priority_basis: 'internal_priority',
        verification_status: 'needs_review',
        scanner_version: SCANNER_VERSION,
        observed_at: now.toISOString(),
        standards: standardsEntry.standards,
        remediation: getRemediationGuidance('WEB-COOKIE-001', 'default', grant.stack),
        validation_criterion: `Verify Set-Cookie for "${meta.name}" emits Secure, HttpOnly, and SameSite over HTTPS.`
      });
      seq += 1;
    }
  }

  return {
    coverage: {
      rule_id: 'WEB-COOKIE-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetKey,
      positive_validation_passed: inspectedSessionCookies > 0 && findings.length === 0,
      // Identity-specific proof: another cookie on the same URL is NOT evidence
      // that a previously vulnerable cookie was secured.
      positive_validation_fingerprints: validatedCookieFingerprints
    },
    findings,
    notes
  };
}

/**
 * Evaluates WEB-TLS-001 on transport observations (S1-01).
 */
export function evaluateWebTlsObserver(params: {
  grant: ScopeAuthorizationGrant;
  endpoint: SyntheticEndpointFixture;
  assetKey: string;
  now: Date;
  findingSeqStart: number;
}): {
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
  notes: InformationalNote[];
} {
  const { grant, endpoint, assetKey, now } = params;
  const standardsEntry = RULE_STANDARDS_CATALOG['WEB-TLS-001'];
  const findings: NormalizedFinding[] = [];
  const notes: InformationalNote[] = [];

  if (!endpoint.tls) {
    return {
      coverage: {
        rule_id: 'WEB-TLS-001',
        rule_version: standardsEntry.version,
        status: 'skipped',
        asset_key: assetKey,
        reason: 'No TLS transport metadata present in fixture'
      },
      findings,
      notes
    };
  }

  if (endpoint.tls.handshake_error) {
    return {
      coverage: {
        rule_id: 'WEB-TLS-001',
        rule_version: standardsEntry.version,
        status: 'failed',
        asset_key: assetKey,
        positive_validation_passed: false,
        reason: `TLS handshake failed: ${redactSensitiveText(endpoint.tls.handshake_error)}`
      },
      findings,
      notes
    };
  }

  const hsts = getHeaderCaseInsensitive(endpoint.headers, 'strict-transport-security');
  const weakProtocol = endpoint.tls.protocol === 'TLSv1.0' || endpoint.tls.protocol === 'TLSv1.1';
  const issues: string[] = [];

  if (weakProtocol) issues.push(`deprecated protocol ${endpoint.tls.protocol}`);
  if (!endpoint.tls.certificate_valid && endpoint.tls.trust_context_verified) {
    issues.push('certificate validation failed');
  }
  if (endpoint.tls.days_until_expiry <= 0) {
    issues.push('certificate expired');
  }
  if (!endpoint.tls.hostname_matches) {
    issues.push('certificate hostname mismatch');
  }
  if (!hsts) {
    notes.push({
      rule_id: 'WEB-TLS-001',
      asset_key: assetKey,
      note: `TLS negotiated ${endpoint.tls.protocol} (${endpoint.tls.days_until_expiry} days remaining); Strict-Transport-Security header was not observed.`
    });
  }

  if (issues.length > 0) {
    const evidenceSummary = `TLS observation on ${assetKey}: ${issues.join(', ')}.`;
    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'WEB-TLS-001',
      asset_key: assetKey,
      context_key: issues.join(',')
    });

    findings.push({
      schema_version: SCHEMA_VERSION,
      id: `HS-${String(params.findingSeqStart).padStart(4, '0')}`,
      rule_id: 'WEB-TLS-001',
      rule_version: standardsEntry.version,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      asset_key: assetKey,
      fingerprint,
      title: 'TLS transport configuration requires hardening',
      observed_condition: `Observed TLS issues on ${assetKey}: ${issues.join(', ')}.`,
      evidence_summary: evidenceSummary,
      evidence_hash: computeEvidenceHash(evidenceSummary),
      inferred_risk: 'Weak TLS protocol versions or invalid certificate bindings weaken transport confidentiality and integrity.',
      limitations: 'Scanner TLS view reflects the tested edge endpoint and trust store at observation time.',
      confidence: endpoint.tls.trust_context_verified ? 'high' : 'medium',
      risk_priority: 'high',
      priority_basis: 'internal_priority',
      verification_status: 'observed',
      scanner_version: SCANNER_VERSION,
      observed_at: now.toISOString(),
      standards: standardsEntry.standards,
      remediation: getRemediationGuidance('WEB-TLS-001', 'default', grant.stack),
      validation_criterion: 'Confirm TLS 1.2/1.3 negotiation with valid certificate chain on target.'
    });
  }

  return {
    coverage: {
      rule_id: 'WEB-TLS-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetKey,
      positive_validation_passed: findings.length === 0
    },
    findings,
    notes
  };
}

/**
 * Evaluates WEB-REDIRECT-001 on HTTP redirect responses without following out-of-scope targets (S1-01 / SEC-003).
 */
export async function evaluateWebRedirectObserver(params: {
  grant: ScopeAuthorizationGrant;
  endpoint: SyntheticEndpointFixture;
  assetKey: string;
  resolver: DnsResolver;
  now: Date;
  findingSeqStart: number;
}): Promise<{
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
  notes: InformationalNote[];
}> {
  const { grant, endpoint, assetKey, resolver, now } = params;
  const standardsEntry = RULE_STANDARDS_CATALOG['WEB-REDIRECT-001'];
  const findings: NormalizedFinding[] = [];
  const notes: InformationalNote[] = [];

  const isRedirectStatus = [301, 302, 303, 307, 308].includes(endpoint.status_code);
  const locationHeader = getHeaderCaseInsensitive(endpoint.headers, 'location');

  if (!isRedirectStatus || !locationHeader) {
    return {
      coverage: {
        rule_id: 'WEB-REDIRECT-001',
        rule_version: standardsEntry.version,
        status: 'executed',
        asset_key: assetKey,
        positive_validation_passed: true
      },
      findings,
      notes
    };
  }

  const parsedSource = parseAndValidateCanonicalUrl(endpoint.url, grant, endpoint.method ?? 'GET');
  if (!parsedSource.decision.allowed || !parsedSource.target) {
    return {
      coverage: {
        rule_id: 'WEB-REDIRECT-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetKey,
        reason: parsedSource.decision.detail
      },
      findings,
      notes
    };
  }

  const redirectCheck = await validateRedirectTransition({
    fromUrl: parsedSource.target,
    locationHeader,
    redirectDepth: 0,
    grant,
    resolver
  });

  if (!redirectCheck.decision.allowed) {
    const safeLocation = redactSensitiveText(locationHeader);
    const isDowngrade = redirectCheck.decision.reason === 'protocol_downgrade';
    const evidenceSummary = `HTTP ${endpoint.status_code} response on ${assetKey} redirected to "${safeLocation}" (${redirectCheck.decision.reason}; redirect not followed).`;

    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'WEB-REDIRECT-001',
      asset_key: assetKey,
      context_key: redirectCheck.decision.reason ?? 'redirect-issue'
    });

    findings.push({
      schema_version: SCHEMA_VERSION,
      id: `HS-${String(params.findingSeqStart).padStart(4, '0')}`,
      rule_id: 'WEB-REDIRECT-001',
      rule_version: standardsEntry.version,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      asset_key: assetKey,
      fingerprint,
      title: isDowngrade
        ? 'Unexpected HTTPS-to-HTTP redirect downgrade observed'
        : 'Out-of-scope redirect target observed (not followed)',
      observed_condition: redirectCheck.decision.detail,
      evidence_summary: evidenceSummary,
      evidence_hash: computeEvidenceHash(evidenceSummary),
      inferred_risk: isDowngrade
        ? 'Downgrading an HTTPS request to cleartext HTTP exposes subsequent requests and cookies to network interception.'
        : 'Redirecting outside the authorized scope boundary may indicate an unvalidated redirect or external dependency.',
      limitations:
        'HegoSentinel never follows out-of-scope redirects; confirm whether the destination is an intentional external partner.',
      confidence: 'high',
      risk_priority: isDowngrade ? 'high' : 'medium',
      priority_basis: 'internal_priority',
      verification_status: 'observed',
      scanner_version: SCANNER_VERSION,
      observed_at: now.toISOString(),
      standards: standardsEntry.standards,
      remediation: getRemediationGuidance('WEB-REDIRECT-001', 'default', grant.stack),
      validation_criterion: 'Confirm redirects remain over HTTPS and stay within approved host/path boundaries.'
    });
  }

  return {
    coverage: {
      rule_id: 'WEB-REDIRECT-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetKey,
      positive_validation_passed: findings.length === 0
    },
    findings,
    notes
  };
}

function computeGlobalCoverageStatus(checks: CheckCoverageRecord[]): GlobalCoverageStatus {
  if (checks.length === 0) return 'failed';
  if (checks.every((c) => c.status === 'denied')) return 'denied';
  if (checks.some((c) => c.status === 'failed')) {
    return checks.some((c) => c.status === 'executed') ? 'completed_with_gaps' : 'failed';
  }
  if (checks.some((c) => c.status === 'skipped' || c.status === 'denied')) {
    return 'completed_with_gaps';
  }
  return 'complete';
}

function buildReportSummary(
  findings: NormalizedFinding[],
  notes: InformationalNote[]
): ScanReport['summary'] {
  const byPriority: Record<RiskPriority, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  const byVerificationStatus: Record<string, number> = {};

  for (const f of findings) {
    byPriority[f.risk_priority] = (byPriority[f.risk_priority] ?? 0) + 1;
    byVerificationStatus[f.verification_status] =
      (byVerificationStatus[f.verification_status] ?? 0) + 1;
  }

  return {
    total_findings: findings.length,
    by_priority: byPriority,
    by_verification_status: byVerificationStatus,
    informational_count: notes.length
  };
}

/**
 * Primary HegoSentinel scan runner enforcing fail-closed scope, SSRF/DNS pinning,
 * remote egress sandbox gate, and truthful coverage (Stage 0 + Stage 1).
 */
export async function executeScan(options: ScanExecutionOptions): Promise<{
  policyDecision: PolicyDecision;
  report: ScanReport;
}> {
  const now = options.now ?? new Date();
  const scanId = options.scanId ?? `SCAN-${now.toISOString().replace(/[:.]/g, '-')}`;
  const grant = options.grant;

  // 0. Check EmergencyStopRegistry / AbortSignal before executing any scan step (SEC-012)
  if (options.emergencyStopRegistry || options.signal?.aborted) {
    const stopCheck = options.emergencyStopRegistry
      ? options.emergencyStopRegistry.checkExecutionAllowed({
          runId: scanId,
          emergencyStopTokenId: options.emergencyStopTokenId,
          signal: options.signal
        })
      : {
          allowed: false,
          reason: 'unauthorized' as const,
          detail: `Execution aborted via AbortSignal for run ${scanId} (SEC-012)`
        };
    if (!stopCheck.allowed) {
      const deniedReport: ScanReport = sanitizeReport({
        schema_version: SCHEMA_VERSION,
        scan_id: scanId,
        organization_id: grant?.organization_id ?? 'unverified-org',
        project_id: grant?.project_id ?? 'unverified-project',
        project_name: grant?.project_name ?? 'Cancelled Scan',
        grant_id: grant?.grant_id ?? 'none',
        scope_version: grant?.scope_version ?? 0,
        profile: grant?.profile ?? 'safe-web',
        mode: options.mode,
        scanner_version: SCANNER_VERSION,
        started_at: now.toISOString(),
        finished_at: now.toISOString(),
        disclaimer: STANDARD_DISCLAIMER,
        coverage: {
          global_status: 'denied',
          request_count: 0,
          max_request_budget: grant?.max_request_budget ?? 0,
          checks: (grant?.allowed_checks ?? ['WEB-HEADER-001']).map((ruleId) => ({
            rule_id: ruleId,
            rule_version: RULE_STANDARDS_CATALOG[ruleId]?.version ?? '1.0.0',
            status: 'denied',
            asset_key: 'cancelled',
            reason: `${stopCheck.reason}: ${stopCheck.detail}`
          }))
        },
        summary: buildReportSummary([], []),
        findings: [],
        informational_notes: []
      });
      return { policyDecision: stopCheck, report: deniedReport };
    }
  }

  // 1. Validate Scope Authorization Grant first (SEC-001: zero requests on failure)
  const grantDecision = validateScopeAuthorizationGrant(grant, now);
  if (!grantDecision.allowed) {
    const deniedReport: ScanReport = sanitizeReport({
      schema_version: SCHEMA_VERSION,
      scan_id: scanId,
      organization_id: grant?.organization_id ?? 'unverified-org',
      project_id: grant?.project_id ?? 'unverified-project',
      project_name: grant?.project_name ?? 'Unauthorized Target',
      grant_id: grant?.grant_id ?? 'none',
      scope_version: grant?.scope_version ?? 0,
      profile: grant?.profile ?? 'safe-web',
      mode: options.mode,
      scanner_version: SCANNER_VERSION,
      started_at: now.toISOString(),
      finished_at: now.toISOString(),
      disclaimer: STANDARD_DISCLAIMER,
      coverage: {
        global_status: 'denied',
        request_count: 0,
        max_request_budget: grant?.max_request_budget ?? 0,
        checks: (grant?.allowed_checks ?? ['WEB-HEADER-001']).map((ruleId) => ({
          rule_id: ruleId,
          rule_version: RULE_STANDARDS_CATALOG[ruleId]?.version ?? '1.0.0',
          status: 'denied',
          asset_key: 'unverified',
          reason: `${grantDecision.reason}: ${grantDecision.detail}`
        }))
      },
      summary: buildReportSummary([], []),
      findings: [],
      informational_notes: []
    });

    return { policyDecision: grantDecision, report: deniedReport };
  }

  // 2. Remote HTTP/TLS transport is not implemented in this alpha release.
  // An in-process, caller-controlled boolean attestation is NOT proof that the OS has
  // enforced an egress sandbox. Keep remote mode disabled even if every flag is true.
  if (options.mode === 'restricted-remote') {
    const preflightDecision = verifyRemoteEgressSandboxGate(options.egressAttestation);
    const egressDecision: PolicyDecision = preflightDecision.allowed
      ? {
          allowed: false,
          reason: 'remote_egress_isolation_unverified',
          detail: 'Remote HTTP/TLS transport and independently verified network containment are not implemented in this alpha release; caller-supplied sandbox flags cannot enable a remote scan.'
        }
      : preflightDecision;
    const deniedReport: ScanReport = sanitizeReport({
      schema_version: SCHEMA_VERSION,
      scan_id: scanId,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      project_name: grant.project_name,
      grant_id: grant.grant_id,
      scope_version: grant.scope_version,
      profile: grant.profile,
      mode: options.mode,
      scanner_version: SCANNER_VERSION,
      started_at: now.toISOString(),
      finished_at: now.toISOString(),
      disclaimer: STANDARD_DISCLAIMER,
      coverage: {
        global_status: 'denied',
        request_count: 0,
        max_request_budget: grant.max_request_budget,
        checks: grant.allowed_checks.map((ruleId) => ({
          rule_id: ruleId,
          rule_version: RULE_STANDARDS_CATALOG[ruleId]?.version ?? '1.0.0',
          status: 'denied',
          asset_key: grant.targets[0]?.hostname ?? 'remote-target',
          reason: `${egressDecision.reason}: ${egressDecision.detail}`
        }))
      },
      summary: buildReportSummary([], []),
      findings: [],
      informational_notes: []
    });

    return { policyDecision: egressDecision, report: deniedReport };
  }

  const resolver: DnsResolver = options.dnsResolver ?? {
    resolve4: async () => ['93.184.216.34'],
    resolve6: async () => []
  };

  const coverageChecks: CheckCoverageRecord[] = [];
  const findings: NormalizedFinding[] = [];
  const notes: InformationalNote[] = [];
  let requestCount = 0;

  const endpoints = options.fixture?.endpoints ?? [];

  for (const endpoint of endpoints) {
    if (requestCount >= grant.max_request_budget) {
      for (const ruleId of grant.allowed_checks) {
        if (ruleId.startsWith('WEB-')) {
          coverageChecks.push({
            rule_id: ruleId,
            rule_version: RULE_STANDARDS_CATALOG[ruleId].version,
            status: 'skipped',
            asset_key: normalizeAssetKey(endpoint.url, endpoint.method ?? 'GET'),
            reason: 'budget_exhausted: max_request_budget reached'
          });
        }
      }
      break;
    }

    const method = endpoint.method ?? 'GET';
    const urlCheck = parseAndValidateCanonicalUrl(endpoint.url, grant, method);
    if (!urlCheck.decision.allowed || !urlCheck.target) {
      for (const ruleId of grant.allowed_checks.filter((r) => r.startsWith('WEB-'))) {
        coverageChecks.push({
          rule_id: ruleId,
          rule_version: RULE_STANDARDS_CATALOG[ruleId].version,
          status: 'denied',
          asset_key: redactSensitiveText(endpoint.url),
          reason: `${urlCheck.decision.reason}: ${urlCheck.decision.detail}`
        });
      }
      return {
        policyDecision: urlCheck.decision,
        report: sanitizeReport({
          schema_version: SCHEMA_VERSION,
          scan_id: scanId,
          organization_id: grant.organization_id,
          project_id: grant.project_id,
          project_name: grant.project_name,
          grant_id: grant.grant_id,
          scope_version: grant.scope_version,
          profile: grant.profile,
          mode: options.mode,
          scanner_version: SCANNER_VERSION,
          started_at: now.toISOString(),
          finished_at: now.toISOString(),
          disclaimer: STANDARD_DISCLAIMER,
          coverage: {
            global_status: 'denied',
            request_count: requestCount,
            max_request_budget: grant.max_request_budget,
            checks: coverageChecks
          },
          summary: buildReportSummary(findings, notes),
          findings,
          informational_notes: notes
        })
      };
    }

    const pinResult = await resolveAndPinDestination(urlCheck.target, resolver);
    if (!pinResult.decision.allowed || !pinResult.pinned) {
      for (const ruleId of grant.allowed_checks.filter((r) => r.startsWith('WEB-'))) {
        coverageChecks.push({
          rule_id: ruleId,
          rule_version: RULE_STANDARDS_CATALOG[ruleId].version,
          status: 'denied',
          asset_key: normalizeAssetKey(urlCheck.target.url, method),
          reason: `${pinResult.decision.reason}: ${pinResult.decision.detail}`
        });
      }
      return {
        policyDecision: pinResult.decision,
        report: sanitizeReport({
          schema_version: SCHEMA_VERSION,
          scan_id: scanId,
          organization_id: grant.organization_id,
          project_id: grant.project_id,
          project_name: grant.project_name,
          grant_id: grant.grant_id,
          scope_version: grant.scope_version,
          profile: grant.profile,
          mode: options.mode,
          scanner_version: SCANNER_VERSION,
          started_at: now.toISOString(),
          finished_at: now.toISOString(),
          disclaimer: STANDARD_DISCLAIMER,
          coverage: {
            global_status: 'denied',
            request_count: requestCount,
            max_request_budget: grant.max_request_budget,
            checks: coverageChecks
          },
          summary: buildReportSummary(findings, notes),
          findings,
          informational_notes: notes
        })
      };
    }

    // Verify socket peer IP to prevent TOCTOU DNS rebinding (SEC-004)
    const connectedPeerIp = endpoint.simulated_socket_peer_ip ?? pinResult.pinned.pinnedIp;
    const peerDecision = verifyConnectedSocketPeer(pinResult.pinned, connectedPeerIp);
    if (!peerDecision.allowed) {
      for (const ruleId of grant.allowed_checks.filter((r) => r.startsWith('WEB-'))) {
        coverageChecks.push({
          rule_id: ruleId,
          rule_version: RULE_STANDARDS_CATALOG[ruleId].version,
          status: 'denied',
          asset_key: normalizeAssetKey(urlCheck.target.url, method),
          reason: `${peerDecision.reason}: ${peerDecision.detail}`
        });
      }
      return {
        policyDecision: peerDecision,
        report: sanitizeReport({
          schema_version: SCHEMA_VERSION,
          scan_id: scanId,
          organization_id: grant.organization_id,
          project_id: grant.project_id,
          project_name: grant.project_name,
          grant_id: grant.grant_id,
          scope_version: grant.scope_version,
          profile: grant.profile,
          mode: options.mode,
          scanner_version: SCANNER_VERSION,
          started_at: now.toISOString(),
          finished_at: now.toISOString(),
          disclaimer: STANDARD_DISCLAIMER,
          coverage: {
            global_status: 'denied',
            request_count: requestCount,
            max_request_budget: grant.max_request_budget,
            checks: coverageChecks
          },
          summary: buildReportSummary(findings, notes),
          findings,
          informational_notes: notes
        })
      };
    }

    requestCount += 1;
    const assetKey = normalizeAssetKey(urlCheck.target.url, method);

    if (grant.allowed_checks.includes('WEB-HEADER-001')) {
      const headerRes = evaluateWebHeadersObserver({
        grant,
        endpoint,
        assetKey,
        now,
        findingSeqStart: findings.length + 1
      });
      coverageChecks.push(headerRes.coverage);
      findings.push(...headerRes.findings);
      notes.push(...headerRes.notes);
    }

    if (grant.allowed_checks.includes('WEB-COOKIE-001')) {
      const cookieRes = evaluateWebCookiesObserver({
        grant,
        endpoint,
        assetKey,
        now,
        findingSeqStart: findings.length + 1
      });
      coverageChecks.push(cookieRes.coverage);
      findings.push(...cookieRes.findings);
      notes.push(...cookieRes.notes);
    }

    if (grant.allowed_checks.includes('WEB-TLS-001')) {
      const tlsRes = evaluateWebTlsObserver({
        grant,
        endpoint,
        assetKey,
        now,
        findingSeqStart: findings.length + 1
      });
      coverageChecks.push(tlsRes.coverage);
      findings.push(...tlsRes.findings);
      notes.push(...tlsRes.notes);
    }

    if (grant.allowed_checks.includes('WEB-REDIRECT-001')) {
      const redirectRes = await evaluateWebRedirectObserver({
        grant,
        endpoint,
        assetKey,
        resolver,
        now,
        findingSeqStart: findings.length + 1
      });
      coverageChecks.push(redirectRes.coverage);
      findings.push(...redirectRes.findings);
      notes.push(...redirectRes.notes);
    }
  }

  // Optional local source & dependency checks (CODE-001 / DEP-001)
  if (options.repositoryPath) {
    if (grant.allowed_checks.includes('CODE-001')) {
      const semgrepRes = await runSemgrepAdapter({
        grant,
        repositoryPath: options.repositoryPath,
        fixtureOutput: options.fixture?.semgrep_fixture,
        signal: options.signal,
        now
      });
      coverageChecks.push(semgrepRes.coverage);
      findings.push(...semgrepRes.findings);
    }

    if (grant.allowed_checks.includes('DEP-001')) {
      const trivyRes = await runTrivyAdapter({
        grant,
        repositoryPath: options.repositoryPath,
        fixtureOutput: options.fixture?.trivy_fixture,
        signal: options.signal,
        now
      });
      coverageChecks.push(trivyRes.coverage);
      findings.push(...trivyRes.findings);
    }
  }

  const globalStatus = computeGlobalCoverageStatus(coverageChecks);

  const finalReport: ScanReport = sanitizeReport({
    schema_version: SCHEMA_VERSION,
    scan_id: scanId,
    organization_id: grant.organization_id,
    project_id: grant.project_id,
    project_name: grant.project_name,
    grant_id: grant.grant_id,
    scope_version: grant.scope_version,
    profile: grant.profile,
    mode: options.mode,
    scanner_version: SCANNER_VERSION,
    started_at: now.toISOString(),
    finished_at: now.toISOString(),
    disclaimer: STANDARD_DISCLAIMER,
    coverage: {
      global_status: globalStatus,
      request_count: requestCount,
      max_request_budget: grant.max_request_budget,
      checks: coverageChecks
    },
    summary: buildReportSummary(findings, notes),
    findings,
    informational_notes: notes
  });

  return {
    policyDecision: {
      allowed: true,
      detail: `Scan ${scanId} completed with coverage status ${globalStatus}`
    },
    report: finalReport
  };
}

