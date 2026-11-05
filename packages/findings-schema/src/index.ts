import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCHEMA_VERSION = '1.0.0' as const;
export const SCANNER_VERSION = '0.1.0-alpha.4' as const;

export type StackTag = 'laravel' | 'nextjs' | 'generic-web';
export type ScanProfile = 'local-demo' | 'safe-web' | 'source';
export type ScanMode = 'offline-fixture' | 'restricted-remote' | 'local-source';
export type AllowedHttpMethod = 'GET' | 'HEAD';

export type RuleId =
  | 'WEB-TLS-001'
  | 'WEB-HEADER-001'
  | 'WEB-COOKIE-001'
  | 'WEB-REDIRECT-001'
  | 'CODE-001'
  | 'DEP-001';

export type ConfidenceLevel = 'low' | 'medium' | 'high';
export type RiskPriority = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type PriorityBasis = 'internal_priority' | 'cvss_v4';

export type VerificationStatus =
  | 'observed'
  | 'needs_review'
  | 'confirmed'
  | 'false_positive'
  | 'no_longer_observed'
  | 'verified_fixed'
  | 'reopened';

export type RecheckState =
  | 'new'
  | 'persistent'
  | 'no_longer_observed'
  | 'verified_fixed'
  | 'reopened'
  | 'not_comparable'
  | 'skipped'
  | 'false_positive';

export type CheckExecutionStatus = 'executed' | 'skipped' | 'failed' | 'denied';
export type GlobalCoverageStatus = 'complete' | 'completed_with_gaps' | 'failed' | 'denied';

export interface ScopeTarget {
  scheme: 'https' | 'http';
  hostname: string;
  port: number;
  path_prefix: string;
}

export interface ScopeTimeWindow {
  start_at: string;
  end_at: string;
}

export interface ScopeAuthorizationGrant {
  schema_version: '1.0.0';
  grant_id: string;
  scope_version: number;
  organization_id: string;
  project_id: string;
  project_name: string;
  stack: StackTag[];
  profile: ScanProfile;
  owner: string;
  authorization_statement: string;
  domain_control_proof?: string;
  written_permission_ref: string;
  emergency_contact: string;
  issued_at: string;
  expires_at: string;
  time_window: ScopeTimeWindow;
  max_request_budget: number;
  allowed_methods: AllowedHttpMethod[];
  allowed_checks: RuleId[];
  targets: ScopeTarget[];
  allowed_repositories?: string[];
}

export interface StandardsMapping {
  cwe: string[];
  owasp_asvs_5_0: string[];
  owasp_wstg_4_2: string[];
  references: string[];
}

export interface FrameworkRemediationGuide {
  framework: StackTag;
  prerequisites: string;
  steps: string[];
  side_effects: string;
}

export interface RemediationGuidance {
  summary: string;
  owner_role: string;
  framework_guides: FrameworkRemediationGuide[];
}

export interface NormalizedFinding {
  schema_version: '1.0.0';
  id: string;
  rule_id: RuleId;
  rule_version: string;
  organization_id: string;
  project_id: string;
  asset_key: string;
  fingerprint: string;
  title: string;
  observed_condition: string;
  evidence_summary: string;
  evidence_hash: string;
  inferred_risk: string;
  limitations: string;
  confidence: ConfidenceLevel;
  risk_priority: RiskPriority;
  priority_basis: PriorityBasis;
  cvss_v4_vector?: string;
  cvss_v4_score?: number;
  verification_status: VerificationStatus;
  scanner_version: string;
  observed_at: string;
  standards: StandardsMapping;
  remediation: RemediationGuidance;
  validation_criterion: string;
}

export type ToolProcessStatus =
  | 'exited'
  | 'killed'
  | 'timed_out'
  | 'not_installed'
  | 'fixture'
  | 'blocked';

export type DbFreshnessStatus = 'fresh' | 'stale' | 'unknown';

export interface CheckCoverageRecord {
  rule_id: RuleId;
  rule_version: string;
  status: CheckExecutionStatus;
  asset_key: string;
  reason?: string;
  tool_version?: string;
  tool_status?: ToolProcessStatus;
  exit_code?: number;
  timed_out?: boolean;
  db_freshness?: DbFreshnessStatus;
  rulepack_version?: string;
  db_version?: string;
  positive_validation_passed?: boolean;
  /** Optional exact finding identities that received positive evidence on this run. */
  positive_validation_fingerprints?: string[];
}

export interface ScanCoverage {
  global_status: GlobalCoverageStatus;
  request_count: number;
  max_request_budget: number;
  checks: CheckCoverageRecord[];
}

export interface InformationalNote {
  rule_id: RuleId;
  asset_key: string;
  note: string;
}

export interface ScanReportSummary {
  total_findings: number;
  by_priority: Record<RiskPriority, number>;
  by_verification_status: Record<string, number>;
  informational_count: number;
}

export interface ScanReport {
  schema_version: '1.0.0';
  scan_id: string;
  organization_id: string;
  project_id: string;
  project_name: string;
  grant_id: string;
  scope_version: number;
  profile: ScanProfile;
  mode: ScanMode;
  scanner_version: string;
  started_at: string;
  finished_at: string;
  disclaimer: string;
  coverage: ScanCoverage;
  summary: ScanReportSummary;
  findings: NormalizedFinding[];
  informational_notes: InformationalNote[];
}

export interface FalsePositiveSuppression {
  fingerprint: string;
  organization_id: string;
  project_id: string;
  scope_version: number;
  reviewer: string;
  reason: string;
  expires_at: string;
}

export interface RecheckComparisonItem {
  fingerprint: string;
  rule_id: RuleId;
  asset_key: string;
  title: string;
  previous_state: string;
  recheck_state: RecheckState;
  explanation: string;
  suppression?: {
    reviewer: string;
    reason: string;
    expires_at: string;
  };
}

export interface RecheckComparisonReport {
  schema_version: '1.0.0';
  baseline_scan_id: string;
  current_scan_id: string;
  organization_id: string;
  project_id: string;
  comparable: boolean;
  incomparability_reasons: string[];
  compared_at: string;
  counts: Record<RecheckState, number>;
  items: RecheckComparisonItem[];
}

export const RULE_STANDARDS_CATALOG: Record<RuleId, { version: string; standards: StandardsMapping }> = {
  'WEB-HEADER-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-693', 'CWE-1021'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V14.4.1', 'ASVS-5.0.0-V14.4.3'],
      owasp_wstg_4_2: ['WSTG-CONF-07', 'WSTG-CLNT-09'],
      references: [
        'https://owasp.org/www-project-secure-headers/',
        'https://asvs.owasp.org/'
      ]
    }
  },
  'WEB-COOKIE-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-614', 'CWE-1004', 'CWE-1275'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V3.4.1', 'ASVS-5.0.0-V3.4.2', 'ASVS-5.0.0-V3.4.3'],
      owasp_wstg_4_2: ['WSTG-SESS-02'],
      references: [
        'https://owasp.org/www-community/controls/SecureCookieAttribute',
        'https://wstg.owasp.org/'
      ]
    }
  },
  'WEB-TLS-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-295', 'CWE-319', 'CWE-326'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V9.1.1', 'ASVS-5.0.0-V9.1.2'],
      owasp_wstg_4_2: ['WSTG-CRYP-01'],
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'
      ]
    }
  },
  'WEB-REDIRECT-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-601', 'CWE-319'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V5.1.5', 'ASVS-5.0.0-V9.1.1'],
      owasp_wstg_4_2: ['WSTG-CLNT-04'],
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
      ]
    }
  },
  'CODE-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-79', 'CWE-89', 'CWE-798'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V5.3.1', 'ASVS-5.0.0-V2.10.4'],
      owasp_wstg_4_2: ['WSTG-INPV-01'],
      references: [
        'https://semgrep.dev/products/community-edition/'
      ]
    }
  },
  'DEP-001': {
    version: '1.0.0',
    standards: {
      cwe: ['CWE-1395'],
      owasp_asvs_5_0: ['ASVS-5.0.0-V14.2.1'],
      owasp_wstg_4_2: ['WSTG-CONF-01'],
      references: [
        'https://trivy.dev/'
      ]
    }
  }
};

/**
 * Normalizes an asset URL or file key without swallowing method, path, or context (S1-03).
 */
export function normalizeAssetKey(rawAsset: string, method: AllowedHttpMethod = 'GET'): string {
  const trimmed = rawAsset.trim();
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    const parsed = new URL(trimmed);
    const scheme = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    const isDefaultPort =
      (scheme === 'https:' && (parsed.port === '' || parsed.port === '443')) ||
      (scheme === 'http:' && (parsed.port === '' || parsed.port === '80'));
    const portPart = isDefaultPort ? '' : `:${parsed.port}`;
    const pathname = parsed.pathname || '/';
    return `${method.toUpperCase()} ${scheme}//${hostname}${portPart}${pathname}`;
  }
  return trimmed.replace(/\\/g, '/');
}

/**
 * Generates a deterministic, project-and-organization-scoped semantic fingerprint (S1-03 / HSR-08).
 */
export function computeFindingFingerprint(params: {
  organization_id: string;
  project_id: string;
  rule_id: RuleId;
  asset_key: string;
  context_key: string;
}): string {
  const canonical = [
    params.organization_id.trim(),
    params.project_id.trim(),
    params.rule_id.trim(),
    params.asset_key.trim(),
    params.context_key.trim()
  ].join('|');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function computeEvidenceHash(sanitizedEvidence: string): string {
  return createHash('sha256').update(sanitizedEvidence, 'utf8').digest('hex');
}

/**
 * Validates that CVSS v4.0 scores are accompanied by a complete vector string;
 * otherwise requires priority_basis === 'internal_priority' (S1-03 / HSR-04).
 */
export function validateFindingSemantics(finding: NormalizedFinding): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (finding.schema_version !== SCHEMA_VERSION) {
    errors.push(`Unsupported schema_version: ${finding.schema_version}`);
  }
  if (!/^[a-f0-9]{64}$/.test(finding.fingerprint)) {
    errors.push('Invalid SHA-256 fingerprint format');
  }
  if (!/^[a-f0-9]{64}$/.test(finding.evidence_hash)) {
    errors.push('Invalid SHA-256 evidence_hash format');
  }
  if (!finding.organization_id || !finding.project_id) {
    errors.push('organization_id and project_id are required for tenant isolation (HSR-08)');
  }
  if (finding.priority_basis === 'cvss_v4') {
    if (!finding.cvss_v4_vector || !finding.cvss_v4_vector.startsWith('CVSS:4.0/')) {
      errors.push('CVSS v4.0 priority_basis requires a complete CVSS:4.0/... vector string');
    }
    if (typeof finding.cvss_v4_score !== 'number' || finding.cvss_v4_score < 0 || finding.cvss_v4_score > 10) {
      errors.push('CVSS v4.0 priority_basis requires a numeric score between 0.0 and 10.0');
    }
  } else if (finding.cvss_v4_score !== undefined) {
    errors.push('Numeric CVSS score must not be set when priority_basis is internal_priority');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

interface JsonSchemaNode {
  type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean';
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  additionalProperties?: boolean;
  properties?: Record<string, JsonSchemaNode>;
  items?: JsonSchemaNode;
  minItems?: number;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  format?: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCHEMAS_DIR = resolve(__dirname, '../../../schemas');

const REPORT_JSON_SCHEMA = JSON.parse(
  readFileSync(resolve(SCHEMAS_DIR, 'report.schema.json'), 'utf8')
) as JsonSchemaNode;
const FINDING_JSON_SCHEMA = JSON.parse(
  readFileSync(resolve(SCHEMAS_DIR, 'finding.schema.json'), 'utf8')
) as JsonSchemaNode;
const RECHECK_JSON_SCHEMA = JSON.parse(
  readFileSync(resolve(SCHEMAS_DIR, 'recheck.schema.json'), 'utf8')
) as JsonSchemaNode;

const SARIF_2_1_0_SCHEMA: JsonSchemaNode = {
  type: 'object',
  additionalProperties: false,
  required: ['$schema', 'version', 'runs'],
  properties: {
    $schema: { type: 'string', minLength: 10 },
    version: { type: 'string', const: '2.1.0' },
    runs: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['tool', 'results'],
        properties: {
          tool: {
            type: 'object',
            additionalProperties: false,
            required: ['driver'],
            properties: {
              driver: {
                type: 'object',
                additionalProperties: false,
                required: ['name', 'version', 'informationUri'],
                properties: {
                  name: { type: 'string', minLength: 1 },
                  version: { type: 'string', minLength: 1 },
                  informationUri: { type: 'string', minLength: 1 }
                }
              }
            }
          },
          results: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['ruleId', 'level', 'message', 'fingerprints', 'locations'],
              properties: {
                ruleId: { type: 'string', enum: ['CODE-001', 'DEP-001'] },
                level: { type: 'string', enum: ['error', 'warning', 'note'] },
                message: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['text'],
                  properties: {
                    text: { type: 'string', minLength: 1 }
                  }
                },
                fingerprints: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['hegosentinelFingerprintV1'],
                  properties: {
                    hegosentinelFingerprintV1: { type: 'string', pattern: '^[a-f0-9]{64}$' }
                  }
                },
                locations: {
                  type: 'array',
                  minItems: 1,
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['physicalLocation'],
                    properties: {
                      physicalLocation: {
                        type: 'object',
                        additionalProperties: false,
                        required: ['artifactLocation', 'region'],
                        properties: {
                          artifactLocation: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['uri'],
                            properties: {
                              uri: { type: 'string', minLength: 1 }
                            }
                          },
                          region: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['startLine'],
                            properties: {
                              startLine: { type: 'integer', minimum: 1 }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
};

const ISO_DATE_TIME_REGEX =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Recursive validator for the subset of JSON Schema Draft 2020-12 keywords used
 * by the bundled project schemas. This is NOT a complete 2020-12 implementation.
 * Currently enforces type, const, enum, required,
 * additionalProperties, minimum, maximum, minLength, maxLength, minItems, pattern, and format (NEW-03).
 */
export function validateAgainstJsonSchema(
  instance: unknown,
  schema: JsonSchemaNode,
  path = '$',
  errors: string[] = []
): string[] {
  if (schema.const !== undefined && instance !== schema.const) {
    errors.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(instance)}`);
    return errors;
  }

  if (schema.enum && !schema.enum.includes(instance)) {
    errors.push(`${path}: value ${JSON.stringify(instance)} is not in enum ${JSON.stringify(schema.enum)}`);
    return errors;
  }

  if (schema.type) {
    switch (schema.type) {
      case 'object': {
        if (!instance || typeof instance !== 'object' || Array.isArray(instance)) {
          errors.push(`${path}: expected object`);
          return errors;
        }
        const obj = instance as Record<string, unknown>;
        if (schema.required) {
          for (const reqKey of schema.required) {
            if (!(reqKey in obj) || obj[reqKey] === undefined) {
              errors.push(`${path}: missing required property "${reqKey}"`);
            }
          }
        }
        if (schema.additionalProperties === false && schema.properties) {
          for (const key of Object.keys(obj)) {
            if (!(key in schema.properties)) {
              errors.push(`${path}: unexpected additional property "${key}"`);
            }
          }
        }
        if (schema.properties) {
          for (const [key, propSchema] of Object.entries(schema.properties)) {
            if (key in obj && obj[key] !== undefined) {
              validateAgainstJsonSchema(obj[key], propSchema, `${path}.${key}`, errors);
            }
          }
        }
        break;
      }
      case 'array': {
        if (!Array.isArray(instance)) {
          errors.push(`${path}: expected array`);
          return errors;
        }
        if (schema.minItems !== undefined && instance.length < schema.minItems) {
          errors.push(`${path}: array length ${instance.length} is less than minItems ${schema.minItems}`);
        }
        if (schema.items) {
          for (let i = 0; i < instance.length; i += 1) {
            validateAgainstJsonSchema(instance[i], schema.items, `${path}[${i}]`, errors);
          }
        }
        break;
      }
      case 'string': {
        if (typeof instance !== 'string') {
          errors.push(`${path}: expected string`);
          return errors;
        }
        if (schema.minLength !== undefined && instance.length < schema.minLength) {
          errors.push(`${path}: string length ${instance.length} is less than minLength ${schema.minLength}`);
        }
        if (schema.maxLength !== undefined && instance.length > schema.maxLength) {
          errors.push(`${path}: string length ${instance.length} exceeds maxLength ${schema.maxLength}`);
        }
        if (schema.pattern && !new RegExp(schema.pattern).test(instance)) {
          errors.push(`${path}: string does not match pattern ${schema.pattern}`);
        }
        if (schema.format === 'date-time') {
          if (!ISO_DATE_TIME_REGEX.test(instance) || Number.isNaN(Date.parse(instance))) {
            errors.push(`${path}: invalid ISO-8601 date-time "${instance}"`);
          }
        }
        break;
      }
      case 'integer': {
        if (typeof instance !== 'number' || !Number.isInteger(instance)) {
          errors.push(`${path}: expected integer`);
          return errors;
        }
        if (schema.minimum !== undefined && instance < schema.minimum) {
          errors.push(`${path}: integer ${instance} is less than minimum ${schema.minimum}`);
        }
        if (schema.maximum !== undefined && instance > schema.maximum) {
          errors.push(`${path}: integer ${instance} exceeds maximum ${schema.maximum}`);
        }
        break;
      }
      case 'number': {
        if (typeof instance !== 'number' || Number.isNaN(instance)) {
          errors.push(`${path}: expected number`);
          return errors;
        }
        if (schema.minimum !== undefined && instance < schema.minimum) {
          errors.push(`${path}: number ${instance} is less than minimum ${schema.minimum}`);
        }
        if (schema.maximum !== undefined && instance > schema.maximum) {
          errors.push(`${path}: number ${instance} exceeds maximum ${schema.maximum}`);
        }
        break;
      }
      case 'boolean': {
        if (typeof instance !== 'boolean') {
          errors.push(`${path}: expected boolean`);
        }
        break;
      }
    }
  }

  return errors;
}

/**
 * Runtime validator for bundled JSON Schema keywords and cross-field checks for ScanReport documents
 * against schemas/report.schema.json and schemas/finding.schema.json (HS-AUDIT-008 / NEW-03).
 */
export function validateScanReportDocument(doc: unknown): { valid: boolean; errors: string[] } {
  const errors = validateAgainstJsonSchema(doc, REPORT_JSON_SCHEMA, '$');
  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const r = doc as ScanReport;

  if (Date.parse(r.finished_at) < Date.parse(r.started_at)) {
    errors.push('$.finished_at must not be earlier than $.started_at');
  }
  if (r.coverage.max_request_budget > 0 && r.coverage.request_count > r.coverage.max_request_budget) {
    errors.push('$.coverage.request_count exceeds $.coverage.max_request_budget');
  }
  if (r.summary.total_findings !== r.findings.length) {
    errors.push(
      `$.summary.total_findings (${r.summary.total_findings}) does not match $.findings.length (${r.findings.length})`
    );
  }
  if (r.summary.informational_count !== r.informational_notes.length) {
    errors.push(
      `$.summary.informational_count (${r.summary.informational_count}) does not match $.informational_notes.length (${r.informational_notes.length})`
    );
  }

  for (const [idx, check] of r.coverage.checks.entries()) {
    if (check.positive_validation_fingerprints?.length) {
      if (check.rule_id !== 'WEB-COOKIE-001' || check.status !== 'executed' ||
          check.positive_validation_passed !== true) {
        errors.push(`$.coverage.checks[${idx}]: per-finding proof requires executed WEB-COOKIE-001 positive coverage`);
      }
      const fingerprints = check.positive_validation_fingerprints;
      if (new Set(fingerprints).size !== fingerprints.length) {
        errors.push(`$.coverage.checks[${idx}]: duplicate positive validation fingerprint`);
      }
      if (r.findings.some((finding) =>
        finding.rule_id === check.rule_id && finding.asset_key === check.asset_key &&
        fingerprints.includes(finding.fingerprint))) {
        errors.push(`$.coverage.checks[${idx}]: a current finding cannot also be positive-validation evidence`);
      }
    }
  }

  r.findings.forEach((f, idx) => {
    validateAgainstJsonSchema(f, FINDING_JSON_SCHEMA, `$.findings[${idx}]`, errors);
    const sem = validateFindingSemantics(f);
    if (!sem.valid) {
      errors.push(...sem.errors.map((e) => `$.findings[${idx}]: ${e}`));
    }
    if (f.organization_id !== r.organization_id || f.project_id !== r.project_id) {
      errors.push(
        `$.findings[${idx}]: tenant boundary mismatch with parent ScanReport (${f.organization_id}/${f.project_id})`
      );
    }
  });

  return { valid: errors.length === 0, errors };
}

/**
 * Runtime validator for bundled JSON Schema keywords and cross-field checks for RecheckComparisonReport
 * against schemas/recheck.schema.json (HS-AUDIT-008 / NEW-03).
 */
export function validateRecheckReportDocument(doc: unknown): { valid: boolean; errors: string[] } {
  const errors = validateAgainstJsonSchema(doc, RECHECK_JSON_SCHEMA, '$');
  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const r = doc as RecheckComparisonReport;
  const sumCounts = Object.values(r.counts).reduce((acc, v) => acc + v, 0);
  if (sumCounts !== r.items.length) {
    errors.push(`$.counts sum (${sumCounts}) does not match $.items.length (${r.items.length})`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Runtime shape validator for HegoSentinel's emitted OASIS SARIF 2.1.0 subset (HS-AUDIT-008 / NEW-03).
 */
export function validateSarifDocument(doc: unknown): { valid: boolean; errors: string[] } {
  const errors = validateAgainstJsonSchema(doc, SARIF_2_1_0_SCHEMA, '$');
  return { valid: errors.length === 0, errors };
}

