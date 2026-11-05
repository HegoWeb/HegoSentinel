import { execFile } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  RULE_STANDARDS_CATALOG,
  SCANNER_VERSION,
  SCHEMA_VERSION,
  computeEvidenceHash,
  computeFindingFingerprint,
  normalizeAssetKey,
  type CheckCoverageRecord,
  type NormalizedFinding,
  type RiskPriority,
  type ScopeAuthorizationGrant
} from '../../../packages/findings-schema/src/index.ts';
import { getRemediationGuidance } from '../../../packages/remediation-catalog/src/index.ts';
import { redactSensitiveText } from '../../../packages/report-engine/src/index.ts';
import {
  validateAuthorizedRepositoryPath,
  type SubprocessExecRunner
} from '../../semgrep/src/index.ts';

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  Title?: string;
  PrimaryURL?: string;
}

export interface TrivyMisconfiguration {
  ID: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  PrimaryURL?: string;
  Status?: 'FAIL' | 'PASS';
}

export interface TrivyTargetResult {
  Target: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

export interface TrivyRawOutput {
  SchemaVersion?: number;
  Metadata?: {
    Version?: string;
    NextUpdate?: string;
    UpdatedAt?: string;
  };
  Results?: TrivyTargetResult[];
}

export interface TrivyAdapterOptions {
  grant: ScopeAuthorizationGrant;
  repositoryPath: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
  fixtureOutput?: TrivyRawOutput;
  execCommandOverride?: string;
  execRunner?: SubprocessExecRunner;
  signal?: AbortSignal;
  now?: Date;
}

export interface TrivyAdapterResult {
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
}

function mapTrivySeverity(sev?: string): RiskPriority {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return 'info';
  }
}

/**
 * Normalizes Trivy lockfile/dependency scan output into HegoSentinel findings (S1-02 / HSR-07).
 */
export function normalizeTrivyOutput(
  raw: TrivyRawOutput,
  grant: ScopeAuthorizationGrant,
  assetLabel: string,
  now: Date = new Date(),
  isRealSubprocess = false
): TrivyAdapterResult {
  const standardsEntry = RULE_STANDARDS_CATALOG['DEP-001'];
  const findings: NormalizedFinding[] = [];
  const results = Array.isArray(raw.Results) ? raw.Results : [];

  let counter = 0;
  for (const targetBlock of results) {
    const targetFile = normalizeAssetKey(targetBlock.Target || assetLabel);
    const vulns = Array.isArray(targetBlock.Vulnerabilities) ? targetBlock.Vulnerabilities : [];

    for (const v of vulns) {
      counter += 1;
      const vulnId = redactSensitiveText(v.VulnerabilityID || 'UNKNOWN-ADVISORY');
      const pkgName = redactSensitiveText(v.PkgName || 'unknown-package');
      const installedVer = redactSensitiveText(v.InstalledVersion || '0.0.0');
      const fixedVer = redactSensitiveText(v.FixedVersion || 'none-listed');

      const evidenceSummary = `Package "${pkgName}@${installedVer}" in ${targetFile} matches advisory ${vulnId} (fixed in: ${fixedVer})`;
      const fingerprint = computeFindingFingerprint({
        organization_id: grant.organization_id,
        project_id: grant.project_id,
        rule_id: 'DEP-001',
        asset_key: targetFile,
        context_key: `${pkgName}@${installedVer}:${vulnId}`
      });

      findings.push({
        schema_version: SCHEMA_VERSION,
        id: `HS-DEP-${String(counter).padStart(4, '0')}`,
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        organization_id: grant.organization_id,
        project_id: grant.project_id,
        asset_key: targetFile,
        fingerprint,
        title: `Vulnerable dependency lockfile entry: ${pkgName} (${vulnId})`,
        observed_condition: `Lockfile ${targetFile} declares ${pkgName}@${installedVer}, which is listed in published advisory ${vulnId}.`,
        evidence_summary: evidenceSummary,
        evidence_hash: computeEvidenceHash(evidenceSummary),
        inferred_risk:
          'If the vulnerable code path within the package is reachable at runtime, the application may be exposed to the flaw described in the advisory.',
        limitations:
          'Lockfile presence does not prove that the affected function is called in production or that dev-only dependencies are deployed.',
        confidence: 'high',
        risk_priority: mapTrivySeverity(v.Severity),
        priority_basis: 'internal_priority',
        verification_status: 'observed',
        scanner_version: SCANNER_VERSION,
        observed_at: now.toISOString(),
        standards: {
          ...standardsEntry.standards,
          references: v.PrimaryURL
            ? [...standardsEntry.standards.references, v.PrimaryURL]
            : standardsEntry.standards.references
        },
        remediation: getRemediationGuidance('DEP-001', 'default', grant.stack),
        validation_criterion: `Update ${pkgName} to >= ${fixedVer} in ${targetFile} and re-run DEP-001 scan.`
      });
    }

    const misconfigs = Array.isArray(targetBlock.Misconfigurations)
      ? targetBlock.Misconfigurations
      : [];
    for (const m of misconfigs) {
      if (m.Status === 'PASS') continue;
      counter += 1;
      const misconfigId = redactSensitiveText(m.ID || 'TRIVY-MISCONFIG');
      const titleText = redactSensitiveText(m.Title || m.Message || 'Configuration security issue');
      const messageText = redactSensitiveText(
        m.Message || m.Description || 'Insecure configuration setting detected'
      );
      const resolutionText = redactSensitiveText(
        m.Resolution || 'Apply hardened configuration settings'
      );
      const evidenceSummary = `Misconfiguration "${misconfigId}" in ${targetFile}: ${messageText} (resolution: ${resolutionText})`;
      const fingerprint = computeFindingFingerprint({
        organization_id: grant.organization_id,
        project_id: grant.project_id,
        rule_id: 'DEP-001',
        asset_key: targetFile,
        context_key: `misconfig:${misconfigId}`
      });

      findings.push({
        schema_version: SCHEMA_VERSION,
        id: `HS-DEP-${String(counter).padStart(4, '0')}`,
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        organization_id: grant.organization_id,
        project_id: grant.project_id,
        asset_key: targetFile,
        fingerprint,
        title: `Configuration weakness requires review: ${titleText} (${misconfigId})`,
        observed_condition: `File ${targetFile} triggered configuration check ${misconfigId}: ${messageText}`,
        evidence_summary: evidenceSummary,
        evidence_hash: computeEvidenceHash(evidenceSummary),
        inferred_risk:
          'Insecure infrastructure or application configuration settings can weaken isolation or expose sensitive surfaces.',
        limitations:
          'Static configuration scanning does not observe compensating runtime controls outside the repository.',
        confidence: 'high',
        risk_priority: mapTrivySeverity(m.Severity),
        priority_basis: 'internal_priority',
        verification_status: 'needs_review',
        scanner_version: SCANNER_VERSION,
        observed_at: now.toISOString(),
        standards: {
          ...standardsEntry.standards,
          references: m.PrimaryURL
            ? [...standardsEntry.standards.references, m.PrimaryURL]
            : standardsEntry.standards.references
        },
        remediation: getRemediationGuidance('DEP-001', 'default', grant.stack),
        validation_criterion: `Remediate ${misconfigId} in ${targetFile} (${resolutionText}) and re-run scan.`
      });
    }
  }

  const nextUpdateRaw = raw.Metadata?.NextUpdate;
  let dbFreshness: 'fresh' | 'stale' | 'unknown' = 'unknown';
  if (typeof nextUpdateRaw === 'string') {
    const nextUpdateMs = Date.parse(nextUpdateRaw);
    if (!Number.isNaN(nextUpdateMs)) {
      if (now.getTime() > nextUpdateMs) {
        return {
          coverage: {
            rule_id: 'DEP-001',
            rule_version: standardsEntry.version,
            status: 'failed',
            asset_key: assetLabel,
            tool_version: raw.Metadata?.Version ? `trivy-${raw.Metadata.Version}` : 'trivy-fixture',
            tool_status: raw.Metadata?.Version ? 'exited' : 'fixture',
            exit_code: 0,
            timed_out: false,
            db_freshness: 'stale',
            db_version: raw.Metadata?.UpdatedAt ?? nextUpdateRaw,
            positive_validation_passed: false,
            reason: `Trivy vulnerability database is stale (NextUpdate=${nextUpdateRaw} < now=${now.toISOString()}); positive clean claim blocked`
          },
          findings
        };
      }
      dbFreshness = 'fresh';
    }
  }

  const toolVersion = raw.Metadata?.Version
    ? `trivy-${raw.Metadata.Version}`
    : isRealSubprocess
      ? 'trivy-cli'
      : 'trivy-fixture';
  const toolStatus = raw.Metadata?.Version || isRealSubprocess ? 'exited' : 'fixture';

  return {
    coverage: {
      rule_id: 'DEP-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetLabel,
      tool_version: toolVersion,
      tool_status: toolStatus,
      exit_code: 0,
      timed_out: false,
      db_freshness: dbFreshness,
      db_version: raw.Metadata?.UpdatedAt ?? raw.Metadata?.NextUpdate,
      positive_validation_passed: findings.length === 0
    },
    findings
  };
}

/**
 * Runs Trivy filesystem/lockfile scan in read-only mode without running package managers (S1-02 / SEC-006 / SEC-008).
 */
export async function runTrivyAdapter(
  options: TrivyAdapterOptions
): Promise<TrivyAdapterResult> {
  const standardsEntry = RULE_STANDARDS_CATALOG['DEP-001'];
  const now = options.now ?? new Date();
  const assetLabel = normalizeAssetKey(options.repositoryPath);

  if (options.signal?.aborted) {
    return {
      coverage: {
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        status: 'failed',
        asset_key: assetLabel,
        tool_status: 'killed',
        timed_out: false,
        db_freshness: 'unknown',
        reason: 'Trivy scan cancelled by kill-switch signal before execution'
      },
      findings: []
    };
  }

  if (!options.grant.allowed_checks.includes('DEP-001')) {
    return {
      coverage: {
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetLabel,
        tool_status: 'blocked',
        reason: 'DEP-001 is not listed in grant allowed_checks'
      },
      findings: []
    };
  }

  const repoValidation = validateAuthorizedRepositoryPath(options.repositoryPath, options.grant);
  if (!repoValidation.allowed || !repoValidation.resolvedPath) {
    return {
      coverage: {
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetLabel,
        tool_status: 'blocked',
        reason: repoValidation.reason ?? 'Unauthorized repository path'
      },
      findings: []
    };
  }

  const binaryName = options.execCommandOverride ?? 'trivy';
  if (binaryName !== 'trivy') {
    return {
      coverage: {
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetLabel,
        tool_status: 'blocked',
        reason: `Disallowed adapter binary "${binaryName}" blocked by executable allowlist (SEC-006)`
      },
      findings: []
    };
  }

  if (options.fixtureOutput) {
    return normalizeTrivyOutput(options.fixtureOutput, options.grant, assetLabel, now);
  }

  if (!existsSync(repoValidation.resolvedPath) || !statSync(repoValidation.resolvedPath).isDirectory()) {
    return {
      coverage: {
        rule_id: 'DEP-001',
        rule_version: standardsEntry.version,
        status: 'failed',
        asset_key: assetLabel,
        tool_status: 'exited',
        exit_code: 2,
        reason: 'Target repository directory does not exist'
      },
      findings: []
    };
  }

  const timeoutMs = options.timeoutMs ?? 15000;
  const maxBufferBytes = options.maxBufferBytes ?? 2 * 1024 * 1024;
  const runner = options.execRunner ?? execFile;

  const toolsBin = resolve(process.cwd(), '.tools/bin');
  const trivyCacheDir = resolve(process.cwd(), '.tools/trivy-cache');
  const pathSep = process.platform === 'win32' ? ';' : ':';
  const augmentedPath = [toolsBin, process.env.PATH ?? ''].join(pathSep);
  const localTrivyWin = resolve(toolsBin, 'trivy.exe');
  const localTrivyPosix = resolve(toolsBin, 'trivy');
  const trivyExecutable = options.execRunner
    ? 'trivy'
    : existsSync(localTrivyWin)
      ? localTrivyWin
      : existsSync(localTrivyPosix)
        ? localTrivyPosix
        : 'trivy';

  return new Promise<TrivyAdapterResult>((resolvePromise) => {
    let settled = false;
    const child = runner(
      trivyExecutable,
      [
        'fs',
        '--scanners',
        'vuln',
        '--format',
        'json',
        '--quiet',
        '--skip-db-update',
        '--offline-scan',
        repoValidation.resolvedPath!
      ],
      {
        shell: false,
        timeout: timeoutMs,
        maxBuffer: maxBufferBytes,
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
          TRIVY_NO_PROGRESS: 'true',
          ...(existsSync(trivyCacheDir) ? { TRIVY_CACHE_DIR: trivyCacheDir } : {})
        }
      },
      (error: NodeJS.ErrnoException | null, stdout: string) => {
        if (settled) return;
        settled = true;

        if (options.signal?.aborted) {
          resolvePromise({
            coverage: {
              rule_id: 'DEP-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'killed',
              timed_out: false,
              db_freshness: 'unknown',
              positive_validation_passed: false,
              reason: 'Trivy scan terminated by kill-switch signal (SIGTERM -> SIGKILL)'
            },
            findings: []
          });
          return;
        }

        if (error) {
          const errCode = error.code;
          if (errCode === 'ENOENT') {
            resolvePromise({
              coverage: {
                rule_id: 'DEP-001',
                rule_version: standardsEntry.version,
                status: 'skipped',
                asset_key: assetLabel,
                tool_status: 'not_installed',
                timed_out: false,
                db_freshness: 'unknown',
                positive_validation_passed: false,
                reason: 'tool_not_installed: Trivy binary not found in PATH'
              },
              findings: []
            });
            return;
          }
          const isTimeout = errCode === 'ETIMEDOUT' || /timed out/i.test(error.message);
          resolvePromise({
            coverage: {
              rule_id: 'DEP-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: isTimeout ? 'timed_out' : 'exited',
              exit_code: typeof error.errno === 'number' ? error.errno : 1,
              timed_out: isTimeout,
              db_freshness: 'unknown',
              positive_validation_passed: false,
              reason: `Trivy execution failed or timed out: ${redactSensitiveText(error.message)}`
            },
            findings: []
          });
          return;
        }

        try {
          const postValidation = validateAuthorizedRepositoryPath(options.repositoryPath, options.grant);
          if (!postValidation.allowed) {
            resolvePromise({
              coverage: {
                rule_id: 'DEP-001',
                rule_version: standardsEntry.version,
                status: 'denied',
                asset_key: assetLabel,
                tool_status: 'blocked',
                positive_validation_passed: false,
                reason: `Post-scan TOCTOU scope re-validation failed: ${postValidation.reason ?? 'Unauthorized symlink mutation detected'}`
              },
              findings: []
            });
            return;
          }

          const parsed = JSON.parse(stdout) as TrivyRawOutput;
          resolvePromise(normalizeTrivyOutput(parsed, options.grant, assetLabel, now, true));
        } catch {
          resolvePromise({
            coverage: {
              rule_id: 'DEP-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'exited',
              exit_code: 1,
              timed_out: false,
              db_freshness: 'unknown',
              positive_validation_passed: false,
              reason: 'Failed to parse Trivy JSON output'
            },
            findings: []
          });
        }
      }
    );

    if (options.signal) {
      const onAbort = () => {
        if (child && typeof child.kill === 'function') {
          child.kill('SIGTERM');
          (
            setTimeout(() => {
              if (child && typeof child.kill === 'function') {
                child.kill('SIGKILL');
              }
            }, 250) as unknown as { unref?: () => void }
          ).unref?.();
        }
        if (!settled) {
          settled = true;
          resolvePromise({
            coverage: {
              rule_id: 'DEP-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'killed',
              timed_out: false,
              db_freshness: 'unknown',
              positive_validation_passed: false,
              reason: 'Trivy scan terminated by kill-switch signal (SIGTERM -> SIGKILL)'
            },
            findings: []
          });
        }
      };
      options.signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}
