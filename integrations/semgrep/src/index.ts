import { execFile } from 'node:child_process';
import { existsSync, lstatSync, realpathSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative, isAbsolute, join } from 'node:path';
import {
  RULE_STANDARDS_CATALOG,
  SCANNER_VERSION,
  SCHEMA_VERSION,
  computeEvidenceHash,
  computeFindingFingerprint,
  normalizeAssetKey,
  type CheckCoverageRecord,
  type NormalizedFinding,
  type ScopeAuthorizationGrant
} from '../../../packages/findings-schema/src/index.ts';
import { getRemediationGuidance } from '../../../packages/remediation-catalog/src/index.ts';
import { redactSensitiveText } from '../../../packages/report-engine/src/index.ts';

export interface RepoFsOperations {
  existsSync(path: string): boolean;
  lstatSync(path: string): { isSymbolicLink(): boolean; isDirectory(): boolean };
  realpathSync(path: string): string;
  readdirSync(path: string): string[];
  maxDepth?: number;
  maxEntries?: number;
}

const DEFAULT_REPO_FS: RepoFsOperations = {
  existsSync,
  lstatSync,
  realpathSync,
  readdirSync,
  maxDepth: 64,
  maxEntries: 25_000
};

function isPathInsideRoot(childPath: string, rootPath: string): boolean {
  const rel = relative(rootPath, childPath);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function inspectDirectorySymlinks(
  dirPath: string,
  approvedRealRoots: string[],
  fsOps: RepoFsOperations,
  depth = 0,
  visitedRealDirs: Set<string> = new Set<string>(),
  inspectionBudget: { entries: number } = { entries: 0 }
): { safe: boolean; reason?: string } {
  const maxDepth = fsOps.maxDepth ?? 64;
  if (depth > maxDepth) {
    return {
      safe: false,
      reason: `Repository directory depth (${depth}) exceeds maximum allowed inspection depth (${maxDepth}); failing closed (NEW-01)`
    };
  }

  let currentRealDir: string;
  try {
    currentRealDir = fsOps.realpathSync(dirPath);
  } catch {
    return {
      safe: false,
      reason: `Failed to resolve realpath for directory "${dirPath}" during scope inspection (NEW-01)`
    };
  }

  if (visitedRealDirs.has(currentRealDir)) {
    return {
      safe: false,
      reason: `Symlink directory cycle detected at "${currentRealDir}" (NEW-01)`
    };
  }
  const nextVisited = new Set<string>(visitedRealDirs);
  nextVisited.add(currentRealDir);

  let entries: string[] = [];
  try {
    entries = fsOps.readdirSync(dirPath);
  } catch (err) {
    return {
      safe: false,
      reason: `Unreadable directory "${dirPath}" encountered during scope inspection (${(err as Error).message}); failing closed (NEW-01)`
    };
  }

  for (const entry of entries) {
    inspectionBudget.entries += 1;
    if (inspectionBudget.entries > (fsOps.maxEntries ?? 25_000)) {
      return {
        safe: false,
        reason: `Repository inspection exceeded ${(fsOps.maxEntries ?? 25_000)} entries; cannot attest symlink safety without a bounded scan`
      };
    }
    const fullEntry = join(dirPath, entry);
    let stat: { isSymbolicLink(): boolean; isDirectory(): boolean };
    try {
      stat = fsOps.lstatSync(fullEntry);
    } catch (err) {
      return {
        safe: false,
        reason: `Unreadable filesystem entry "${fullEntry}" encountered during scope inspection (${(err as Error).message}); failing closed (NEW-01)`
      };
    }

    if (stat.isSymbolicLink()) {
      let resolvedTarget: string;
      try {
        resolvedTarget = fsOps.realpathSync(fullEntry);
      } catch {
        return {
          safe: false,
          reason: `Dangling or unresolvable symlink "${fullEntry}" blocked inside repository (HS-AUDIT-002 / NEW-01)`
        };
      }
      const insideApproved = approvedRealRoots.some((root) =>
        isPathInsideRoot(resolvedTarget, root)
      );
      if (!insideApproved) {
        return {
          safe: false,
          reason: `Symlink escape detected: "${fullEntry}" resolves to "${resolvedTarget}" outside allowed_repositories (HS-AUDIT-002 / NEW-01)`
        };
      }
    } else if (stat.isDirectory()) {
      // Never skip a directory without enforcing an equally strong exclusion at the scanner boundary.
      // An unchecked node_modules tree can otherwise conceal symlinks to unauthorized files.
      const sub = inspectDirectorySymlinks(
        fullEntry,
        approvedRealRoots,
        fsOps,
        depth + 1,
        nextVisited,
        inspectionBudget
      );
      if (!sub.safe) {
        return sub;
      }
    }
  }
  return { safe: true };
}

export interface SemgrepRawResult {
  check_id: string;
  path: string;
  start?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: 'ERROR' | 'WARNING' | 'INFO';
    metadata?: {
      cwe?: string | string[];
      confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
    };
  };
}

export interface SemgrepRawOutput {
  version?: string;
  results?: SemgrepRawResult[];
  errors?: unknown[];
}

export type SubprocessExecRunner = (
  file: string,
  args: readonly string[],
  options: {
    shell: false;
    timeout: number;
    maxBuffer: number;
    windowsHide: boolean;
    env: NodeJS.ProcessEnv;
  },
  callback: (error: NodeJS.ErrnoException | null, stdout: string, stderr: string) => void
) => { kill?: (signal?: string) => boolean } | void;

export interface SemgrepAdapterOptions {
  grant: ScopeAuthorizationGrant;
  repositoryPath: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
  rulepackRef?: string;
  fixtureOutput?: SemgrepRawOutput;
  execCommandOverride?: string;
  execRunner?: SubprocessExecRunner;
  fsOps?: RepoFsOperations;
  signal?: AbortSignal;
  now?: Date;
}

export interface SemgrepAdapterResult {
  coverage: CheckCoverageRecord;
  findings: NormalizedFinding[];
}

const FORBIDDEN_EXECUTABLES = new Set([
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'composer',
  'php',
  'node',
  'sh',
  'bash',
  'cmd',
  'cmd.exe',
  'powershell',
  'pwsh',
  'git'
]);

/**
 * Verifies repository path is explicitly authorized and free of lexical or physical symlink/junction
 * traversal escapes (HSR-03 / SEC-006 / HS-AUDIT-002).
 *
 * Security Boundary Note: Application-level path & realpath validation prevents accidental or symlink-based
 * directory traversal, but is NOT a substitute for an OS/container filesystem sandbox. Production worker
 * deployments must mount target repositories read-only inside an isolated container namespace.
 */
export function validateAuthorizedRepositoryPath(
  repoPath: string,
  grant: ScopeAuthorizationGrant,
  fsOps: RepoFsOperations = DEFAULT_REPO_FS
): { allowed: boolean; resolvedPath?: string; reason?: string } {
  if (!grant.allowed_checks.includes('CODE-001') && !grant.allowed_checks.includes('DEP-001')) {
    return { allowed: false, reason: 'Grant does not authorize source or dependency checks' };
  }
  if (!Array.isArray(grant.allowed_repositories) || grant.allowed_repositories.length === 0) {
    return { allowed: false, reason: 'No allowed_repositories configured in scope grant' };
  }

  const targetLexical = resolve(repoPath);
  const isLexicallyInsideApproved = grant.allowed_repositories.some((allowedRepo) =>
    isPathInsideRoot(targetLexical, resolve(allowedRepo))
  );

  if (!isLexicallyInsideApproved) {
    return {
      allowed: false,
      reason: `Repository path "${repoPath}" is outside grant allowed_repositories`
    };
  }

  const approvedRealRoots: string[] = [];
  for (const allowedRepo of grant.allowed_repositories) {
    const lexicalRoot = resolve(allowedRepo);
    if (fsOps.existsSync(lexicalRoot)) {
      try {
        approvedRealRoots.push(fsOps.realpathSync(lexicalRoot));
      } catch {
        // Ignore unresolvable configured root
      }
    }
  }

  if (approvedRealRoots.length === 0) {
    return {
      allowed: false,
      reason: 'None of the grant allowed_repositories exist on disk or could be resolved via realpath'
    };
  }

  if (!fsOps.existsSync(targetLexical)) {
    return {
      allowed: false,
      reason: `Target repository path "${repoPath}" does not exist`
    };
  }

  let targetRealpath: string;
  try {
    targetRealpath = fsOps.realpathSync(targetLexical);
  } catch {
    return {
      allowed: false,
      reason: `Failed to resolve physical realpath for "${repoPath}" (HS-AUDIT-002)`
    };
  }

  const isPhysicallyInsideApproved = approvedRealRoots.some((realRoot) =>
    isPathInsideRoot(targetRealpath, realRoot)
  );
  if (!isPhysicallyInsideApproved) {
    return {
      allowed: false,
      reason: `Physical repository path "${targetRealpath}" escapes grant allowed_repositories via symlink or junction (HS-AUDIT-002)`
    };
  }

  const symlinkInspection = inspectDirectorySymlinks(targetRealpath, approvedRealRoots, fsOps);
  if (!symlinkInspection.safe) {
    return {
      allowed: false,
      reason: symlinkInspection.reason
    };
  }

  return { allowed: true, resolvedPath: targetRealpath };
}

/**
 * Parses and normalizes Semgrep JSON output without exposing raw source lines (S1-02 / HSR-03 / HSR-06).
 */
export function normalizeSemgrepOutput(
  raw: SemgrepRawOutput,
  grant: ScopeAuthorizationGrant,
  assetLabel: string,
  now: Date = new Date(),
  rulepackRef = 'p/default'
): SemgrepAdapterResult {
  const standardsEntry = RULE_STANDARDS_CATALOG['CODE-001'];
  const findings: NormalizedFinding[] = [];
  const results = Array.isArray(raw.results) ? raw.results : [];

  results.forEach((item, index) => {
    const line = item.start?.line ?? 1;
    const normalizedPath = normalizeAssetKey(`${item.path}:${line}`);
    const checkId = redactSensitiveText(item.check_id || 'semgrep-rule');
    const message = redactSensitiveText(item.extra?.message || 'Static analysis pattern matched');
    const evidenceSummary = `Semgrep rule "${checkId}" matched at ${normalizedPath} (source snippet omitted by privacy policy)`;

    const rawSeverity = item.extra?.severity ?? 'WARNING';
    const riskPriority =
      rawSeverity === 'ERROR' ? 'high' : rawSeverity === 'WARNING' ? 'medium' : 'low';
    const rawConf = item.extra?.metadata?.confidence ?? 'MEDIUM';
    const confidence =
      rawConf === 'HIGH' ? 'high' : rawConf === 'LOW' ? 'low' : 'medium';

    const fingerprint = computeFindingFingerprint({
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      rule_id: 'CODE-001',
      asset_key: normalizedPath,
      context_key: checkId
    });

    findings.push({
      schema_version: SCHEMA_VERSION,
      id: `HS-CODE-${String(index + 1).padStart(4, '0')}`,
      rule_id: 'CODE-001',
      rule_version: standardsEntry.version,
      organization_id: grant.organization_id,
      project_id: grant.project_id,
      asset_key: normalizedPath,
      fingerprint,
      title: `Static code pattern requires review (${checkId})`,
      observed_condition: message,
      evidence_summary: evidenceSummary,
      evidence_hash: computeEvidenceHash(evidenceSummary),
      inferred_risk:
        'A static code pattern associated with potential input handling or security weakness was matched.',
      limitations:
        'Static pattern matching does not prove runtime reachability or exploitability; developer code review is required.',
      confidence,
      risk_priority: riskPriority,
      priority_basis: 'internal_priority',
      verification_status: 'needs_review',
      scanner_version: SCANNER_VERSION,
      observed_at: now.toISOString(),
      standards: standardsEntry.standards,
      remediation: getRemediationGuidance('CODE-001', 'default', grant.stack),
      validation_criterion: `Re-run CODE-001 scan on ${normalizedPath} and verify rule ${checkId} no longer matches.`
    });
  });

  return {
    coverage: {
      rule_id: 'CODE-001',
      rule_version: standardsEntry.version,
      status: 'executed',
      asset_key: assetLabel,
      tool_version: raw.version ? `semgrep-${raw.version}` : 'semgrep-fixture',
      tool_status: raw.version ? 'exited' : 'fixture',
      exit_code: 0,
      timed_out: false,
      rulepack_version: rulepackRef,
      positive_validation_passed: findings.length === 0
    },
    findings
  };
}

/**
 * Runs Semgrep Community Edition in a restricted, read-only subprocess with metrics off and shell: false (S1-02 / SEC-006 / SEC-008).
 */
export async function runSemgrepAdapter(
  options: SemgrepAdapterOptions
): Promise<SemgrepAdapterResult> {
  const standardsEntry = RULE_STANDARDS_CATALOG['CODE-001'];
  const now = options.now ?? new Date();
  const assetLabel = normalizeAssetKey(options.repositoryPath);
  const rulepackRef = options.rulepackRef ?? 'p/default';

  if (options.signal?.aborted) {
    return {
      coverage: {
        rule_id: 'CODE-001',
        rule_version: standardsEntry.version,
        status: 'failed',
        asset_key: assetLabel,
        tool_status: 'killed',
        timed_out: false,
        rulepack_version: rulepackRef,
        reason: 'Semgrep scan cancelled by kill-switch signal before execution'
      },
      findings: []
    };
  }

  if (!options.grant.allowed_checks.includes('CODE-001')) {
    return {
      coverage: {
        rule_id: 'CODE-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetLabel,
        tool_status: 'blocked',
        reason: 'CODE-001 is not listed in grant allowed_checks'
      },
      findings: []
    };
  }

  const repoValidation = validateAuthorizedRepositoryPath(
    options.repositoryPath,
    options.grant,
    options.fsOps
  );
  if (!repoValidation.allowed || !repoValidation.resolvedPath) {
    return {
      coverage: {
        rule_id: 'CODE-001',
        rule_version: standardsEntry.version,
        status: 'denied',
        asset_key: assetLabel,
        tool_status: 'blocked',
        reason: repoValidation.reason ?? 'Unauthorized repository path'
      },
      findings: []
    };
  }

  // Enforce executable allowlist (SEC-006: never invoke package managers, shells, or repo scripts)
  const binaryName = options.execCommandOverride ?? 'semgrep';
  if (FORBIDDEN_EXECUTABLES.has(binaryName.toLowerCase()) || binaryName !== 'semgrep') {
    return {
      coverage: {
        rule_id: 'CODE-001',
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
    const normalized = normalizeSemgrepOutput(
      options.fixtureOutput,
      options.grant,
      assetLabel,
      now,
      rulepackRef
    );
    const postValidation = validateAuthorizedRepositoryPath(
      options.repositoryPath,
      options.grant,
      options.fsOps
    );
    if (!postValidation.allowed || postValidation.resolvedPath !== repoValidation.resolvedPath) {
      return {
        coverage: {
          rule_id: 'CODE-001',
          rule_version: standardsEntry.version,
          status: 'denied',
          asset_key: assetLabel,
          tool_status: 'blocked',
          reason:
            postValidation.reason ??
            'TOCTOU repository path or symlink mutation detected during scan execution (NEW-01)'
        },
        findings: []
      };
    }
    return normalized;
  }

  if (!existsSync(repoValidation.resolvedPath) || !statSync(repoValidation.resolvedPath).isDirectory()) {
    return {
      coverage: {
        rule_id: 'CODE-001',
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
  const venvScriptsWin = resolve(process.cwd(), '.tools/semgrep-venv/Scripts');
  const venvBinPosix = resolve(process.cwd(), '.tools/semgrep-venv/bin');
  const pathSep = process.platform === 'win32' ? ';' : ':';
  const augmentedPath = [toolsBin, venvScriptsWin, venvBinPosix, process.env.PATH ?? ''].join(pathSep);
  const localSemgrepWin = resolve(venvScriptsWin, 'semgrep.exe');
  const localSemgrepPosix = resolve(venvBinPosix, 'semgrep');
  const semgrepExecutable = options.execRunner
    ? 'semgrep'
    : existsSync(localSemgrepWin)
      ? localSemgrepWin
      : existsSync(localSemgrepPosix)
        ? localSemgrepPosix
        : 'semgrep';

  return new Promise<SemgrepAdapterResult>((resolvePromise) => {
    let settled = false;
    const child = runner(
      semgrepExecutable,
      [
        'scan',
        '--json',
        '--quiet',
        '--metrics=off',
        '--disable-version-check',
        '--config',
        rulepackRef,
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
          PYTHONUTF8: '1',
          SEMGREP_SEND_METRICS: 'off',
          SEMGREP_ENABLE_VERSION_CHECK: '0'
        }
      },
      (error: NodeJS.ErrnoException | null, stdout: string) => {
        if (settled) return;
        settled = true;

        if (options.signal?.aborted) {
          resolvePromise({
            coverage: {
              rule_id: 'CODE-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'killed',
              timed_out: false,
              rulepack_version: rulepackRef,
              positive_validation_passed: false,
              reason: 'Semgrep scan terminated by kill-switch signal (SIGTERM -> SIGKILL)'
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
                rule_id: 'CODE-001',
                rule_version: standardsEntry.version,
                status: 'skipped',
                asset_key: assetLabel,
                tool_status: 'not_installed',
                timed_out: false,
                rulepack_version: rulepackRef,
                positive_validation_passed: false,
                reason: 'tool_not_installed: Semgrep Community Edition binary not found in PATH'
              },
              findings: []
            });
            return;
          }
          const isTimeout = errCode === 'ETIMEDOUT' || /timed out/i.test(error.message);
          resolvePromise({
            coverage: {
              rule_id: 'CODE-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: isTimeout ? 'timed_out' : 'exited',
              exit_code: typeof error.errno === 'number' ? error.errno : 1,
              timed_out: isTimeout,
              rulepack_version: rulepackRef,
              positive_validation_passed: false,
              reason: `Semgrep execution failed or timed out: ${redactSensitiveText(error.message)}`
            },
            findings: []
          });
          return;
        }

        const postValidation = validateAuthorizedRepositoryPath(
          options.repositoryPath,
          options.grant,
          options.fsOps
        );
        if (!postValidation.allowed || postValidation.resolvedPath !== repoValidation.resolvedPath) {
          resolvePromise({
            coverage: {
              rule_id: 'CODE-001',
              rule_version: standardsEntry.version,
              status: 'denied',
              asset_key: assetLabel,
              tool_status: 'blocked',
              positive_validation_passed: false,
              reason:
                postValidation.reason ??
                'TOCTOU repository path or symlink mutation detected during scan execution (NEW-01)'
            },
            findings: []
          });
          return;
        }

        try {
          const parsed = JSON.parse(stdout) as SemgrepRawOutput;
          resolvePromise(normalizeSemgrepOutput(parsed, options.grant, assetLabel, now, rulepackRef));
        } catch {
          resolvePromise({
            coverage: {
              rule_id: 'CODE-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'exited',
              exit_code: 1,
              timed_out: false,
              rulepack_version: rulepackRef,
              positive_validation_passed: false,
              reason: 'Failed to parse Semgrep JSON output'
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
              rule_id: 'CODE-001',
              rule_version: standardsEntry.version,
              status: 'failed',
              asset_key: assetLabel,
              tool_status: 'killed',
              timed_out: false,
              rulepack_version: rulepackRef,
              positive_validation_passed: false,
              reason: 'Semgrep scan terminated by kill-switch signal (SIGTERM -> SIGKILL)'
            },
            findings: []
          });
        }
      };
      options.signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}
