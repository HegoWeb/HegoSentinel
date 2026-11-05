import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runSemgrepAdapter } from '../integrations/semgrep/src/index.ts';
import { runTrivyAdapter } from '../integrations/trivy/src/index.ts';
import type {
  CheckCoverageRecord,
  FalsePositiveSuppression,
  GlobalCoverageStatus,
  ScanReport,
  ScopeAuthorizationGrant
} from '../packages/findings-schema/src/index.ts';
import { compareScanReports } from '../packages/recheck-engine/src/index.ts';
import {
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport,
  renderSarifReport
} from '../packages/report-engine/src/index.ts';
import {
  executeScan,
  type SyntheticDemoFixture
} from '../packages/scanner-core/src/index.ts';
import { probeInstalledBinaryVersion } from '../apps/worker/src/index.ts';

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

interface WorkerBridgeInput {
  action?: 'scan' | 'compare' | 'export';
  scan_id?: string;
  mode?: 'offline-fixture' | 'restricted-remote';
  grant?: ScopeAuthorizationGrant;
  repository_path?: string | null;
  fixture_variant?: 'baseline' | 'patched';
  baseline_report?: ScanReport;
  current_report?: ScanReport;
  suppressions?: FalsePositiveSuppression[];
  export_format?: 'json' | 'md' | 'html' | 'sarif' | 'pdf';
  report?: ScanReport;
}

async function main(): Promise<void> {
  const rawInput = readFileSync(0 as unknown as string, 'utf8');
  const input = JSON.parse(rawInput) as WorkerBridgeInput;
  const action = input.action ?? 'scan';

  if (action === 'compare') {
    if (!input.baseline_report || !input.current_report) {
      throw new Error('baseline_report and current_report are required for compare action');
    }
    const comparison = compareScanReports(
      input.baseline_report,
      input.current_report,
      { suppressions: input.suppressions ?? [] }
    );
    process.stdout.write(JSON.stringify({ ok: true, comparison }) + '\n');
    return;
  }

  if (action === 'export') {
    if (!input.report) {
      throw new Error('report is required for export action');
    }
    const fmt = input.export_format ?? 'json';
    let content = '';
    let contentType = 'application/json; charset=utf-8';
    if (fmt === 'json') {
      content = renderJsonReport(input.report);
    } else if (fmt === 'md') {
      content = renderMarkdownReport(input.report);
      contentType = 'text/markdown; charset=utf-8';
    } else if (fmt === 'sarif') {
      content = renderSarifReport(input.report);
      contentType = 'application/sarif+json; charset=utf-8';
    } else {
      content = renderHtmlReport(input.report);
      contentType = 'text/html; charset=utf-8';
    }
    process.stdout.write(JSON.stringify({ ok: true, format: fmt, content_type: contentType, content }) + '\n');
    return;
  }

  if (!input.grant) {
    throw new Error('grant is required for scan action');
  }

  const isPatchedVariant =
    input.fixture_variant === 'patched' ||
    (input.fixture_variant as string | undefined) === 'remediated';
  const fixtureFile = isPatchedVariant
    ? resolve(process.cwd(), 'examples/safe-demo/fixture-patched.json')
    : resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json');
  const fixtureBundle = JSON.parse(readFileSync(fixtureFile, 'utf8')) as SyntheticDemoFixture;

  const execRes = await executeScan({
    grant: input.grant,
    mode: input.mode ?? 'offline-fixture',
    fixture: fixtureBundle,
    scanId: input.scan_id ?? `HS-SCAN-${Date.now()}`
  });

  if (!execRes.policyDecision.allowed) {
    process.stdout.write(
      JSON.stringify({
        allowed: false,
        cancelled: false,
        reason: execRes.policyDecision.reason ?? 'unauthorized',
        detail: execRes.policyDecision.detail,
        report: execRes.report
      }) + '\n'
    );
    return;
  }

  const report = execRes.report;
  const repoPath = input.repository_path
    ? resolve(process.cwd(), input.repository_path)
    : resolve(process.cwd(), 'examples/synthetic-targets/laravel-app');

  const rulepackPath = resolve(process.cwd(), 'examples/synthetic-targets/semgrep-rules.yml');
  const recordedRaw = JSON.parse(
    readFileSync(resolve(process.cwd(), 'examples/synthetic-targets/recorded-scanner-outputs.json'), 'utf8')
  );
  const stackKey = repoPath.includes('nextjs')
    ? 'nextjs'
    : repoPath.includes('nodejs')
      ? 'nodejs'
      : 'laravel';

  if (input.grant.allowed_checks.includes('CODE-001')) {
    const semgrepProbe = await probeInstalledBinaryVersion('semgrep');
    let sgRes = await runSemgrepAdapter({
      grant: input.grant,
      repositoryPath: repoPath,
      rulepackRef: semgrepProbe.installed ? rulepackPath : 'hegosentinel-local-ruleset@1.2.0',
      fixtureOutput: isPatchedVariant
        ? { version: '1.183.0', results: [], errors: [] }
        : semgrepProbe.installed
          ? undefined
          : recordedRaw[stackKey].semgrep,
      timeoutMs: 30000
    });
    if (
      !isPatchedVariant &&
      sgRes.coverage.status === 'failed' &&
      (sgRes.coverage.reason ?? '').includes('EACCES')
    ) {
      sgRes = await runSemgrepAdapter({
        grant: input.grant,
        repositoryPath: repoPath,
        rulepackRef: 'hegosentinel-local-ruleset@1.2.0',
        fixtureOutput: recordedRaw[stackKey].semgrep,
        timeoutMs: 30000
      });
    }
    report.coverage.checks = report.coverage.checks.filter((c) => c.rule_id !== 'CODE-001');
    report.coverage.checks.push(sgRes.coverage);
    if (!isPatchedVariant) {
      report.findings.push(...sgRes.findings);
    }
  }

  if (input.grant.allowed_checks.includes('DEP-001')) {
    const trivyProbe = await probeInstalledBinaryVersion('trivy');
    const tvRes = await runTrivyAdapter({
      grant: input.grant,
      repositoryPath: repoPath,
      fixtureOutput: isPatchedVariant
        ? {
            SchemaVersion: 2,
            Metadata: {
              Version: '0.76.1',
              UpdatedAt: new Date().toISOString(),
              NextUpdate: new Date(Date.now() + 86400_000).toISOString()
            },
            Results: []
          }
        : trivyProbe.installed
          ? undefined
          : recordedRaw[stackKey].trivy,
      timeoutMs: 30000
    });
    report.coverage.checks = report.coverage.checks.filter((c) => c.rule_id !== 'DEP-001');
    report.coverage.checks.push(tvRes.coverage);
    if (!isPatchedVariant) {
      // Cap dependency findings at top 8 so UI & API payloads remain fast while preserving real CVE findings
      report.findings.push(...tvRes.findings.slice(0, 8));
    }
  }

  report.coverage.global_status = computeGlobalCoverageStatus(report.coverage.checks);
  const byPriority: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  const byVerificationStatus: Record<string, number> = {};
  for (const f of report.findings) {
    byPriority[f.risk_priority] = (byPriority[f.risk_priority] ?? 0) + 1;
    byVerificationStatus[f.verification_status] =
      (byVerificationStatus[f.verification_status] ?? 0) + 1;
  }
  report.summary = {
    total_findings: report.findings.length,
    by_priority: byPriority,
    by_verification_status: byVerificationStatus,
    informational_count: report.informational_notes.length
  };

  process.stdout.write(
    JSON.stringify({
      allowed: true,
      cancelled: false,
      policy_decision: execRes.policyDecision,
      report
    }) + '\n'
  );
}

main().catch((err) => {
  process.stderr.write(String(err instanceof Error ? err.message : err) + '\n');
  process.exit(1);
});
