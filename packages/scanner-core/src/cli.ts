import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SCANNER_VERSION,
  validateRecheckReportDocument,
  validateScanReportDocument,
  type ScanReport,
  type ScopeAuthorizationGrant
} from '../../findings-schema/src/index.ts';
import { compareScanReports } from '../../recheck-engine/src/index.ts';
import {
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport
} from '../../report-engine/src/index.ts';
import { executeScan, type SyntheticDemoFixture } from './index.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '../../..');

function parseArgs(argv: string[]): {
  command: string;
  flags: Record<string, string | boolean>;
} {
  const command = argv[0] ?? 'help';
  const flags: Record<string, string | boolean> = {};

  for (let i = 1; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = next;
        i += 1;
      }
    }
  }
  return { command, flags };
}

export async function runCli(argv: string[]): Promise<{ exitCode: number; stdout: string }> {
  const { command, flags } = parseArgs(argv);
  const outputLines: string[] = [];

  if (command === 'demo') {
    if (!flags.offline) {
      return {
        exitCode: 1,
        stdout: 'Error: `hegosentinel demo` requires `--offline` in v0.1 to guarantee zero external network traffic.\n'
      };
    }

    const scopePath = resolve(REPO_ROOT, 'examples/safe-demo/hegosentinel.scope.json');
    const baselineFixturePath = resolve(REPO_ROOT, 'examples/safe-demo/fixture-baseline.json');
    const patchedFixturePath = resolve(REPO_ROOT, 'examples/safe-demo/fixture-patched.json');
    const outDir = resolve(REPO_ROOT, typeof flags.output === 'string' ? flags.output : 'reports');
    mkdirSync(outDir, { recursive: true });

    const grant = JSON.parse(readFileSync(scopePath, 'utf8')) as ScopeAuthorizationGrant;
    const baselineFixture = JSON.parse(
      readFileSync(baselineFixturePath, 'utf8')
    ) as SyntheticDemoFixture;
    const patchedFixture = JSON.parse(
      readFileSync(patchedFixturePath, 'utf8')
    ) as SyntheticDemoFixture;

    const fixedTimestamp = new Date('2026-11-04T20:00:00.000Z');
    const patchedTimestamp = new Date('2026-11-04T20:05:00.000Z');

    // Run 1: Baseline offline scan
    const baselineExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-DEMO-BASELINE-001',
      fixture: baselineFixture,
      now: fixedTimestamp
    });

    if (!baselineExec.policyDecision.allowed) {
      return {
        exitCode: 1,
        stdout: `Baseline demo blocked by policy: ${baselineExec.policyDecision.detail}\n`
      };
    }

    // Run 2: Patched offline scan (after applying CSP fix)
    const patchedExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-DEMO-PATCHED-002',
      fixture: patchedFixture,
      now: patchedTimestamp
    });

    const comparison = compareScanReports(baselineExec.report, patchedExec.report, {
      now: patchedTimestamp
    });

    const baselineValidation = validateScanReportDocument(baselineExec.report);
    const patchedValidation = validateScanReportDocument(patchedExec.report);
    const recheckValidation = validateRecheckReportDocument(comparison);
    if (!baselineValidation.valid || !patchedValidation.valid || !recheckValidation.valid) {
      return {
        exitCode: 1,
        stdout: `Schema validation failed before export: ${[
          ...baselineValidation.errors,
          ...patchedValidation.errors,
          ...recheckValidation.errors
        ].join('; ')}\n`
      };
    }

    const baselineJsonPath = resolve(outDir, 'demo-baseline.json');
    const baselineMdPath = resolve(outDir, 'demo-baseline.md');
    const baselineHtmlPath = resolve(outDir, 'demo-baseline.html');

    const patchedJsonPath = resolve(outDir, 'demo-patched.json');
    const recheckJsonPath = resolve(outDir, 'demo-recheck.json');
    const recheckMdPath = resolve(outDir, 'demo-recheck.md');
    const recheckHtmlPath = resolve(outDir, 'demo-recheck.html');

    writeFileSync(baselineJsonPath, renderJsonReport(baselineExec.report), 'utf8');
    writeFileSync(baselineMdPath, renderMarkdownReport(baselineExec.report), 'utf8');
    writeFileSync(baselineHtmlPath, renderHtmlReport(baselineExec.report), 'utf8');

    writeFileSync(patchedJsonPath, renderJsonReport(patchedExec.report), 'utf8');
    writeFileSync(recheckJsonPath, `${JSON.stringify(comparison, null, 2)}\n`, 'utf8');
    writeFileSync(recheckMdPath, renderMarkdownReport(patchedExec.report, comparison), 'utf8');
    writeFileSync(recheckHtmlPath, renderHtmlReport(patchedExec.report, comparison), 'utf8');

    outputLines.push('=== HegoSentinel Offline Synthetic Demo (Zero External Network Access) ===');
    outputLines.push(`Grant Verified: ${grant.grant_id} (Scope v${grant.scope_version}) · Target: https://demo.example.test/`);
    outputLines.push('');
    outputLines.push(`[Run 1 — Baseline Scan: ${baselineExec.report.scan_id}]`);
    outputLines.push(`  Coverage Status: ${baselineExec.report.coverage.global_status.toUpperCase()} (${baselineExec.report.coverage.request_count}/${baselineExec.report.coverage.max_request_budget} requests)`);
    outputLines.push(`  Observations: ${baselineExec.report.summary.total_findings} · Informational Notes: ${baselineExec.report.summary.informational_count}`);
    for (const f of baselineExec.report.findings) {
      outputLines.push(`  - ${f.id} [${f.rule_id}] ${f.title} (Priority: ${f.risk_priority}, Confidence: ${f.confidence}, Status: ${f.verification_status})`);
    }
    outputLines.push('');
    outputLines.push(`[Run 2 — Re-Test After Sample Fixture Change: ${patchedExec.report.scan_id}]`);
    outputLines.push(`  Comparable: ${comparison.comparable}`);
    for (const item of comparison.items) {
      outputLines.push(`  - [${item.rule_id}] ${item.title}: ${item.previous_state} -> ${item.recheck_state.toUpperCase()}`);
    }
    outputLines.push('');
    outputLines.push('Generated Sanitized Artifacts:');
    outputLines.push(`  - ${baselineJsonPath}`);
    outputLines.push(`  - ${baselineMdPath}`);
    outputLines.push(`  - ${patchedJsonPath}`);
    outputLines.push(`  - ${recheckJsonPath}`);
    outputLines.push(`  - ${recheckMdPath}`);
    outputLines.push(`  - ${recheckHtmlPath}`);

    return { exitCode: 0, stdout: `${outputLines.join('\n')}\n` };
  }

  if (command === 'scan') {
    const scopeArg = typeof flags.scope === 'string' ? flags.scope : '';
    if (!scopeArg) {
      return {
        exitCode: 1,
        stdout: 'Error: `hegosentinel scan` requires `--scope <path-to-scope.json>`.\n'
      };
    }

    const scopePath = resolve(process.cwd(), scopeArg);
    const grant = JSON.parse(readFileSync(scopePath, 'utf8')) as ScopeAuthorizationGrant;
    const outDir = resolve(process.cwd(), typeof flags.output === 'string' ? flags.output : 'reports');
    mkdirSync(outDir, { recursive: true });

    let fixture: SyntheticDemoFixture | undefined;
    if (typeof flags.fixture === 'string') {
      fixture = JSON.parse(readFileSync(resolve(process.cwd(), flags.fixture), 'utf8')) as SyntheticDemoFixture;
    }

    const mode = fixture ? 'offline-fixture' : typeof flags.repo === 'string' ? 'local-source' : 'restricted-remote';
    const result = await executeScan({
      grant,
      mode,
      fixture,
      repositoryPath: typeof flags.repo === 'string' ? flags.repo : undefined
    });

    const reportValidation = validateScanReportDocument(result.report);
    if (!reportValidation.valid) {
      return {
        exitCode: 1,
        stdout: `Error: Generated scan report failed schema validation: ${reportValidation.errors.join('; ')}\n`
      };
    }

    const reportJsonPath = resolve(outDir, `${result.report.scan_id}.json`);
    const reportMdPath = resolve(outDir, `${result.report.scan_id}.md`);
    writeFileSync(reportJsonPath, renderJsonReport(result.report), 'utf8');
    writeFileSync(reportMdPath, renderMarkdownReport(result.report), 'utf8');

    if (!result.policyDecision.allowed) {
      return {
        exitCode: 2,
        stdout: `Scan denied by policy (${result.policyDecision.reason}): ${result.policyDecision.detail}\n`
      };
    }

    return {
      exitCode: 0,
      stdout: `Scan ${result.report.scan_id} finished (${result.report.coverage.global_status}). Reports saved to ${outDir}\n`
    };
  }

  if (command === 'compare') {
    const baselineArg = typeof flags.baseline === 'string' ? flags.baseline : '';
    const currentArg = typeof flags.current === 'string' ? flags.current : '';
    if (!baselineArg || !currentArg) {
      return {
        exitCode: 1,
        stdout: 'Error: `hegosentinel compare` requires `--baseline <file.json> --current <file.json>`.\n'
      };
    }

    const baseline = JSON.parse(readFileSync(resolve(process.cwd(), baselineArg), 'utf8')) as ScanReport;
    const current = JSON.parse(readFileSync(resolve(process.cwd(), currentArg), 'utf8')) as ScanReport;
    const baseValid = validateScanReportDocument(baseline);
    const currValid = validateScanReportDocument(current);
    if (!baseValid.valid || !currValid.valid) {
      return {
        exitCode: 1,
        stdout: `Error: Input report failed schema validation: ${[...baseValid.errors, ...currValid.errors].join('; ')}\n`
      };
    }

    const comparison = compareScanReports(baseline, current);
    const cmpValid = validateRecheckReportDocument(comparison);
    if (!cmpValid.valid) {
      return {
        exitCode: 1,
        stdout: `Error: Generated comparison report failed schema validation: ${cmpValid.errors.join('; ')}\n`
      };
    }

    return {
      exitCode: 0,
      stdout: `${JSON.stringify(comparison, null, 2)}\n`
    };
  }

  return {
    exitCode: 0,
    stdout: [
      `HegoSentinel CLI v${SCANNER_VERSION}`,
      'Usage:',
      '  hegosentinel demo --offline [--output ./reports]',
      '  hegosentinel scan --scope ./hegosentinel.scope.json [--fixture ./fixture.json] [--repo ./dir] [--output ./reports]',
      '  hegosentinel compare --baseline ./reports/first.json --current ./reports/second.json'
    ].join('\n') + '\n'
  };
}

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  runCli(process.argv.slice(2)).then(({ exitCode, stdout }) => {
    process.stdout.write(stdout);
    process.exitCode = exitCode;
  });
}

