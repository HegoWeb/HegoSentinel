import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runCli } from '../../packages/scanner-core/src/cli.ts';

describe('E2E Tests: CLI `hegosentinel demo --offline` and `hegosentinel compare` (SEC-014)', () => {
  it('Runs `hegosentinel demo --offline`, generates sanitized reports, and verifies re-test loop without external network calls', async () => {
    const demoRun = await runCli(['demo', '--offline']);
    assert.equal(demoRun.exitCode, 0);
    assert.match(demoRun.stdout, /SCAN-DEMO-BASELINE-001/);
    assert.match(demoRun.stdout, /SCAN-DEMO-PATCHED-002/);
    assert.match(demoRun.stdout, /VERIFIED_FIXED/);

    const baselinePath = resolve(process.cwd(), 'reports/demo-baseline.json');
    const patchedPath = resolve(process.cwd(), 'reports/demo-patched.json');
    const recheckMdPath = resolve(process.cwd(), 'reports/demo-recheck.md');

    assert.ok(existsSync(baselinePath));
    assert.ok(existsSync(patchedPath));
    assert.ok(existsSync(recheckMdPath));

    const baselineReport = JSON.parse(readFileSync(baselinePath, 'utf8'));
    assert.equal(baselineReport.summary.total_findings, 2);
    assert.equal(baselineReport.summary.informational_count, 2);

    // Ensure planted JWT cookie value from fixture-baseline.json is never present in output
    const rawMd = readFileSync(recheckMdPath, 'utf8');
    assert.ok(!rawMd.includes('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'));

    // Test `hegosentinel compare` CLI command directly
    const compareRun = await runCli([
      'compare',
      '--baseline',
      './reports/demo-baseline.json',
      '--current',
      './reports/demo-patched.json'
    ]);
    assert.equal(compareRun.exitCode, 0);
    const parsedCmp = JSON.parse(compareRun.stdout);
    assert.equal(parsedCmp.comparable, true);
    assert.equal(parsedCmp.counts.verified_fixed, 1);
    assert.equal(parsedCmp.counts.persistent, 1);
  });
});
