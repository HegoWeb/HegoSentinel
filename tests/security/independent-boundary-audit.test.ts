import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import { validateAuthorizedRepositoryPath } from '../../integrations/semgrep/src/index.ts';

const loadGrant = (): ScopeAuthorizationGrant => JSON.parse(
  readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
) as ScopeAuthorizationGrant;

const url = 'https://demo.example.test/';
const htmlBaseline = {
  fixture_id: 'AUDIT-HTML-BASELINE',
  description: 'HTML response without CSP',
  endpoints: [{ url, method: 'GET' as const, status_code: 200, headers: { 'Content-Type': 'text/html' } }]
};

describe('Independent alpha.3 boundary audit regressions', () => {
  it('AUD-2026-01: HTML to JSON or 404 must not verify a CSP fix', async () => {
    const grant = loadGrant();
    const baseline = await executeScan({ grant, mode: 'offline-fixture', fixture: htmlBaseline, scanId: 'AUD-HTML-BASELINE' });
    assert.equal(baseline.report.findings.some(f => f.rule_id === 'WEB-HEADER-001'), true);

    const cases = [
      { title: 'content-type changes to JSON', status_code: 200, headers: { 'Content-Type': 'application/json' } },
      { title: 'endpoint is now 404 with valid CSP', status_code: 404, headers: { 'Content-Type': 'text/html', 'Content-Security-Policy': "default-src 'self'" } }
    ];
    for (const [idx, currentCase] of cases.entries()) {
      const current = await executeScan({
        grant, mode: 'offline-fixture', scanId: `AUD-CURRENT-${idx}`,
        fixture: { fixture_id: `AUD-CASE-${idx}`, description: currentCase.title,
          endpoints: [{ url, method: 'GET', status_code: currentCase.status_code, headers: currentCase.headers as Record<string, string | string[]> }] }
      });
      const headerCoverage = current.report.coverage.checks.find(c => c.rule_id === 'WEB-HEADER-001');
      assert.equal(headerCoverage?.positive_validation_passed, false, currentCase.title);
      const compared = compareScanReports(baseline.report, current.report);
      assert.equal(compared.items.find(i => i.rule_id === 'WEB-HEADER-001')?.recheck_state, 'not_comparable', currentCase.title);
      assert.equal(compared.counts.verified_fixed, 0, currentCase.title);
    }
  });

  it('AUD-2026-02: Symlinks hidden inside node_modules do not bypass the approved repository boundary', () => {
    const parent = join(tmpdir(), `hegosentinel-repo-audit-${randomUUID()}`);
    const approved = join(parent, 'approved');
    const outside = join(parent, 'outside');
    const packageDir = join(approved, 'node_modules');
    mkdirSync(packageDir, { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(outside, 'private.txt'), 'SYNTHETIC_ONLY');
    try {
      try {
        symlinkSync(outside, join(packageDir, 'external'), process.platform === 'win32' ? 'junction' : 'dir');
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'EPERM') return; // Windows no symlink privileges
        throw e;
      }
      const grant: ScopeAuthorizationGrant = {
        ...loadGrant(), allowed_checks: ['CODE-001'], allowed_repositories: [approved]
      };
      const r = validateAuthorizedRepositoryPath(approved, grant);
      assert.equal(r.allowed, false, `Expected fail-closed path validation, got ${JSON.stringify(r)}`);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('AUD-2026-05: Caller-supplied egress flags cannot activate an unimplemented remote transport', async () => {
    const grant = { ...loadGrant(), profile: 'safe-web' as const };
    const result = await executeScan({
      grant, mode: 'restricted-remote',
      egressAttestation: {
        sandboxActive: true, allowlistedDestinationsOnly: true,
        internalPlaneReachable: false, ambientProxyDisabled: true
      },
      fixture: htmlBaseline
    });
    assert.equal(result.policyDecision.allowed, false);
    assert.equal(result.report.coverage.global_status, 'denied');
    assert.equal(result.report.coverage.request_count, 0);
  });

  it('AUD-2026-04: An oversized repository scope inspection fails closed within a configured entry budget', () => {
    const approved = resolve(process.cwd(), 'examples/safe-demo/sample-repo');
    const grant: ScopeAuthorizationGrant = {
      ...loadGrant(), allowed_checks: ['CODE-001'], allowed_repositories: [approved]
    };
    const res = validateAuthorizedRepositoryPath(approved, grant, {
      existsSync: () => true,
      realpathSync: (p: string) => resolve(p),
      maxEntries: 1,
      lstatSync: () => ({ isSymbolicLink: () => false, isDirectory: () => false }),
      readdirSync: () => ['first', 'second']
    });
    assert.equal(res.allowed, false);
    assert.match(res.reason ?? '', /inspection exceeded/);
  });

  it('AUD-2026-03: A false_positive decision from a different scope_version is not valid in the current scope', async () => {
    const grant = loadGrant();
    const baseline = await executeScan({ grant, mode: 'offline-fixture', fixture: htmlBaseline, scanId: 'AUD-BASE' });
    const current = await executeScan({ grant, mode: 'offline-fixture', fixture: htmlBaseline, scanId: 'AUD-CURRENT' });
    const first = baseline.report.findings.find(f => f.rule_id === 'WEB-HEADER-001');
    assert.ok(first);
    const comp = compareScanReports(baseline.report, current.report, {
      now: new Date('2026-11-04T20:00:00.000Z'),
      suppressions: [{ fingerprint: first.fingerprint,
        organization_id: grant.organization_id, project_id: grant.project_id,
        scope_version: grant.scope_version + 99, reviewer: 'test-reviewer',
        reason: 'approved for a different scope', expires_at: '2029-11-04T00:00:00Z' }]
    });
    assert.equal(comp.items.find(i => i.rule_id === 'WEB-HEADER-001')?.recheck_state, 'persistent');
  });
});
