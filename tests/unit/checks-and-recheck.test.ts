import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  validateFindingSemantics,
  type ScopeAuthorizationGrant
} from '../../packages/findings-schema/src/index.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';

function loadGrant(): ScopeAuthorizationGrant {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
  ) as ScopeAuthorizationGrant;
}

describe('Unit Tests: Web Observers, Negative Fixtures (HSR-04), and Re-Test Transitions', () => {
  it('HSR-04 Negative Fixtures: non-HTML asset, CSP-Report-Only, and public preference cookie do not produce false findings', async () => {
    const grant = loadGrant();
    const res = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: {
        fixture_id: 'NEGATIVE-FIXTURE-HSR04',
        description: 'Negative fixtures verifying zero false claims',
        endpoints: [
          {
            url: 'https://demo.example.test/api/status',
            status_code: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': ['theme=dark; Path=/', 'locale=tr; Path=/']
            }
          },
          {
            url: 'https://demo.example.test/staging',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Security-Policy-Report-Only': "default-src 'self'",
              'Set-Cookie': ['hegosentinel_session=abc; Path=/; Secure; HttpOnly; SameSite=Lax']
            }
          }
        ]
      }
    });

    assert.equal(res.policyDecision.allowed, true);
    assert.equal(res.report.findings.length, 0);
    assert.ok(res.report.informational_notes.length >= 2);
  });

  it('S1-03: Validates finding semantics and CVSS v4.0 vector requirement', async () => {
    const grant = loadGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );
    const res = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: baselineFixture
    });

    for (const f of res.report.findings) {
      const sem = validateFindingSemantics(f);
      assert.equal(sem.valid, true, sem.errors.join(', '));
    }

    // Invalid CVSS v4 without vector must fail validation
    const invalidFinding = {
      ...res.report.findings[0],
      priority_basis: 'cvss_v4' as const,
      cvss_v4_score: 7.5
    };
    const invalidSem = validateFindingSemantics(invalidFinding);
    assert.equal(invalidSem.valid, false);
  });

  it('S1-05: Verifies new, persistent, verified_fixed, and reopened state transitions', async () => {
    const grant = loadGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );
    const patchedFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-patched.json'), 'utf8')
    );

    const baselineScan = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-BASE',
      fixture: baselineFixture
    });
    const patchedScan = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-PATCHED',
      fixture: patchedFixture
    });

    // Baseline -> Patched: HS-0001 becomes verified_fixed, HS-0002 remains persistent
    const cmp1 = compareScanReports(baselineScan.report, patchedScan.report);
    assert.equal(cmp1.comparable, true);
    assert.equal(cmp1.counts.verified_fixed, 1);
    assert.equal(cmp1.counts.persistent, 1);

    // Patched -> Baseline (regression) with previouslyResolvedFingerprints: HS-0001 becomes reopened
    const resolvedFp = baselineScan.report.findings.find((f) => f.rule_id === 'WEB-HEADER-001')!.fingerprint;
    const cmpRegression = compareScanReports(patchedScan.report, baselineScan.report, {
      previouslyResolvedFingerprints: [resolvedFp]
    });
    assert.equal(cmpRegression.counts.reopened, 1);
    assert.equal(cmpRegression.counts.persistent, 1);
  });
});

