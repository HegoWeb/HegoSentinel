import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';
import {
  renderHtmlReport,
  renderMarkdownReport,
  renderSarifReport
} from '../../packages/report-engine/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';

function loadSourceGrant(): ScopeAuthorizationGrant {
  const base = JSON.parse(
    readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
  ) as ScopeAuthorizationGrant;
  return {
    ...base,
    profile: 'source',
    allowed_checks: ['CODE-001', 'DEP-001']
  };
}

describe('Integration Tests: Semgrep/Trivy Adapters and Report Exporters (JSON/MD/HTML/SARIF)', () => {
  it('Normalizes offline Semgrep (CODE-001) and Trivy (DEP-001) fixtures and exports valid SARIF 2.1.0', async () => {
    const grant = loadSourceGrant();
    const res = await executeScan({
      grant,
      mode: 'local-source',
      repositoryPath: './examples/safe-demo/sample-repo',
      fixture: {
        fixture_id: 'SOURCE-FIXTURE-01',
        description: 'Synthetic SAST + SCA fixture',
        endpoints: [],
        semgrep_fixture: {
          version: '1.90.0',
          results: [
            {
              check_id: 'laravel.security.raw-blade-unescaped',
              path: 'resources/views/profile.blade.php',
              start: { line: 42 },
              extra: {
                message: 'Unescaped Blade expression {!! $bio !!} observed',
                severity: 'WARNING',
                metadata: { confidence: 'HIGH' }
              }
            }
          ]
        },
        trivy_fixture: {
          SchemaVersion: 2,
          Metadata: { Version: '0.56.0' },
          Results: [
            {
              Target: 'package-lock.json',
              Vulnerabilities: [
                {
                  VulnerabilityID: 'CVE-2026-0001',
                  PkgName: 'example-lib',
                  InstalledVersion: '1.0.0',
                  FixedVersion: '1.0.1',
                  Severity: 'HIGH',
                  PrimaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001'
                }
              ]
            }
          ]
        }
      }
    });

    assert.equal(res.policyDecision.allowed, true);
    assert.equal(res.report.coverage.global_status, 'complete');
    assert.equal(res.report.findings.length, 2);

    const sarifRaw = renderSarifReport(res.report);
    const sarif = JSON.parse(sarifRaw);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 2);
    assert.equal(
      sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine,
      42
    );

    const html = renderHtmlReport(res.report);
    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('HS-CODE-0001'));
    assert.ok(html.includes('HS-DEP-0001'));

    const md = renderMarkdownReport(res.report);
    assert.ok(md.includes('HS-CODE-0001'));
    assert.ok(md.includes('HS-DEP-0001'));
  });
});

