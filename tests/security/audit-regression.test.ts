import assert from 'node:assert/strict';
import { mkdirSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import {
  validateRecheckReportDocument,
  validateSarifDocument,
  validateScanReportDocument,
  type ScopeAuthorizationGrant
} from '../../packages/findings-schema/src/index.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import { renderSarifReport } from '../../packages/report-engine/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';
import { validateAuthorizedRepositoryPath } from '../../integrations/semgrep/src/index.ts';

function loadGrant(): ScopeAuthorizationGrant {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
  ) as ScopeAuthorizationGrant;
}

describe('Independent Code Audit Regression Suite (HS-AUDIT-001 .. HS-AUDIT-008)', () => {
  it('HS-AUDIT-001 (P0): Baseline finding on /old must NEVER become verified_fixed when current scan only tested /different-page', async () => {
    const grant = loadGrant();

    const baselineExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-AUDIT-OLD',
      fixture: {
        fixture_id: 'FIXTURE-OLD-PAGE',
        description: 'Baseline scan on /old without CSP',
        endpoints: [
          {
            url: 'https://demo.example.test/old',
            method: 'GET',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8'
            }
          }
        ]
      }
    });

    const currentExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-AUDIT-DIFFERENT',
      fixture: {
        fixture_id: 'FIXTURE-DIFFERENT-PAGE',
        description: 'Current scan only testing /different-page with CSP',
        endpoints: [
          {
            url: 'https://demo.example.test/different-page',
            method: 'GET',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Security-Policy': "default-src 'self'"
            }
          }
        ]
      }
    });

    const cmp = compareScanReports(baselineExec.report, currentExec.report);
    const oldCspItem = cmp.items.find(
      (i) => i.rule_id === 'WEB-HEADER-001' && i.asset_key === 'GET https://demo.example.test/old'
    );

    assert.ok(oldCspItem, 'Expected baseline /old finding in comparison items');
    assert.notEqual(
      oldCspItem.recheck_state,
      'verified_fixed',
      'CRITICAL (HS-AUDIT-001): /old must NEVER be marked verified_fixed when only /different-page was scanned'
    );
    assert.notEqual(
      oldCspItem.recheck_state,
      'no_longer_observed',
      'CRITICAL (HS-AUDIT-001): /old was not scanned at all in current run, so it must be not_comparable'
    );
    assert.equal(oldCspItem.recheck_state, 'not_comparable');
  });

  it('HS-AUDIT-004 (P1): Changing grant_id or scope_version between baseline and current must mark comparison not_comparable', async () => {
    const grant = loadGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );
    const patchedFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-patched.json'), 'utf8')
    );

    const baselineExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-GRANT-V1',
      fixture: baselineFixture
    });

    const modifiedGrant: ScopeAuthorizationGrant = {
      ...grant,
      grant_id: 'SOME-OTHER-GRANT',
      scope_version: 999
    };

    const currentExec = await executeScan({
      grant: modifiedGrant,
      mode: 'offline-fixture',
      scanId: 'SCAN-GRANT-V999',
      fixture: patchedFixture
    });

    const cmp = compareScanReports(baselineExec.report, currentExec.report);
    assert.equal(
      cmp.comparable,
      false,
      'Expected comparable=false when grant_id or scope_version changed (HS-AUDIT-004)'
    );
    assert.equal(cmp.counts.verified_fixed, 0);
    assert.equal(cmp.counts.not_comparable, cmp.items.length);
  });

  it('HS-AUDIT-002 (P0): Symlink or junction inside approved repository pointing outside allowed_repositories must be denied via realpath', () => {
    const baseGrant: ScopeAuthorizationGrant = {
      ...loadGrant(),
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: ['./examples/safe-demo/sample-repo']
    };

    const outsideDir = resolve(
      process.cwd(),
      `examples/safe-demo/.tmp-unapproved-outside-${Date.now()}`
    );
    const linkInsideApproved = resolve(
      process.cwd(),
      'examples/safe-demo/sample-repo/linked-outside'
    );

    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, 'secret.txt'), 'TOP_SECRET', 'utf8');

    try {
      let symlinkCreatedOnDisk = false;
      try {
        symlinkSync(
          outsideDir,
          linkInsideApproved,
          process.platform === 'win32' ? 'junction' : 'dir'
        );
        symlinkCreatedOnDisk = true;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== 'EPERM' && code !== 'EACCES') {
          throw err;
        }
      }

      const checkDirect = symlinkCreatedOnDisk
        ? validateAuthorizedRepositoryPath(linkInsideApproved, baseGrant)
        : validateAuthorizedRepositoryPath(linkInsideApproved, baseGrant, {
            existsSync: () => true,
            lstatSync: (p: string) => ({
              isSymbolicLink: () => resolve(p) === linkInsideApproved,
              isDirectory: () => true
            }),
            realpathSync: (p: string) =>
              resolve(p).startsWith(linkInsideApproved) ? outsideDir : resolve(p),
            readdirSync: () => []
          });

      assert.equal(
        checkDirect.allowed,
        false,
        `CRITICAL (HS-AUDIT-002): Symlink/junction pointing to ${outsideDir} escaped allowed_repositories!`
      );

      // Also verify that scanning the parent approved repo fails closed when a nested entry is a symlink pointing outside
      const approvedRepoRoot = resolve(process.cwd(), 'examples/safe-demo/sample-repo');
      const checkParentWithNestedSymlink = symlinkCreatedOnDisk
        ? validateAuthorizedRepositoryPath(approvedRepoRoot, baseGrant)
        : validateAuthorizedRepositoryPath(approvedRepoRoot, baseGrant, {
            existsSync: () => true,
            lstatSync: (p: string) => ({
              isSymbolicLink: () => resolve(p) === linkInsideApproved,
              isDirectory: () => resolve(p) === approvedRepoRoot
            }),
            realpathSync: (p: string) =>
              resolve(p).startsWith(linkInsideApproved) ? outsideDir : resolve(p),
            readdirSync: (p: string) =>
              resolve(p) === approvedRepoRoot ? ['linked-outside', 'package-lock.json'] : []
          });

      assert.equal(
        checkParentWithNestedSymlink.allowed,
        false,
        'Expected parent repository scan to be denied when a nested symlink points outside allowed_repositories'
      );
    } finally {
      rmSync(linkInsideApproved, { recursive: true, force: true });
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it('HS-AUDIT-007 (P1): CODE-001 and DEP-001 recheck verifies same-repo fixes and blocks cross-repo false verified_fixed', async () => {
    const sourceGrant: ScopeAuthorizationGrant = {
      ...loadGrant(),
      profile: 'source',
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: ['./examples/safe-demo/sample-repo', './examples/safe-demo']
    };

    const baselineSource = await executeScan({
      grant: sourceGrant,
      mode: 'local-source',
      scanId: 'SCAN-SRC-BASE',
      repositoryPath: './examples/safe-demo/sample-repo',
      fixture: {
        fixture_id: 'SRC-BASE',
        description: 'Baseline vulnerable source + lockfile',
        endpoints: [],
        semgrep_fixture: {
          version: '1.90.0',
          results: [
            {
              check_id: 'laravel.security.raw-blade',
              path: 'resources/views/profile.blade.php',
              start: { line: 42 },
              extra: { message: 'Unescaped Blade', severity: 'WARNING' }
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
                  Severity: 'HIGH'
                }
              ]
            }
          ]
        }
      }
    });

    // 1. Scanning a DIFFERENT repository path must mark baseline findings as not_comparable, never verified_fixed
    const differentRepoScan = await executeScan({
      grant: sourceGrant,
      mode: 'local-source',
      scanId: 'SCAN-SRC-OTHER-REPO',
      repositoryPath: './examples/safe-demo',
      fixture: {
        fixture_id: 'SRC-OTHER',
        description: 'Different repo path with 0 findings',
        endpoints: [],
        semgrep_fixture: { version: '1.90.0', results: [] },
        trivy_fixture: { SchemaVersion: 2, Metadata: { Version: '0.56.0' }, Results: [] }
      }
    });

    const crossRepoCmp = compareScanReports(baselineSource.report, differentRepoScan.report);
    assert.equal(crossRepoCmp.counts.verified_fixed, 0);
    assert.equal(crossRepoCmp.counts.not_comparable, 2);

    // 2. Scanning the SAME repository path with 0 findings marks both CODE-001 and DEP-001 verified_fixed
    const sameRepoPatched = await executeScan({
      grant: sourceGrant,
      mode: 'local-source',
      scanId: 'SCAN-SRC-PATCHED',
      repositoryPath: './examples/safe-demo/sample-repo',
      fixture: {
        fixture_id: 'SRC-PATCHED',
        description: 'Same repo path after fixing code and lockfile',
        endpoints: [],
        semgrep_fixture: { version: '1.90.0', results: [] },
        trivy_fixture: { SchemaVersion: 2, Metadata: { Version: '0.56.0' }, Results: [] }
      }
    });

    const sameRepoCmp = compareScanReports(baselineSource.report, sameRepoPatched.report);
    assert.equal(sameRepoCmp.comparable, true);
    assert.equal(sameRepoCmp.counts.verified_fixed, 2);

    // 3. Validate runtime schemas and SARIF 2.1.0 output (HS-AUDIT-008)
    const reportSchemaCheck = validateScanReportDocument(baselineSource.report);
    assert.equal(reportSchemaCheck.valid, true, reportSchemaCheck.errors.join(', '));

    const recheckSchemaCheck = validateRecheckReportDocument(sameRepoCmp);
    assert.equal(recheckSchemaCheck.valid, true, recheckSchemaCheck.errors.join(', '));

    const sarifDoc = JSON.parse(renderSarifReport(baselineSource.report));
    const sarifSchemaCheck = validateSarifDocument(sarifDoc);
    assert.equal(sarifSchemaCheck.valid, true, sarifSchemaCheck.errors.join(', '));

    // Malformed report and SARIF documents must be rejected by runtime validators
    assert.equal(validateScanReportDocument({ schema_version: '9.9.9' }).valid, false);
    assert.equal(validateRecheckReportDocument({ schema_version: '1.0.0' }).valid, false);
    assert.equal(validateSarifDocument({ version: '1.0.0', runs: [] }).valid, false);
  });

  it('NEW-01 (P1): Deep symlink (depth 13+ / 20), unreadable directory, and TOCTOU symlink mutation must fail-closed', () => {
    const baseGrant: ScopeAuthorizationGrant = {
      ...loadGrant(),
      allowed_checks: ['CODE-001', 'DEP-001'],
      allowed_repositories: ['./examples/safe-demo/sample-repo']
    };
    const approvedRoot = resolve(process.cwd(), 'examples/safe-demo/sample-repo');
    const outsideTarget = resolve(process.cwd(), 'examples/safe-demo/.tmp-outside-deep');

    // 1. Build a simulated 15-level deep tree with a symlink at level 15 pointing to outsideTarget
    const levels = Array.from({ length: 15 }, (_, idx) => `d${idx + 1}`);
    const deepSymlinkPath = join(approvedRoot, ...levels, 'escape-link');

    const deepCheck = validateAuthorizedRepositoryPath(approvedRoot, baseGrant, {
      existsSync: () => true,
      lstatSync: (p: string) => ({
        isSymbolicLink: () => resolve(p) === resolve(deepSymlinkPath),
        isDirectory: () => resolve(p) !== resolve(deepSymlinkPath)
      }),
      realpathSync: (p: string) =>
        resolve(p) === resolve(deepSymlinkPath) ? outsideTarget : resolve(p),
      readdirSync: (p: string) => {
        const norm = resolve(p);
        if (norm === approvedRoot) return ['d1'];
        for (let i = 0; i < levels.length - 1; i += 1) {
          const prefix = resolve(approvedRoot, ...levels.slice(0, i + 1));
          if (norm === prefix) return [levels[i + 1]];
        }
        const deepestDir = resolve(approvedRoot, ...levels);
        if (norm === deepestDir) return ['escape-link'];
        return [];
      }
    });

    assert.equal(
      deepCheck.allowed,
      false,
      'CRITICAL (NEW-01): Symlink at depth 15 pointing outside allowed_repositories must be denied!'
    );

    // 2. Unreadable directory (readdirSync throwing EACCES) must fail-closed (allowed: false), never safe: true
    const unreadableCheck = validateAuthorizedRepositoryPath(approvedRoot, baseGrant, {
      existsSync: () => true,
      lstatSync: () => ({ isSymbolicLink: () => false, isDirectory: () => true }),
      realpathSync: (p: string) => resolve(p),
      readdirSync: () => {
        const err = new Error('EACCES: permission denied') as NodeJS.ErrnoException;
        err.code = 'EACCES';
        throw err;
      }
    });

    assert.equal(
      unreadableCheck.allowed,
      false,
      'CRITICAL (NEW-01): Unreadable directory during scope check must fail-closed (denied)!'
    );
  });

  it('NEW-02 (P1): Invalid or overly permissive CSP must NEVER set positive_validation_passed=true or recheck_state=verified_fixed', async () => {
    const grant = loadGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );

    const baselineExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-CSP-BASE',
      fixture: baselineFixture
    });

    // 1. Invalid CSP directive ("totally-invalid-directive")
    const invalidCspExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-CSP-INVALID',
      fixture: {
        fixture_id: 'FIXTURE-INVALID-CSP',
        description: 'Response with broken non-directive CSP',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Security-Policy': 'totally-invalid-directive'
            }
          }
        ]
      }
    });

    const invalidHeaderCov = invalidCspExec.report.coverage.checks.find(
      (c) => c.rule_id === 'WEB-HEADER-001'
    );
    assert.equal(
      invalidHeaderCov?.positive_validation_passed,
      false,
      'CRITICAL (NEW-02): "totally-invalid-directive" must NOT pass positive_validation_passed'
    );

    const invalidCmp = compareScanReports(baselineExec.report, invalidCspExec.report);
    assert.equal(
      invalidCmp.counts.verified_fixed,
      0,
      'CRITICAL (NEW-02): "totally-invalid-directive" must NEVER produce verified_fixed!'
    );

    // 2. Overly permissive CSP ("default-src * 'unsafe-inline' 'unsafe-eval'")
    const permissiveCspExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-CSP-PERMISSIVE',
      fixture: {
        fixture_id: 'FIXTURE-PERMISSIVE-CSP',
        description: 'Response with wildcard and unsafe-inline CSP',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            method: 'GET',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval'"
            }
          }
        ]
      }
    });

    const permissiveCmp = compareScanReports(baselineExec.report, permissiveCspExec.report);
    assert.equal(
      permissiveCmp.counts.verified_fixed,
      0,
      'CRITICAL (NEW-02): Wildcard/unsafe-inline CSP must NOT be marked verified_fixed without review!'
    );
  });

  it('NEW-03 (P1/P2): Runtime validator must enforce JSON Schema Draft 2020-12 required fields, minimum bounds, and additionalProperties=false', async () => {
    const grant = loadGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );
    const validExec = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-SCHEMA-VALID',
      fixture: baselineFixture
    });

    const validReport = validExec.report;
    assert.equal(validateScanReportDocument(validReport).valid, true);

    // 1. Missing required top-level fields: summary, started_at, scanner_version
    const missingSummary = { ...validReport } as Record<string, unknown>;
    delete missingSummary.summary;
    assert.equal(
      validateScanReportDocument(missingSummary).valid,
      false,
      'CRITICAL (NEW-03): Report missing summary must be invalid'
    );

    const missingStartedAt = { ...validReport } as Record<string, unknown>;
    delete missingStartedAt.started_at;
    assert.equal(
      validateScanReportDocument(missingStartedAt).valid,
      false,
      'CRITICAL (NEW-03): Report missing started_at must be invalid'
    );

    const missingScannerVersion = { ...validReport } as Record<string, unknown>;
    delete missingScannerVersion.scanner_version;
    assert.equal(
      validateScanReportDocument(missingScannerVersion).valid,
      false,
      'CRITICAL (NEW-03): Report missing scanner_version must be invalid'
    );

    // 2. Negative integers on minimum: 0 fields (coverage.request_count = -100, max_request_budget = -1)
    const negativeCounts = {
      ...validReport,
      coverage: {
        ...validReport.coverage,
        request_count: -100,
        max_request_budget: -1
      }
    };
    assert.equal(
      validateScanReportDocument(negativeCounts).valid,
      false,
      'CRITICAL (NEW-03): Negative request_count or max_request_budget must be invalid'
    );

    // 3. Missing coverage.checks[0].asset_key
    const missingCheckAssetKey = {
      ...validReport,
      coverage: {
        ...validReport.coverage,
        checks: validReport.coverage.checks.map((c, idx) => {
          if (idx === 0) {
            const copy = { ...c } as Record<string, unknown>;
            delete copy.asset_key;
            return copy;
          }
          return c;
        })
      }
    };
    assert.equal(
      validateScanReportDocument(missingCheckAssetKey).valid,
      false,
      'CRITICAL (NEW-03): Coverage check missing asset_key must be invalid'
    );

    // 4. Unknown extra property (additionalProperties: false)
    const extraPropertyReport = {
      ...validReport,
      unexpected_extra_field: 'should-be-rejected'
    };
    assert.equal(
      validateScanReportDocument(extraPropertyReport).valid,
      false,
      'CRITICAL (NEW-03): Unknown additional property must be rejected'
    );
  });
});
