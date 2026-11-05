import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';
import {
  authorizeTenantResourceAccess,
  classifyIpAddress,
  EmergencyStopRegistry,
  parseAndValidateCanonicalUrl,
  resolveAndPinDestination,
  validateExternalNotificationRequest,
  validateRedirectTransition,
  validateScopeAuthorizationGrant,
  verifyConnectedSocketPeer,
  verifyRemoteEgressSandboxGate
} from '../../packages/policy-engine/src/index.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import {
  redactSensitiveText,
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport
} from '../../packages/report-engine/src/index.ts';
import { executeScan } from '../../packages/scanner-core/src/index.ts';
import { runSemgrepAdapter } from '../../integrations/semgrep/src/index.ts';
import { runTrivyAdapter } from '../../integrations/trivy/src/index.ts';

function loadBaseGrant(): ScopeAuthorizationGrant {
  const raw = readFileSync(
    resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'),
    'utf8'
  );
  return JSON.parse(raw) as ScopeAuthorizationGrant;
}

describe('Release-Blocking Security Acceptance Matrix (SEC-001 .. SEC-014)', () => {
  it('SEC-001: Missing, expired, outside-window, wildcard, or domain-proof-only permission emits denied with zero requests', async () => {
    const base = loadBaseGrant();

    // 1. Expired grant
    const expiredGrant: ScopeAuthorizationGrant = {
      ...base,
      expires_at: '2026-01-02T00:00:00.000Z'
    };
    const expiredRes = await executeScan({
      grant: expiredGrant,
      mode: 'offline-fixture',
      now: new Date('2026-11-04T20:00:00.000Z')
    });
    assert.equal(expiredRes.policyDecision.allowed, false);
    assert.equal(expiredRes.policyDecision.reason, 'scope_expired');
    assert.equal(expiredRes.report.coverage.global_status, 'denied');
    assert.equal(expiredRes.report.coverage.request_count, 0);

    // 2. Domain control proof without written_permission_ref (HSR-02)
    const noWrittenPermGrant: ScopeAuthorizationGrant = {
      ...base,
      domain_control_proof: 'dns-txt-verified',
      written_permission_ref: ''
    };
    const noWrittenRes = validateScopeAuthorizationGrant(noWrittenPermGrant);
    assert.equal(noWrittenRes.allowed, false);
    assert.equal(noWrittenRes.reason, 'missing_written_permission');

    // 3. Wildcard hostname
    const wildcardGrant: ScopeAuthorizationGrant = {
      ...base,
      targets: [{ scheme: 'https', hostname: '*.example.test', port: 443, path_prefix: '/' }]
    };
    const wildcardRes = validateScopeAuthorizationGrant(wildcardGrant);
    assert.equal(wildcardRes.allowed, false);
    assert.equal(wildcardRes.reason, 'wildcard_forbidden');

    // 4. Outside approved time window
    const windowRes = validateScopeAuthorizationGrant(
      base,
      new Date('2025-01-01T00:00:00.000Z')
    );
    assert.equal(windowRes.allowed, false);
    assert.equal(windowRes.reason, 'outside_window');
  });

  it('SEC-002: Private, loopback, link-local, cloud metadata, and IPv6/mapped-IPv6 destinations are denied', async () => {
    const disallowedIps = [
      '127.0.0.1',
      '127.0.1.1',
      '0.0.0.0',
      '10.0.0.1',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '100.100.100.200',
      '224.0.0.1',
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd00:ec2::254',
      '::ffff:127.0.0.1',
      '::ffff:169.254.169.254',
      '::ffff:10.0.0.1',
      '2001:db8::1',
      '64:ff9b::127.0.0.1'
    ];

    for (const ip of disallowedIps) {
      const check = classifyIpAddress(ip);
      assert.equal(check.allowed, false, `Expected IP ${ip} to be blocked, got ${check.category}`);
    }

    const globalCheck = classifyIpAddress('93.184.216.34');
    assert.equal(globalCheck.allowed, true);

    // URL with integer/octal/hex IP literal or embedded credentials
    const grant: ScopeAuthorizationGrant = {
      ...loadBaseGrant(),
      profile: 'safe-web'
    };
    assert.equal(
      parseAndValidateCanonicalUrl('https://2130706433/', grant).decision.allowed,
      false
    );
    assert.equal(
      parseAndValidateCanonicalUrl('https://0177.0.0.1/', grant).decision.allowed,
      false
    );
    assert.equal(
      parseAndValidateCanonicalUrl('https://user:pass@demo.example.test/', grant).decision.reason,
      'embedded_credentials_forbidden'
    );

    // DNS resolver returning cloud metadata IPv6 or RFC1918 IPv4
    const validTarget = parseAndValidateCanonicalUrl('https://demo.example.test/', grant).target!;
    const badDnsResult = await resolveAndPinDestination(validTarget, {
      resolve4: async () => ['93.184.216.34'],
      resolve6: async () => ['::ffff:169.254.169.254']
    });
    assert.equal(badDnsResult.decision.allowed, false);
    assert.equal(badDnsResult.decision.reason, 'blocked_destination');
  });

  it('SEC-003: Redirect to out-of-scope destination or HTTP downgrade is logged and not followed', async () => {
    const grant: ScopeAuthorizationGrant = {
      ...loadBaseGrant(),
      allowed_checks: ['WEB-REDIRECT-001']
    };
    const fromTarget = parseAndValidateCanonicalUrl('https://demo.example.test/login', grant).target!;
    const safeResolver = {
      resolve4: async () => ['93.184.216.34'],
      resolve6: async () => []
    };

    // Out-of-scope host redirect
    const externalRedirect = await validateRedirectTransition({
      fromUrl: fromTarget,
      locationHeader: 'https://evil.example.org/phish',
      redirectDepth: 0,
      grant,
      resolver: safeResolver
    });
    assert.equal(externalRedirect.decision.allowed, false);
    assert.equal(externalRedirect.decision.reason, 'out_of_scope_redirect');

    // HTTPS -> HTTP downgrade redirect
    const downgradeRedirect = await validateRedirectTransition({
      fromUrl: fromTarget,
      locationHeader: 'http://demo.example.test/insecure',
      redirectDepth: 0,
      grant,
      resolver: safeResolver
    });
    assert.equal(downgradeRedirect.decision.allowed, false);
    assert.equal(downgradeRedirect.decision.reason, 'protocol_downgrade');

    // Scanner records observation without making follow-up request
    const scanRes = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: {
        fixture_id: 'REDIRECT-FIXTURE',
        description: 'Redirect test',
        endpoints: [
          {
            url: 'https://demo.example.test/go',
            status_code: 302,
            headers: {
              Location: 'https://169.254.169.254/latest/meta-data/'
            }
          }
        ]
      }
    });
    assert.equal(scanRes.report.coverage.request_count, 1);
    assert.equal(scanRes.report.findings.length, 1);
    assert.equal(scanRes.report.findings[0].rule_id, 'WEB-REDIRECT-001');
  });

  it('SEC-004: DNS rebind between validation and socket connect is rejected', async () => {
    const grant = loadBaseGrant();
    const target = parseAndValidateCanonicalUrl('https://demo.example.test/', grant).target!;
    const pinnedRes = await resolveAndPinDestination(target, {
      resolve4: async () => ['93.184.216.34'],
      resolve6: async () => []
    });
    assert.equal(pinnedRes.decision.allowed, true);

    // Simulate socket connecting to rebound metadata IP 169.254.169.254
    const peerCheck = verifyConnectedSocketPeer(pinnedRes.pinned!, '169.254.169.254');
    assert.equal(peerCheck.allowed, false);
    assert.equal(peerCheck.reason, 'dns_rebind_detected');

    // Full scan runner blocks on simulated rebind with 0 completed requests
    const scanRes = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: {
        fixture_id: 'REBIND-FIXTURE',
        description: 'DNS rebind simulation',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            status_code: 200,
            headers: {},
            simulated_socket_peer_ip: '127.0.0.1'
          }
        ]
      }
    });
    assert.equal(scanRes.policyDecision.allowed, false);
    assert.equal(scanRes.policyDecision.reason, 'dns_rebind_detected');
    assert.equal(scanRes.report.coverage.global_status, 'denied');
    assert.equal(scanRes.report.coverage.request_count, 0);
  });

  it('SEC-005: Remote scan mode fails closed unless network-layer egress isolation is verified and internal plane is unreachable', async () => {
    const grant: ScopeAuthorizationGrant = {
      ...loadBaseGrant(),
      profile: 'safe-web'
    };

    // 1. Default remote scan without egress attestation -> denied
    const unverifiedRemote = await executeScan({
      grant,
      mode: 'restricted-remote'
    });
    assert.equal(unverifiedRemote.policyDecision.allowed, false);
    assert.equal(unverifiedRemote.policyDecision.reason, 'remote_egress_isolation_unverified');
    assert.equal(unverifiedRemote.report.coverage.request_count, 0);

    // 2. Worker with reachable internal plane -> denied with egress_escape_detected
    const escapeCheck = verifyRemoteEgressSandboxGate({
      sandboxActive: true,
      allowlistedDestinationsOnly: true,
      internalPlaneReachable: true,
      ambientProxyDisabled: true
    });
    assert.equal(escapeCheck.allowed, false);
    assert.equal(escapeCheck.reason, 'egress_escape_detected');
  });

  it('SEC-006: Repository scan blocks forbidden executables (npm/composer/sh) and out-of-scope paths', async () => {
    const grant: ScopeAuthorizationGrant = {
      ...loadBaseGrant(),
      allowed_checks: ['CODE-001', 'DEP-001']
    };

    // Attempt to invoke npm or shell instead of allowlisted semgrep binary
    const forbiddenBinRes = await runSemgrepAdapter({
      grant,
      repositoryPath: './examples/safe-demo/sample-repo',
      execCommandOverride: 'npm'
    });
    assert.equal(forbiddenBinRes.coverage.status, 'denied');
    assert.match(forbiddenBinRes.coverage.reason ?? '', /SEC-006/);

    // Attempt path traversal outside allowed_repositories
    const traversalRes = await runTrivyAdapter({
      grant,
      repositoryPath: './examples/safe-demo/../../'
    });
    assert.equal(traversalRes.coverage.status, 'denied');
  });

  it('SEC-007: Secrets in headers, cookies, URLs, and tool output never appear in reports', async () => {
    const plantedJwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3JldCJ9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
    const plantedApiKey = 'sk-live_SUPERSECRETKEY1234567890ABCDEF';
    const plantedAwsKey = 'AKIAIOSFODNN7EXAMPLE';
    const rawDirty = `Authorization: Bearer ${plantedJwt}\nSet-Cookie: sid=my_super_secret_cookie_val; Path=/\nURL: https://demo.example.test/?token=secret_query_tok_999&api_key=${plantedApiKey}&aws=${plantedAwsKey}&email=alice@secret.example.com`;

    const redacted = redactSensitiveText(rawDirty);
    assert.ok(!redacted.includes(plantedJwt), 'JWT leaked');
    assert.ok(!redacted.includes('my_super_secret_cookie_val'), 'Cookie value leaked');
    assert.ok(!redacted.includes('secret_query_tok_999'), 'Query token leaked');
    assert.ok(!redacted.includes(plantedApiKey), 'API key leaked');
    assert.ok(!redacted.includes(plantedAwsKey), 'AWS key leaked');
    assert.ok(!redacted.includes('alice@secret.example.com'), 'Email leaked');

    // Run full scan with planted secrets in Set-Cookie and verify JSON, MD, and HTML outputs
    const grant = loadBaseGrant();
    const scanRes = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: {
        fixture_id: 'SECRET-LEAK-FIXTURE',
        description: 'Secret leak check',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html',
              'Set-Cookie': [`hegosentinel_session=${plantedJwt}; Path=/`]
            }
          }
        ]
      }
    });

    const jsonOut = renderJsonReport(scanRes.report);
    const mdOut = renderMarkdownReport(scanRes.report);
    const htmlOut = renderHtmlReport(scanRes.report);

    assert.ok(!jsonOut.includes(plantedJwt));
    assert.ok(!mdOut.includes(plantedJwt));
    assert.ok(!htmlOut.includes(plantedJwt));
  });

  it('SEC-008: Missing tool or failed check produces skipped/completed_with_gaps, never complete/clean', async () => {
    const grant: ScopeAuthorizationGrant = {
      ...loadBaseGrant(),
      allowed_checks: ['WEB-HEADER-001', 'WEB-TLS-001']
    };

    // Endpoint without TLS metadata causes WEB-TLS-001 to be skipped
    const res = await executeScan({
      grant,
      mode: 'offline-fixture',
      fixture: {
        fixture_id: 'PARTIAL-FIXTURE',
        description: 'Partial coverage fixture',
        endpoints: [
          {
            url: 'https://demo.example.test/',
            status_code: 200,
            headers: {
              'Content-Type': 'text/html',
              'Content-Security-Policy': "default-src 'self'"
            }
          }
        ]
      }
    });

    assert.equal(res.report.findings.length, 0);
    assert.equal(res.report.coverage.global_status, 'completed_with_gaps');
    assert.notEqual(res.report.coverage.global_status, 'complete');
  });

  it('SEC-009 & SEC-010: Re-test marks mismatched scope/rule-version as not_comparable and enforces scoped false_positive suppression', async () => {
    const grant = loadBaseGrant();
    const baselineFixture = JSON.parse(
      readFileSync(resolve(process.cwd(), 'examples/safe-demo/fixture-baseline.json'), 'utf8')
    );

    const run1 = await executeScan({
      grant,
      mode: 'offline-fixture',
      scanId: 'SCAN-1',
      fixture: baselineFixture,
      now: new Date('2026-11-04T20:00:00.000Z')
    });

    // Different project_id -> must be not_comparable, never fixed
    const runDiffProject = {
      ...run1.report,
      scan_id: 'SCAN-2',
      project_id: 'proj-other-tenant',
      findings: []
    };
    const incomp = compareScanReports(run1.report, runDiffProject);
    assert.equal(incomp.comparable, false);
    assert.equal(incomp.counts.not_comparable, 2);
    assert.equal(incomp.counts.verified_fixed, 0);
    assert.equal(incomp.counts.no_longer_observed, 0);

    // Valid scoped false_positive suppression (SEC-010)
    const targetFp = run1.report.findings[0].fingerprint;
    const suppressedComparison = compareScanReports(run1.report, run1.report, {
      now: new Date('2026-11-04T20:10:00.000Z'),
      suppressions: [
        {
          fingerprint: targetFp,
          organization_id: grant.organization_id,
          project_id: grant.project_id,
          scope_version: grant.scope_version,
          reviewer: 'sec-lead@example.test',
          reason: 'Handled by edge CDN policy on staging',
          expires_at: '2027-01-01T00:00:00.000Z'
        }
      ]
    });
    assert.equal(suppressedComparison.counts.false_positive, 1);
    assert.equal(suppressedComparison.counts.persistent, 1);
  });

  it('SEC-011: Multi-tenant boundary and RBAC isolation denies cross-tenant/cross-project reads and unprivileged actions', () => {
    const tenantADev = {
      user_id: 'usr-dev-a1',
      organization_id: 'org-tenant-a',
      project_ids: ['proj-alpha'],
      role: 'developer' as const
    };
    const tenantAOwner = {
      user_id: 'usr-owner-a1',
      organization_id: 'org-tenant-a',
      project_ids: ['proj-alpha'],
      role: 'owner' as const
    };
    const tenantBReport = {
      resource_type: 'report' as const,
      resource_id: 'SCAN-TENANT-B-999',
      organization_id: 'org-tenant-b',
      project_id: 'proj-beta'
    };
    const tenantAOtherProjectReport = {
      resource_type: 'report' as const,
      resource_id: 'SCAN-TENANT-A-OTHER',
      organization_id: 'org-tenant-a',
      project_id: 'proj-unassigned'
    };
    const tenantAReport = {
      resource_type: 'report' as const,
      resource_id: 'SCAN-TENANT-A-001',
      organization_id: 'org-tenant-a',
      project_id: 'proj-alpha'
    };

    // 1. Cross-tenant read denied
    const crossTenant = authorizeTenantResourceAccess({
      principal: tenantAOwner,
      resource: tenantBReport,
      action: 'read_report'
    });
    assert.equal(crossTenant.allowed, false);
    assert.equal(crossTenant.reason, 'unauthorized');

    // 2. Cross-project read within same org denied
    const crossProject = authorizeTenantResourceAccess({
      principal: tenantADev,
      resource: tenantAOtherProjectReport,
      action: 'read_report'
    });
    assert.equal(crossProject.allowed, false);

    // 3. Developer cannot approve scope grants or suppress false positives
    const devApproveGrant = authorizeTenantResourceAccess({
      principal: tenantADev,
      resource: tenantAReport,
      action: 'approve_scope_grant'
    });
    assert.equal(devApproveGrant.allowed, false);

    const devSuppressFp = authorizeTenantResourceAccess({
      principal: tenantADev,
      resource: tenantAReport,
      action: 'suppress_false_positive'
    });
    assert.equal(devSuppressFp.allowed, false);

    // 4. Owner within matching org & project succeeds
    const ownerApprove = authorizeTenantResourceAccess({
      principal: tenantAOwner,
      resource: tenantAReport,
      action: 'approve_scope_grant'
    });
    assert.equal(ownerApprove.allowed, true);
  });

  it('SEC-012: Emergency stop kill-switch aborts active runs, revokes stop tokens, and blocks post-cancel execution', () => {
    const stopRegistry = new EmergencyStopRegistry();
    const ctrl = new AbortController();
    stopRegistry.registerRunController('RUN-KILL-001', ctrl);

    assert.equal(
      stopRegistry.checkExecutionAllowed({
        runId: 'RUN-KILL-001',
        emergencyStopTokenId: 'ESTOP-TOKEN-001',
        signal: ctrl.signal
      }).allowed,
      true
    );

    // Cancel run -> immediately aborts registered AbortController and blocks future requests
    stopRegistry.cancelRun({
      runId: 'RUN-KILL-001',
      cancelledBy: 'sec-ops@example.test',
      reason: 'Emergency stop triggered by target operator'
    });
    assert.equal(ctrl.signal.aborted, true);
    assert.equal(
      stopRegistry.checkExecutionAllowed({
        runId: 'RUN-KILL-001',
        emergencyStopTokenId: 'ESTOP-TOKEN-001'
      }).allowed,
      false
    );

    // Revoking emergency_stop_token_id blocks any run using that token
    stopRegistry.revokeEmergencyStopToken({
      tokenId: 'ESTOP-TOKEN-002',
      revokedBy: 'owner@example.test',
      reason: 'Maintenance window closed early'
    });
    assert.equal(
      stopRegistry.checkExecutionAllowed({
        runId: 'RUN-KILL-002',
        emergencyStopTokenId: 'ESTOP-TOKEN-002'
      }).allowed,
      false
    );
  });

  it('SEC-013: External notifications are disabled by default and block public sinks, unverified recipients, non-owners, and unredacted secrets', () => {
    const ownerPrincipal = {
      user_id: 'usr-owner-1',
      organization_id: 'org-hegoweb-demo',
      project_ids: ['proj-safe-demo'],
      role: 'owner' as const
    };
    const devPrincipal = {
      user_id: 'usr-dev-1',
      organization_id: 'org-hegoweb-demo',
      project_ids: ['proj-safe-demo'],
      role: 'developer' as const
    };

    const validBase = {
      channel: 'github_issue' as const,
      organization_id: 'org-hegoweb-demo',
      project_id: 'proj-safe-demo',
      enabled_by_owner: true,
      human_approval_id: 'APPROVAL-2026-0001',
      approved_by_principal: ownerPrincipal,
      recipient_or_repo: 'hegoweb/private-sec-tracker',
      verified_recipient_allowlist: ['hegoweb/private-sec-tracker', 'security-team@example.test'],
      sink_visibility: 'private' as const,
      sanitized_summary_only: true,
      payload_text: 'Sanitized summary: 1 medium header observation [REDACTED].'
    };

    // 1. Disabled by default rejected
    assert.equal(
      validateExternalNotificationRequest({ ...validBase, enabled_by_owner: false }).allowed,
      false
    );

    // 2. Public repository / public issue tracker rejected
    assert.equal(
      validateExternalNotificationRequest({ ...validBase, sink_visibility: 'public' }).allowed,
      false
    );

    // 3. Unverified external recipient rejected
    assert.equal(
      validateExternalNotificationRequest({
        ...validBase,
        recipient_or_repo: 'attacker@evil.example.com'
      }).allowed,
      false
    );

    // 4. Developer (non-owner) approval rejected
    assert.equal(
      validateExternalNotificationRequest({
        ...validBase,
        approved_by_principal: devPrincipal
      }).allowed,
      false
    );

    // 5. Unredacted JWT / GitHub token in notification payload rejected
    assert.equal(
      validateExternalNotificationRequest({
        ...validBase,
        payload_text: 'Leak: ghp_1234567890abcdefghijklmnopqrstuv'
      }).allowed,
      false
    );

    // 6. Owner-approved, private-sink, allowlisted, sanitized summary succeeds
    assert.equal(validateExternalNotificationRequest(validBase).allowed, true);
  });
});

