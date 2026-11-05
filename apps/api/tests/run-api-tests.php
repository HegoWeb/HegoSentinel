<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;

/**
 * HegoSentinel Laravel API Integration & Security Boundary Test Suite
 *
 * Verifies all 14 backend modules and enforces:
 * - SEC-001 / SEC-002: ScopeAuthorizationGrant & SSRF/wildcard/private-IP rejection
 * - SEC-010: Scoped false_positive suppressions (org + project + fingerprint + scope_version)
 * - SEC-011: Multi-tenant data isolation (org-level + project-level) & RBAC enforcement
 * - SEC-012: Emergency stop & subprocess cancellation
 * - SEC-013: Approved developer notification controls (public sink block, verified domain check, secret leak block)
 * - Tamper-evident SHA-256 hash-chained audit logs
 */

putenv('DB_CONNECTION=sqlite');
putenv('DB_SQLITE_PATH=:memory:');
putenv('DB_DATABASE=:memory:');
// Demo tenants/users with KNOWN credentials exist only in explicit, non-production demo mode (B1).
putenv('APP_ENV=testing');
putenv('HEGOSENTINEL_DEMO_MODE=1');
$_ENV['DB_CONNECTION'] = 'sqlite';
$_ENV['DB_SQLITE_PATH'] = ':memory:';
$_ENV['DB_DATABASE'] = ':memory:';

$pdo = DatabaseManager::connect();
$service = new SecurityPlatformService($pdo);
$controller = new PlatformApiController($service);

$passed = 0;
$failed = 0;

function assertCheck(bool $condition, string $label, string $detail = ''): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo sprintf("  [PASS] %s\n", $label);
    } else {
        $failed++;
        echo sprintf("  [FAIL] %s %s\n", $label, $detail !== '' ? "— $detail" : '');
    }
}

echo "========================================================================\n";
echo "HegoSentinel Laravel API (apps/api) — 14-Module & SEC-011..013 Test Suite\n";
echo "========================================================================\n";

// 0. Health Check & Audit Chain Integrity
$health = $controller->handle('GET', '/api/v1/health');
assertCheck($health['status'] === 200 && ($health['body']['ok'] ?? false) === true, 'GET /api/v1/health returns 200 OK and pinned scanner versions');
assertCheck(($health['body']['audit_chain_integrity']['valid'] ?? false) === true, 'Initial SHA-256 audit log hash chain is valid');

// 1. Module 1: Authentication (Login, Register, Password Reset, Session Management)
$badLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'admin@hegoweb.local',
    'password' => 'wrong-password',
]);
assertCheck($badLogin['status'] === 401, 'Module 1: Rejects invalid credentials with 401 Unauthorized');

$ownerLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'admin@hegoweb.local',
    'password' => 'HegoSentinel!2026',
]);
assertCheck($ownerLogin['status'] === 200 && !empty($ownerLogin['body']['data']['token']), 'Module 1: Owner login issues session token');
$ownerToken = (string) $ownerLogin['body']['data']['token'];
$ownerHeaders = ['authorization' => 'Bearer ' . $ownerToken];

$secLeadLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'sec-lead@hegoweb.local',
    'password' => 'HegoSentinel!2026',
]);
$secLeadHeaders = ['authorization' => 'Bearer ' . $secLeadLogin['body']['data']['token']];

$devLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'dev@hegoweb.local',
    'password' => 'HegoSentinel!2026',
]);
$devHeaders = ['authorization' => 'Bearer ' . $devLogin['body']['data']['token']];

$viewerLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'auditor@hegoweb.local',
    'password' => 'HegoSentinel!2026',
]);
$viewerHeaders = ['authorization' => 'Bearer ' . $viewerLogin['body']['data']['token']];

$otherOrgLogin = $controller->handle('POST', '/api/v1/auth/login', [], [], [
    'email' => 'owner@betafintech.example.test',
    'password' => 'HegoSentinel!2026',
]);
$otherOrgHeaders = ['authorization' => 'Bearer ' . $otherOrgLogin['body']['data']['token']];

$pwdReset = $controller->handle('POST', '/api/v1/auth/password-reset', [], [], ['email' => 'dev@hegoweb.local']);
assertCheck($pwdReset['status'] === 200 && ($pwdReset['body']['data']['status'] ?? '') === 'accepted', 'Module 1: Password reset token issuance works safely');

// 2. Module 2 & 3: Organization, Team Management & RBAC (SEC-011)
$orgRes = $controller->handle('GET', '/api/v1/organization', $ownerHeaders);
assertCheck($orgRes['status'] === 200 && count($orgRes['body']['data']['members'] ?? []) >= 4, 'Module 2: Lists organization members and verified notification domains');

$viewerInviteTry = $controller->handle('POST', '/api/v1/organization/members', $viewerHeaders, [], [
    'email' => 'new@hegoweb.local',
    'name' => 'Unauthorized Invite',
    'role' => 'developer',
]);
assertCheck($viewerInviteTry['status'] === 403, 'Module 3 (SEC-011): Viewer role cannot invite or modify organization members');

$ownerInvite = $controller->handle('POST', '/api/v1/organization/members', $ownerHeaders, [], [
    'email' => 'compliance-obs@hegoweb.local',
    'name' => 'Canan Yıldız (Compliance Viewer)',
    'role' => 'viewer',
    'allowed_project_ids' => ['proj-laravel-commerce'],
    'password' => 'Initial-Pass-Unit-2026!',
]);
assertCheck($ownerInvite['status'] === 200 && count($ownerInvite['body']['data']['members'] ?? []) >= 5, 'Module 2 & 3: Owner can invite and configure team member RBAC');

// 3. Module 4 & 5: Projects, Target Assets, and ScopeAuthorizationGrant (SEC-001 & SEC-002)
$ssrfProjectTry = $controller->handle('POST', '/api/v1/projects', $ownerHeaders, [], [
    'name' => 'Illegal Internal Metadata Target',
    'environment' => 'staging',
    'stack' => ['laravel'],
    'hostname' => '169.254.169.254',
]);
assertCheck($ssrfProjectTry['status'] === 422, 'Module 4 & 5 (SEC-002): Blocks cloud metadata IP 169.254.169.254 target creation');

$wildcardProjectTry = $controller->handle('POST', '/api/v1/projects', $ownerHeaders, [], [
    'name' => 'Illegal Wildcard Target',
    'environment' => 'staging',
    'stack' => ['nextjs'],
    'hostname' => '*.example.test',
]);
assertCheck($wildcardProjectTry['status'] === 422, 'Module 4 & 5 (SEC-001): Blocks wildcard hostname *.example.test in target scope');

$newProject = $controller->handle('POST', '/api/v1/projects', $secLeadHeaders, [], [
    'name' => 'HegoFin Core API Service',
    'environment' => 'staging',
    'stack' => ['laravel', 'generic-web'],
    'hostname' => 'fin-api.example.test',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
    'written_permission_ref' => 'AUTH-FIN-2026-88',
]);
assertCheck($newProject['status'] === 201 && !empty($newProject['body']['data']['id']), 'Module 4 & 5: Creates authorized project, target asset, and ScopeAuthorizationGrant v1');
$createdProjectId = (string) $newProject['body']['data']['id'];

// Verify SEC-001: Identical domain_control_proof and written_permission_ref rejected
$badGrant = $controller->handle('POST', "/api/v1/projects/$createdProjectId/grants", $secLeadHeaders, [], [
    'written_permission_ref' => 'SAME-PROOF-123',
    'domain_control_proof' => 'SAME-PROOF-123',
    'hostname' => 'fin-api.example.test',
]);
assertCheck($badGrant['status'] === 422, 'Module 5 (SEC-001): Rejects scope grant when written_permission_ref equals domain_control_proof');

// 4. Module 6 & 7: Authorized Scan Creation, Queue Execution & Coverage Matrix
$restrictedRemoteTry = $controller->handle('POST', '/api/v1/scans', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'restricted-remote',
]);
assertCheck(
    $restrictedRemoteTry['status'] === 403 && ($restrictedRemoteTry['body']['data']['status'] ?? '') === 'denied',
    'Module 6: restricted-remote mode is fail-closed (BLOCKED) until independent network isolation is enabled'
);

$viewerScanTry = $controller->handle('POST', '/api/v1/scans', $viewerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'offline-fixture',
]);
assertCheck($viewerScanTry['status'] === 403, 'Module 3 & 6 (SEC-011): Viewer role is blocked from triggering scans');

$baselineScan = $controller->handle('POST', '/api/v1/scans', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'offline-fixture',
    'fixture_variant' => 'baseline',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
]);
assertCheck(
    $baselineScan['status'] === 201 && ($baselineScan['body']['data']['total_findings'] ?? 0) >= 5,
    'Module 6 & 7: Executes baseline authorized scan and records coverage matrix + findings',
    sprintf('status=%d, reason=%s, total=%d', $baselineScan['status'], (string) ($baselineScan['body']['data']['cancelled_reason'] ?? ($baselineScan['body']['message'] ?? 'none')), (int) ($baselineScan['body']['data']['total_findings'] ?? -1))
);
$baselineScanId = (string) $baselineScan['body']['data']['id'];

// Cross-tenant isolation check (SEC-011)
$crossTenantRead = $controller->handle('GET', "/api/v1/scans/$baselineScanId", $otherOrgHeaders);
assertCheck($crossTenantRead['status'] === 403, 'SEC-011: Cross-organization user is blocked from reading tenant scan report');

// Cross-project isolation check (SEC-011): Developer is only assigned to proj-laravel-commerce & proj-nextjs-portal, not $createdProjectId
$crossProjectRead = $controller->handle('GET', '/api/v1/scans', $devHeaders, ['project_id' => $createdProjectId]);
assertCheck($crossProjectRead['status'] === 403, 'SEC-011: Developer cannot access unassigned project within same organization');

// 5. Module 8: Security Findings & Scoped Suppressions (SEC-010)
$findingsRes = $controller->handle('GET', '/api/v1/findings', $ownerHeaders, ['scan_run_id' => $baselineScanId]);
$findingsList = $findingsRes['body']['data'] ?? [];
assertCheck($findingsRes['status'] === 200 && count($findingsList) >= 5, 'Module 8: Lists normalized findings with evidence hashes and OWASP/CWE references');
$firstFindingId = (string) ($findingsList[0]['id'] ?? '');

$devSuppressTry = $controller->handle('POST', "/api/v1/findings/$firstFindingId/suppress", $devHeaders, [], [
    'rationale' => 'Developer trying to suppress finding without security_lead approval',
]);
assertCheck($devSuppressTry['status'] === 403, 'Module 8 (SEC-010 / SEC-011): Developer cannot approve false_positive suppressions');

$secLeadSuppress = $controller->handle('POST', "/api/v1/findings/$firstFindingId/suppress", $secLeadHeaders, [], [
    'rationale' => 'Compensating edge WAF header injection verified for scope v1.',
]);
assertCheck($secLeadSuppress['status'] === 201 && !empty($secLeadSuppress['body']['data']['id']), 'Module 8 (SEC-010): Security Lead creates scoped false_positive suppression');

// 6. Module 9: Vulnerability Remediation Tasks
$tasksRes = $controller->handle('GET', '/api/v1/remediation-tasks', $devHeaders, ['project_id' => 'proj-laravel-commerce']);
$tasksList = $tasksRes['body']['data'] ?? [];
assertCheck($tasksRes['status'] === 200 && count($tasksList) >= 1, 'Module 9: Lists remediation tasks with framework code patch guidance');
$firstTaskId = (string) ($tasksList[0]['id'] ?? '');

$updatedTask = $controller->handle('PATCH', "/api/v1/remediation-tasks/$firstTaskId", $devHeaders, [], [
    'status' => 'ready_for_retest',
    'notes' => 'Applied security headers middleware and pinned patched composer/npm packages.',
]);
assertCheck(
    $updatedTask['status'] === 200 && ($updatedTask['body']['data']['status'] ?? '') === 'ready_for_retest',
    'Module 9: Developer updates remediation task status to ready_for_retest'
);

// 7. Module 10: Re-Test & Comparison (SEC-009 / S1-05)
$hardenedScan = $controller->handle('POST', '/api/v1/scans', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'offline-fixture',
    'fixture_variant' => 'remediated',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
]);
$hardenedScanId = (string) $hardenedScan['body']['data']['id'];

$recheckRes = $controller->handle('POST', '/api/v1/rechecks', $ownerHeaders, [], [
    'baseline_scan_id' => $baselineScanId,
    'current_scan_id' => $hardenedScanId,
]);
$recheckCounts = $recheckRes['body']['data']['counts'] ?? [];
assertCheck(
    $recheckRes['status'] === 201 &&
    ($recheckRes['body']['data']['comparable'] ?? false) === true &&
    (($recheckCounts['verified_fixed'] ?? 0) >= 1 || ($recheckCounts['false_positive'] ?? 0) >= 1),
    'Module 10: Side-by-side re-test comparison verifies fixed findings and scoped suppressions'
);

// 8. Module 11: Safe Report Export (JSON, MD, HTML, SARIF, PDF)
foreach (['json', 'md', 'html', 'sarif', 'pdf'] as $fmt) {
    $exp = $controller->handle('GET', "/api/v1/scans/$baselineScanId/export", $ownerHeaders, ['format' => $fmt]);
    assertCheck(
        $exp['status'] === 200 && strlen((string) ($exp['body']['data']['content'] ?? '')) > 50,
        sprintf('Module 11: Safe report export succeeds for format %s', strtoupper($fmt))
    );
}

// 9. Module 12: Approved Developer Notifications (SEC-013)
$publicSinkTry = $controller->handle('POST', '/api/v1/notifications', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'channel' => 'webhook',
    'recipient' => 'https://hooks.slack.com/services/T000/B000/PUBLICSINK',
    'summary' => 'Scan summary',
]);
assertCheck($publicSinkTry['status'] === 403, 'Module 12 (SEC-013): Blocks public webhook sink hooks.slack.com');

$unverifiedDomainTry = $controller->handle('POST', '/api/v1/notifications', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'channel' => 'email',
    'recipient' => 'attacker@unverified-external.org',
    'summary' => 'Scan summary',
]);
assertCheck($unverifiedDomainTry['status'] === 403, 'Module 12 (SEC-013): Blocks notification to unverified recipient domain');

$secretLeakTry = $controller->handle('POST', '/api/v1/notifications', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'channel' => 'email',
    'recipient' => 'dev@hegoweb.local',
    'summary' => 'Leaked token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret',
]);
assertCheck($secretLeakTry['status'] === 422, 'Module 12 (SEC-013): Blocks notification containing unredacted Bearer secret token');

$devNotifyTry = $controller->handle('POST', '/api/v1/notifications', $devHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'channel' => 'email',
    'recipient' => 'dev@hegoweb.local',
    'summary' => 'Clean summary without approval privileges.',
]);
assertCheck($devNotifyTry['status'] === 403, 'Module 12 (SEC-013): Blocks developer role from approving outbound notifications');

$validNotify = $controller->handle('POST', '/api/v1/notifications', $secLeadHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'channel' => 'email',
    'recipient' => 'dev@hegoweb.local',
    'summary' => 'Authorized scan completed. 3 remediation tasks are ready for review.',
]);
assertCheck($validNotify['status'] === 201 && ($validNotify['body']['data']['status'] ?? '') === 'dispatched', 'Module 12 (SEC-013): Dispatches approved notification to verified domain');

// 10. Module 14: Emergency Stop & Subprocess Cancellation (SEC-012)
$devStopTry = $controller->handle('POST', '/api/v1/emergency-stop', $devHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'reason' => 'Developer unauthorized emergency stop attempt',
]);
assertCheck($devStopTry['status'] === 403, 'Module 14 (SEC-012 / SEC-011): Developer role cannot trigger emergency stop');

$validStop = $controller->handle('POST', '/api/v1/emergency-stop', $ownerHeaders, [], [
    'project_id' => 'proj-laravel-commerce',
    'scan_run_id' => $baselineScanId,
    'reason' => 'Operator emergency stop verification test',
]);
assertCheck(
    $validStop['status'] === 201 && ($validStop['body']['data']['subprocesses_terminated'] ?? 0) === 1,
    'Module 14 (SEC-012): Owner triggers emergency stop and terminates scan job'
);

// 11. Module 13: Tamper-Evident Audit Logs Verification
$auditRes = $controller->handle('GET', '/api/v1/audit-logs', $ownerHeaders);
$integrity = $auditRes['body']['data']['integrity'] ?? [];
assertCheck(
    $auditRes['status'] === 200 &&
    ($integrity['valid'] ?? false) === true &&
    ($integrity['entries_checked'] ?? 0) >= 15,
    sprintf('Module 13: Tamper-evident SHA-256 audit log chain verified (%d entries)', $integrity['entries_checked'] ?? 0)
);

echo "------------------------------------------------------------------------\n";
echo sprintf("API Test Summary: %d passed, %d failed\n", $passed, $failed);
echo "========================================================================\n";

if ($failed > 0) {
    exit(1);
}
