<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;

/**
 * HegoSentinel API — Sprint 9 security regression suite (B1 + architecture re-audit).
 *
 * Exercises the real controller + service + in-memory SQLite under three runtime modes:
 *   PRODUCTION (APP_ENV=production, even with HEGOSENTINEL_DEMO_MODE=1 forced),
 *   DEVELOPMENT/DEMO (APP_ENV=local, HEGOSENTINEL_DEMO_MODE=1),
 *   TEST (APP_ENV=testing, no demo flag).
 * Nothing here weakens a control to make a test pass; every assertion is a negative (deny) case
 * unless explicitly labelled as the legitimate positive control.
 */

putenv('DB_CONNECTION=sqlite');
putenv('DB_SQLITE_PATH=:memory:');
putenv('DB_DATABASE=:memory:');

$passed = 0;
$failed = 0;

function ok(bool $cond, string $label, string $detail = ''): void
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
        echo "  [PASS] {$label}\n";
    } else {
        $failed++;
        echo "  [FAIL] {$label}" . ($detail !== '' ? " — {$detail}" : '') . "\n";
    }
}

function freshController(string $appEnv, ?string $demoFlag): array
{
    putenv('APP_ENV=' . $appEnv);
    $_ENV['APP_ENV'] = $appEnv;
    if ($demoFlag === null) {
        putenv('HEGOSENTINEL_DEMO_MODE');
    } else {
        putenv('HEGOSENTINEL_DEMO_MODE=' . $demoFlag);
    }
    $pdo = new PDO('sqlite::memory:', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    DatabaseManager::resetConnection($pdo, 'sqlite');
    $service = new SecurityPlatformService($pdo);
    return [new PlatformApiController($service), $pdo];
}

/** @param array<string, string> $extra */
function call(PlatformApiController $c, string $method, string $path, ?string $token = null, array $body = [], array $extra = [], array $query = []): array
{
    $headers = $extra;
    if ($token !== null) {
        $headers['authorization'] = 'Bearer ' . $token;
    }
    return $c->handle($method, $path, $headers, $query, $body);
}

function loginToken(PlatformApiController $c, string $email, string $password = 'HegoSentinel!2026'): ?string
{
    $r = call($c, 'POST', '/api/v1/auth/login', null, ['email' => $email, 'password' => $password]);
    return $r['status'] === 200 ? (string) $r['body']['data']['token'] : null;
}

echo "========================================================================\n";
echo "HegoSentinel API — Sprint 9 Security Regression Suite (B1 + re-audit)\n";
echo "========================================================================\n";

// ---------------------------------------------------------------------------------------------
echo "\n[A] PRODUCTION mode (APP_ENV=production, demo flag forced ON must be ignored)\n";
[$prod, $prodPdo] = freshController('production', '1');
$orgCount = (int) $prodPdo->query('SELECT COUNT(*) FROM organizations')->fetchColumn();
$userCount = (int) $prodPdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
ok($orgCount === 0 && $userCount === 0, 'A1: production database is NOT seeded with demo tenants/users even when HEGOSENTINEL_DEMO_MODE=1', "orgs={$orgCount} users={$userCount}");
ok(call($prod, 'POST', '/api/v1/auth/login', null, ['email' => 'admin@hegoweb.local', 'password' => 'HegoSentinel!2026'])['status'] === 401, 'A2: known demo credentials do not exist in production');
foreach (['X-Demo-Principal', 'x-demo-principal', 'X-DEMO-PRINCIPAL'] as $hn) {
    $r = call($prod, 'GET', '/api/v1/auth/me', null, [], [$hn => 'usr-owner-01']);
    ok($r['status'] === 401, "A3: header {$hn}: usr-owner-01 never establishes identity (production)", 'status=' . $r['status']);
}
$reg = call($prod, 'POST', '/api/v1/auth/register', null, [
    'email' => 'founder@prod.example.test', 'name' => 'Prod Founder', 'password' => 'Str0ng-Prod-Pass-2026', 'organization_name' => 'Prod Org',
]);
ok($reg['status'] === 201 && ($reg['body']['data']['principal']['role'] ?? '') === 'owner', 'A4 (positive control): legitimate registration + Bearer session works in production');
$prodToken = (string) ($reg['body']['data']['token'] ?? '');
ok(call($prod, 'GET', '/api/v1/auth/me', $prodToken)['status'] === 200, 'A5 (positive control): valid Bearer token authenticates');
ok(call($prod, 'GET', '/api/v1/auth/me', 'hst_' . str_repeat('0', 48))['status'] === 401, 'A6: forged Bearer token is rejected');
ok(call($prod, 'GET', '/api/v1/auth/me', $prodToken, [], ['x-demo-principal' => 'usr-owner-01'])['status'] === 200
    && call($prod, 'GET', '/api/v1/auth/me', $prodToken, [], ['x-demo-principal' => 'usr-owner-01'])['body']['data']['email'] === 'founder@prod.example.test',
    'A7: a valid session plus X-Demo-Principal still resolves ONLY the session owner (header ignored)');

// ---------------------------------------------------------------------------------------------
echo "\n[B] TEST mode (APP_ENV=testing, no demo flag)\n";
[$testc, $testPdo] = freshController('testing', null);
ok((int) $testPdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0, 'B1: no demo flag => no seeded users');
ok(call($testc, 'GET', '/api/v1/projects', null, [], ['X-Demo-Principal' => 'usr-owner-01'])['status'] === 401, 'B2: X-Demo-Principal rejected in test mode');

// ---------------------------------------------------------------------------------------------
echo "\n[C] DEVELOPMENT/DEMO mode (APP_ENV=local, HEGOSENTINEL_DEMO_MODE=1)\n";
[$dev, $devPdo] = freshController('local', '1');
ok((int) $devPdo->query('SELECT COUNT(*) FROM organizations')->fetchColumn() >= 2, 'C0: demo mode seeds demo tenants (explicit operator opt-in)');

$protectedRoutes = [
    ['GET', '/api/v1/auth/me'], ['GET', '/api/v1/dashboard'], ['GET', '/api/v1/organization'],
    ['POST', '/api/v1/organization/members'], ['GET', '/api/v1/projects'], ['POST', '/api/v1/projects'],
    ['POST', '/api/v1/projects/proj-laravel-commerce/grants'], ['GET', '/api/v1/scans'], ['POST', '/api/v1/scans'],
    ['GET', '/api/v1/scans/SCAN-X'], ['GET', '/api/v1/scans/SCAN-X/export'], ['GET', '/api/v1/findings'],
    ['POST', '/api/v1/findings/F-1/suppress'], ['GET', '/api/v1/remediation-tasks'], ['PATCH', '/api/v1/remediation-tasks/T-1'],
    ['GET', '/api/v1/rechecks'], ['POST', '/api/v1/rechecks'], ['GET', '/api/v1/notifications'], ['POST', '/api/v1/notifications'],
    ['GET', '/api/v1/emergency-stop'], ['POST', '/api/v1/emergency-stop'], ['GET', '/api/v1/audit-logs'],
    ['GET', '/api/v1/does-not-exist'],
];
$bypass = [];
foreach ($protectedRoutes as [$m, $p]) {
    foreach ([[], ['X-Demo-Principal' => 'usr-owner-01'], ['x-demo-principal' => 'usr-beta-owner']] as $extra) {
        $r = call($dev, $m, $p, null, [], $extra);
        if ($r['status'] !== 401) {
            $bypass[] = "{$m} {$p} " . json_encode($extra) . ' => ' . $r['status'];
        }
    }
    $r = call($dev, $m, $p, 'hst_forged_token_value');
    if ($r['status'] !== 401) {
        $bypass[] = "{$m} {$p} forged-token => " . $r['status'];
    }
}
ok($bypass === [], 'C1: every one of ' . count($protectedRoutes) . ' routes returns 401 without a real session (no header/forged-token bypass, unknown route not disclosed)', implode('; ', array_slice($bypass, 0, 3)));

// Re-run of the original PoC against the fixed service
$p2 = call($dev, 'GET', '/api/v1/auth/me', null, [], ['X-Demo-Principal' => 'usr-owner-01']);
$p3 = call($dev, 'GET', '/api/v1/auth/me', null, [], ['X-Demo-Principal' => 'usr-beta-owner']);
$p4 = call($dev, 'GET', '/api/v1/projects', null, [], ['X-Demo-Principal' => 'usr-owner-01']);
$p5 = call($dev, 'GET', '/api/v1/audit-logs', null, [], ['X-Demo-Principal' => 'usr-owner-01']);
ok($p2['status'] === 401 && $p3['status'] === 401 && $p4['status'] === 401 && $p5['status'] === 401, 'C2: original PoC (owner/beta-owner impersonation, project list, audit log) now returns 401 x4');

// Tokens for each persona (real login against the demo seed)
$ownerA = loginToken($dev, 'admin@hegoweb.local');
$leadA = loginToken($dev, 'sec-lead@hegoweb.local');
$devA = loginToken($dev, 'dev@hegoweb.local');
$viewerA = loginToken($dev, 'auditor@hegoweb.local');
$ownerB = loginToken($dev, 'owner@betafintech.example.test');
ok($ownerA && $leadA && $devA && $viewerA && $ownerB, 'C3 (positive control): all five demo personas can really log in with password');

$scansA = call($dev, 'GET', '/api/v1/scans', $ownerA)['body']['data'] ?? [];
$findingsA = call($dev, 'GET', '/api/v1/findings', $ownerA)['body']['data'] ?? [];
$scanIdA = (string) ($scansA[0]['id'] ?? '');
$findingIdA = (string) ($findingsA[0]['id'] ?? '');
ok($scanIdA !== '' && $findingIdA !== '', 'C4: org A has a scan and findings to test cross-tenant access against', "scan={$scanIdA} finding={$findingIdA}");
$taskA = $devPdo->query("SELECT id FROM remediation_tasks WHERE organization_id = 'org-hegoweb-sec' LIMIT 1")->fetchColumn();
$taskIdA = $taskA ? (string) $taskA : '';

// --- Cross-tenant (BOLA/IDOR): Beta owner against every org-A object id
$cross = [
    ['GET', "/api/v1/scans/{$scanIdA}", []],
    ['GET', "/api/v1/scans/{$scanIdA}/export", ['format' => 'json']],
    ['POST', "/api/v1/findings/{$findingIdA}/suppress", ['rationale' => 'cross tenant attempt rationale']],
    ['POST', '/api/v1/projects/proj-laravel-commerce/grants', ['written_permission_ref' => 'DOC-1', 'domain_control_proof' => 'dns-1']],
    ['POST', '/api/v1/scans', ['project_id' => 'proj-laravel-commerce']],
    ['POST', '/api/v1/emergency-stop', ['project_id' => 'proj-laravel-commerce', 'reason' => 'cross tenant stop attempt']],
    ['POST', '/api/v1/rechecks', ['baseline_scan_id' => $scanIdA, 'current_scan_id' => $scanIdA]],
    ['POST', '/api/v1/notifications', ['project_id' => 'proj-laravel-commerce', 'recipient' => 'x@betafintech.example.test', 'channel' => 'email']],
];
if ($taskIdA !== '') {
    $cross[] = ['PATCH', "/api/v1/remediation-tasks/{$taskIdA}", ['status' => 'in_progress']];
}
$crossLeaks = [];
foreach ($cross as [$m, $p, $b]) {
    $r = call($dev, $m, $p, $ownerB, $m === 'GET' ? [] : $b, [], $m === 'GET' ? $b : []);
    if (!in_array($r['status'], [403, 404], true)) {
        $crossLeaks[] = "{$m} {$p} => {$r['status']}";
    }
}
ok($crossLeaks === [], 'C5: Beta tenant owner is denied (403/404) on all ' . count($cross) . ' org-A object endpoints (BOLA/IDOR)', implode('; ', $crossLeaks));

$betaView = json_encode([
    call($dev, 'GET', '/api/v1/projects', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/scans', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/findings', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/remediation-tasks', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/notifications', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/audit-logs', $ownerB)['body']['data'] ?? [],
    call($dev, 'GET', '/api/v1/organization', $ownerB)['body']['data'] ?? [],
]);
ok(!str_contains((string) $betaView, 'org-hegoweb-sec') && !str_contains((string) $betaView, 'proj-laravel-commerce') && !str_contains((string) $betaView, $scanIdA), 'C6: no org-A identifier appears in ANY list endpoint response of the Beta tenant');

// --- Same-organization RBAC / project isolation
ok(call($dev, 'POST', '/api/v1/rechecks', $viewerA, ['baseline_scan_id' => $scanIdA, 'current_scan_id' => $scanIdA])['status'] === 403, 'C7: viewer (read-only) can NOT run Re-Test (it mutates remediation state)');
ok(call($dev, 'GET', '/api/v1/audit-logs', $viewerA)['status'] === 403, 'C8: viewer can NOT read the organization audit trail');
ok(call($dev, 'GET', '/api/v1/audit-logs', $devA)['status'] === 403, 'C9: developer can NOT read the organization audit trail');
ok(call($dev, 'GET', '/api/v1/audit-logs', $leadA)['status'] === 200 && call($dev, 'GET', '/api/v1/audit-logs', $ownerA)['status'] === 200, 'C10 (positive control): security_lead and owner can read the audit trail');
$dash = call($dev, 'GET', '/api/v1/dashboard', $viewerA);
ok($dash['status'] === 200 && ($dash['body']['data']['recent_audit_entries'] ?? ['x']) === [], 'C11: viewer dashboard exposes no audit entries');

if ($taskIdA !== '') {
    $closeTry = call($dev, 'PATCH', "/api/v1/remediation-tasks/{$taskIdA}", $devA, ['status' => 'verified_closed']);
    ok($closeTry['status'] === 422, 'C12: developer can NOT hand-close a task as verified_closed (only a verified Re-Test may)', 'status=' . $closeTry['status']);
    $ownerClose = call($dev, 'PATCH', "/api/v1/remediation-tasks/{$taskIdA}", $ownerA, ['status' => 'verified_closed']);
    ok($ownerClose['status'] === 422, 'C13: not even the owner can hand-close a task as verified_closed');
}

$viewerNotifs = call($dev, 'GET', '/api/v1/notifications', $viewerA)['body']['data'] ?? [];
$allowedForViewer = ['proj-laravel-commerce', 'proj-demo-sandbox'];
$leakNotif = array_filter((array) $viewerNotifs, static fn ($n) => !in_array($n['project_id'] ?? '', $allowedForViewer, true));
ok($leakNotif === [], 'C14: notification/emergency-stop lists are filtered to the viewer\'s assigned projects');

// --- Re-Test cannot be used to claim a fix across projects; legitimate same-project re-test still works
$nextScan = call($dev, 'POST', '/api/v1/scans', $ownerA, ['project_id' => 'proj-nextjs-portal', 'grant_id' => 'GRANT-NEXTJS-2026-001']);
$nextScanId = (string) ($nextScan['body']['data']['id'] ?? '');
ok($nextScanId !== '' && $nextScan['status'] === 201, 'C14a: owner can scan the second project (positive control)', 'status=' . $nextScan['status']);
$crossProjectRecheck = call($dev, 'POST', '/api/v1/rechecks', $ownerA, ['baseline_scan_id' => $scanIdA, 'current_scan_id' => $nextScanId]);
ok($crossProjectRecheck['status'] === 422, 'C14b: Re-Test between scans of DIFFERENT projects is rejected (no cross-project verified_fixed)', 'status=' . $crossProjectRecheck['status']);
$sameProjectRecheck = call($dev, 'POST', '/api/v1/rechecks', $devA, ['baseline_scan_id' => $scanIdA, 'current_scan_id' => $scanIdA]);
ok($sameProjectRecheck['status'] === 201, 'C14c (positive control): developer can run a same-project Re-Test', 'status=' . $sameProjectRecheck['status']);
$devToUnassigned = call($dev, 'POST', '/api/v1/rechecks', $devA, ['baseline_scan_id' => $nextScanId, 'current_scan_id' => $nextScanId]);
ok($devToUnassigned['status'] === 201, 'C14d (positive control): developer assigned to proj-nextjs-portal can re-test it');
$viewerNext = call($dev, 'GET', "/api/v1/scans/{$nextScanId}", $viewerA);
ok($viewerNext['status'] === 403, 'C14e: viewer not assigned to proj-nextjs-portal cannot read its scan (project-level isolation)', 'status=' . $viewerNext['status']);

// --- Registration takeover (anonymous caller tries to join/own an existing tenant)
$takeover = call($dev, 'POST', '/api/v1/auth/register', null, [
    'email' => 'attacker@evil.example.test', 'name' => 'Mallory', 'password' => 'Attacker-Pass-2026!',
    'organization_id' => 'org-hegoweb-sec', 'role' => 'owner', 'allowed_project_ids' => ['proj-laravel-commerce'],
]);
$tp = $takeover['body']['data']['principal'] ?? [];
ok($takeover['status'] === 201 && ($tp['organization_id'] ?? '') !== 'org-hegoweb-sec', 'C15: register ignores client organization_id — attacker gets a NEW org, not org-hegoweb-sec', json_encode($tp));
$atkTok = (string) ($takeover['body']['data']['token'] ?? '');
$atkProjects = call($dev, 'GET', '/api/v1/projects', $atkTok)['body']['data'] ?? [];
ok($atkProjects === [] && call($dev, 'GET', "/api/v1/scans/{$scanIdA}", $atkTok)['status'] === 403, 'C16: self-registered attacker sees no org-A project and is denied org-A scans');
$mem = (int) $devPdo->query("SELECT COUNT(*) FROM organization_members WHERE organization_id = 'org-hegoweb-sec' AND user_id = '" . ($tp['user_id'] ?? 'none') . "'")->fetchColumn();
ok($mem === 0, 'C17: no membership row was created in org-hegoweb-sec for the attacker');

// --- Team management hardening
$noPw = call($dev, 'POST', '/api/v1/organization/members', $ownerA, ['email' => 'nopw@hegoweb.local', 'name' => 'No Pw', 'role' => 'viewer']);
ok($noPw['status'] === 422, 'C18: inviting a NEW member without an explicit initial password is rejected (no built-in default password)', 'status=' . $noPw['status']);
$userCreated = (int) $devPdo->query("SELECT COUNT(*) FROM users WHERE email = 'nopw@hegoweb.local'")->fetchColumn();
ok($userCreated === 0, 'C19: no default-password account was created');
$foreignProj = call($dev, 'POST', '/api/v1/organization/members', $ownerA, [
    'email' => 'scoped@hegoweb.local', 'name' => 'Scoped', 'role' => 'developer', 'password' => 'Scoped-Initial-Pass-2026', 'allowed_project_ids' => ['proj-beta-core'],
]);
ok($foreignProj['status'] === 422, 'C20: allowed_project_ids cannot reference another organization\'s project');

// --- Path traversal / repository confinement
$before = (int) $devPdo->query('SELECT COUNT(*) FROM projects')->fetchColumn();
$traversals = ['../../../', '/etc', 'C:\\Windows', '..\\..\\apps', 'examples/../apps/api', 'examples/synthetic-targets/laravel-app/../../../../apps/api', "examples/\0evil", '//server/share'];
$allRejected = true;
$detail = [];
foreach ($traversals as $t) {
    $r = call($dev, 'POST', '/api/v1/projects', $ownerA, ['name' => 'Traversal Probe', 'repository_path' => $t]);
    if ($r['status'] !== 422) {
        $allRejected = false;
        $detail[] = json_encode($t) . '=>' . $r['status'];
    }
}
ok($allRejected, 'C21: createProject rejects 8 path-traversal / absolute / UNC / NUL repository_path payloads with 422', implode('; ', $detail));
ok((int) $devPdo->query('SELECT COUNT(*) FROM projects')->fetchColumn() === $before, 'C22: rejected traversal attempts left NO orphan project rows');

$scanTrav = call($dev, 'POST', '/api/v1/scans', $ownerA, ['project_id' => 'proj-laravel-commerce', 'grant_id' => 'GRANT-LARAVEL-2026-001', 'repository_path' => 'apps/api']);
ok(in_array($scanTrav['status'], [403, 422], true), 'C23: scanning a repo path outside the workspace (apps/api) is rejected', 'status=' . $scanTrav['status']);
$scanCross = call($dev, 'POST', '/api/v1/scans', $ownerA, ['project_id' => 'proj-laravel-commerce', 'grant_id' => 'GRANT-LARAVEL-2026-001', 'repository_path' => 'examples/synthetic-targets/nextjs-app']);
ok($scanCross['status'] === 403, 'C24: a project cannot scan another project\'s repository (not a registered asset of this project)', 'status=' . $scanCross['status']);
$scanRoot = call($dev, 'POST', '/api/v1/scans', $ownerA, ['project_id' => 'proj-laravel-commerce', 'grant_id' => 'GRANT-LARAVEL-2026-001', 'repository_path' => 'examples']);
ok($scanRoot['status'] === 403, 'C25: a request cannot WIDEN scope to the parent workspace directory', 'status=' . $scanRoot['status']);
ok((int) $devPdo->query("SELECT COUNT(*) FROM scan_queue_jobs WHERE status = 'running'")->fetchColumn() === 0, 'C26: denied path attempts created no dangling queue jobs');

// --- Emergency stop cannot be bypassed by omitting a client flag
$stop = call($dev, 'POST', '/api/v1/emergency-stop', $ownerA, ['project_id' => 'proj-laravel-commerce', 'reason' => 'Regression: project-wide stop must hold new scans']);
ok($stop['status'] === 201, 'C27 (positive control): owner triggers project-wide emergency stop');
$afterStop = call($dev, 'POST', '/api/v1/scans', $ownerA, ['project_id' => 'proj-laravel-commerce', 'grant_id' => 'GRANT-LARAVEL-2026-001']);
ok($afterStop['status'] === 403 && ($afterStop['body']['data']['status'] ?? '') === 'denied', 'C28: a new scan right after a project-wide stop is DENIED without any client flag (honor_project_stop opt-in removed)', 'status=' . $afterStop['status']);
ok(call($dev, 'POST', '/api/v1/emergency-stop', $ownerA, ['project_id' => 'proj-does-not-exist', 'reason' => 'phantom project stop'])['status'] === 404, 'C29: emergency stop for a non-existent project id is rejected (404)');
ok(call($dev, 'POST', '/api/v1/emergency-stop', $devA, ['project_id' => 'proj-laravel-commerce', 'reason' => 'dev tries stop'])['status'] === 403, 'C30: developer still cannot trigger emergency stop');

// --- Brute-force throttling
[$thr] = freshController('local', '1');
$statuses = [];
for ($i = 0; $i < 5; $i++) {
    $statuses[] = call($thr, 'POST', '/api/v1/auth/login', null, ['email' => 'admin@hegoweb.local', 'password' => 'wrong-' . $i], ['x-hegosentinel-remote-addr' => '203.0.113.9'])['status'];
}
$sixth = call($thr, 'POST', '/api/v1/auth/login', null, ['email' => 'admin@hegoweb.local', 'password' => 'HegoSentinel!2026']);
ok($statuses === [401, 401, 401, 401, 401] && $sixth['status'] === 429, 'C31: 5 failed logins lock the account for 15 min — even the CORRECT password is then refused with 429', json_encode($statuses) . ' / ' . $sixth['status']);
ok(call($thr, 'POST', '/api/v1/auth/login', null, ['email' => 'owner@betafintech.example.test', 'password' => 'HegoSentinel!2026'])['status'] === 200, 'C32 (positive control): throttling is per-account; other accounts are unaffected');

// --- Error hygiene
$errBody = json_encode(call($dev, 'GET', '/api/v1/scans/SCAN-NOPE', $ownerA)['body']);
ok(!str_contains((string) $errBody, 'Stack trace') && !str_contains((string) $errBody, '.php'), 'C33: error responses do not leak stack traces or file paths');

echo "\n========================================================================\n";
echo sprintf("Sprint 9 Security Regression Summary: %d passed, %d failed\n", $passed, $failed);
echo "========================================================================\n";
exit($failed > 0 ? 1 : 0);
