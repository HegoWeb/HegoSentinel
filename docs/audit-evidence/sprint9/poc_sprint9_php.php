<?php
// Sprint 9 PoC battery — run against ANY checkout root: php poc_sprint9_php.php <repoRoot>
// HEAD copy (git archive) = "before", working tree = "after". Prints, per check, whether the weakness is EXPOSED.
declare(strict_types=1);

$root = $argv[1] ?? null;
if (!$root || !is_file($root . '/apps/api/bootstrap/autoload.php')) {
    fwrite(STDERR, "usage: php poc_sprint9_php.php <repoRoot>\n");
    exit(2);
}
chdir($root);
putenv('DB_CONNECTION=sqlite'); putenv('DB_SQLITE_PATH=:memory:'); putenv('DB_DATABASE=:memory:');
putenv('APP_ENV=local'); putenv('HEGOSENTINEL_DEMO_MODE=1'); // demo data needed by the PoC itself (ignored by the pre-fix code)
$_ENV['APP_ENV'] = 'local';
require_once $root . '/apps/api/bootstrap/autoload.php';

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
DatabaseManager::resetConnection($pdo, 'sqlite');
$c = new PlatformApiController(new SecurityPlatformService($pdo));

function call(PlatformApiController $c, string $m, string $p, ?string $tok = null, array $body = [], array $hdr = [], array $query = []): array
{
    if ($tok !== null) { $hdr['authorization'] = 'Bearer ' . $tok; }
    return $c->handle($m, $p, $hdr, $query, $body);
}
function tok(PlatformApiController $c, string $email, string $pw = 'HegoSentinel!2026'): ?string
{
    $r = call($c, 'POST', '/api/v1/auth/login', null, ['email' => $email, 'password' => $pw]);
    return $r['status'] === 200 ? (string) $r['body']['data']['token'] : null;
}

$res = [];
$owner = tok($c, 'admin@hegoweb.local'); $viewer = tok($c, 'auditor@hegoweb.local'); $dev = tok($c, 'dev@hegoweb.local'); $beta = tok($c, 'owner@betafintech.example.test');
$scans = call($c, 'GET', '/api/v1/scans', $owner)['body']['data'] ?? [];
$scanId = (string) ($scans[0]['id'] ?? '');

// 1. header impersonation
$r = call($c, 'GET', '/api/v1/auth/me', null, [], ['X-Demo-Principal' => 'usr-owner-01']);
$res['S9-01 X-Demo-Principal impersonation (HTTP 200 = exposed)'] = ['exposed' => $r['status'] === 200, 'status' => $r['status']];

// 2. anonymous registration joining a foreign organization as owner
$r = call($c, 'POST', '/api/v1/auth/register', null, ['email' => 'mallory@evil.example.test', 'name' => 'Mallory', 'password' => 'Attacker-Pass-2026!', 'organization_id' => 'org-hegoweb-sec', 'role' => 'owner']);
$mt = (string) ($r['body']['data']['token'] ?? '');
$joined = $mt !== '' ? (call($c, 'GET', '/api/v1/projects', $mt)['body']['data'] ?? []) : [];
$res['S9-02 register joins foreign org as owner (sees victim projects)'] = ['exposed' => count($joined) > 0, 'victim_projects_visible' => count($joined), 'org' => $r['body']['data']['principal']['organization_id'] ?? null, 'role' => $r['body']['data']['principal']['role'] ?? null];

// 3. invited member gets a built-in default password
$r = call($c, 'POST', '/api/v1/organization/members', $owner, ['email' => 'invitee@hegoweb.local', 'name' => 'Invitee', 'role' => 'viewer']);
$res['S9-03 invited user has built-in default password'] = ['exposed' => $r['status'] === 200 && tok($c, 'invitee@hegoweb.local') !== null, 'invite_status' => $r['status']];

// 4. brute force: 8 wrong logins then the right password still works
for ($i = 0; $i < 8; $i++) { call($c, 'POST', '/api/v1/auth/login', null, ['email' => 'dev@hegoweb.local', 'password' => 'wrong' . $i]); }
$res['S9-04 no brute-force lockout'] = ['exposed' => tok($c, 'dev@hegoweb.local') !== null];

// 5/6/7. viewer privileges
$r = call($c, 'POST', '/api/v1/rechecks', $viewer, ['baseline_scan_id' => $scanId, 'current_scan_id' => $scanId]);
$res['S9-05 read-only viewer can run Re-Test (mutates tasks)'] = ['exposed' => $r['status'] === 201, 'status' => $r['status']];
$r = call($c, 'GET', '/api/v1/audit-logs', $viewer);
$res['S9-06 viewer can read org audit trail'] = ['exposed' => $r['status'] === 200, 'status' => $r['status']];

// 8. manual verified_closed
$taskId = (string) ($pdo->query("SELECT id FROM remediation_tasks LIMIT 1")->fetchColumn() ?: '');
$r = $taskId !== '' ? call($c, 'PATCH', "/api/v1/remediation-tasks/{$taskId}", $dev, ['status' => 'verified_closed']) : ['status' => -1];
$res['S9-07 developer hand-closes a task as verified_closed'] = ['exposed' => $r['status'] === 200, 'status' => $r['status']];

// 9. cross-tenant denial leaks foreign identifiers into the caller's audit trail
call($c, 'GET', "/api/v1/scans/{$scanId}", $beta);
$aud = json_encode(call($c, 'GET', '/api/v1/audit-logs', $beta)['body']['data'] ?? []);
$res['S9-08 cross-tenant denial writes victim org/project ids into attacker audit log'] = ['exposed' => str_contains((string) $aud, 'org-hegoweb-sec')];

// 10. repository path traversal at project creation / scan time
$r = call($c, 'POST', '/api/v1/projects', $owner, ['name' => 'Traversal Probe', 'repository_path' => '../../../']);
$res['S9-09 createProject accepts ../ repository_path'] = ['exposed' => $r['status'] === 201, 'status' => $r['status']];
$r = call($c, 'POST', '/api/v1/scans', $owner, ['project_id' => 'proj-laravel-commerce', 'grant_id' => 'GRANT-LARAVEL-2026-001', 'repository_path' => 'schemas']);
$res['S9-10 scan of an arbitrary workspace directory (not a project asset)'] = ['exposed' => $r['status'] === 201, 'status' => $r['status']];

// 11. emergency stop is only honoured if the CLIENT asks for it
call($c, 'POST', '/api/v1/emergency-stop', $owner, ['project_id' => 'proj-nextjs-portal', 'reason' => 'PoC project-wide stop']);
$r = call($c, 'POST', '/api/v1/scans', $owner, ['project_id' => 'proj-nextjs-portal', 'grant_id' => 'GRANT-NEXTJS-2026-001']);
$res['S9-11 new scan runs right after a project-wide emergency stop'] = ['exposed' => $r['status'] === 201, 'status' => $r['status']];

$exposed = array_keys(array_filter($res, static fn ($x) => $x['exposed']));
echo json_encode(['root_label' => basename($root), 'checks' => $res, 'exposed_count' => count($exposed), 'total' => count($res)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

