<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';

use App\Jobs\DispatchApprovedNotificationJob;
use App\Jobs\ExecuteAuthorizedScanJob;
use App\Jobs\ExecuteRecheckComparisonJob;
use App\Models\Finding;
use App\Models\Organization;
use App\Models\Project;
use App\Models\RemediationTask;
use App\Models\ScanQueueJob;
use App\Models\ScanRun;
use App\Models\User;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use App\Support\TenantRlsContext;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * HegoSentinel Sprint 10 — S10-01 & S10-03 Verification Suite
 *
 * Verifies:
 * 1. Real Laravel 11 (`Illuminate\Foundation\Application`) HTTP Kernel request pipeline (`bootstrap/app.php`)
 * 2. Hardened middleware (`SecurityHeadersAndCorsMiddleware`) stripping `X-Demo-Principal` & enforcing security headers
 * 3. Eloquent ORM models & `BelongsToOrganization` Global Scope (fail-closed when unbound, strict tenant isolation)
 * 4. Laravel `Gate` & `Policy` RBAC and project-scope enforcement (`OrganizationPolicy`, `ProjectPolicy`, `ScanRunPolicy`, `RemediationTaskPolicy`)
 * 5. `S10-03` Queue Plane (`hegosentinel-scans`, `hegosentinel-rechecks`, `hegosentinel-notifications`), idempotency deduplication,
 *    worker heartbeat tracking, `< 2000ms` (`< 2s`) Emergency Stop cancellation SLA, and blocked restart of cancelled scans.
 */

putenv('APP_ENV=testing');
putenv('HEGOSENTINEL_DEMO_MODE=1');
putenv('DB_CONNECTION=sqlite');
putenv('DB_SQLITE_PATH=:memory:');
putenv('DB_DATABASE=:memory:');
$_ENV['APP_ENV'] = 'testing';
$_ENV['HEGOSENTINEL_DEMO_MODE'] = '1';
$_ENV['DB_CONNECTION'] = 'sqlite';
$_ENV['DB_SQLITE_PATH'] = ':memory:';
$_ENV['DB_DATABASE'] = ':memory:';

$passed = 0;
$failed = 0;

function check(bool $cond, string $label, string $detail = ''): void
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

echo "========================================================================\n";
echo "HegoSentinel Sprint 10 — Laravel 11 Kernel, Eloquent, Policy & Queue Suite\n";
echo "========================================================================\n";

// 1. Boot Real Laravel 11 Application Kernel
/** @var Application $app */
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(\Illuminate\Contracts\Http\Kernel::class)->bootstrap();
check(
    str_starts_with(Application::VERSION, '11.'),
    'S10-01.1: Real Laravel 11 framework booted (' . Application::VERSION . ')'
);

// Initialize shared in-memory PDO and bind it to Laravel's SQLite Eloquent connection
$pdo = DatabaseManager::connect();
$service = $app->make(SecurityPlatformService::class);
$app['db']->connection('sqlite')->setPdo($pdo)->setReadPdo($pdo);

// 2. Dispatch real HTTP request through Laravel 11 HTTP Kernel (`$app->handle(...)`)
$healthReq = Request::create('/api/v1/health', 'GET', [], [], [], [
    'HTTP_ORIGIN' => 'http://localhost:3000',
    'HTTP_X_DEMO_PRINCIPAL' => 'usr-owner-01',
]);
$healthRes = $app->handle($healthReq);
$healthBody = json_decode((string) $healthRes->getContent(), true) ?: [];

check(
    $healthRes->getStatusCode() === 200
    && ($healthBody['ok'] ?? false) === true
    && str_starts_with((string) ($healthBody['framework'] ?? ''), 'Laravel 11.'),
    'S10-01.2: GET /api/v1/health routed through real Laravel 11 HTTP Kernel',
    json_encode($healthBody)
);
check(
    $healthRes->headers->get('X-Content-Type-Options') === 'nosniff'
    && $healthRes->headers->get('X-Frame-Options') === 'DENY'
    && $healthRes->headers->get('Access-Control-Allow-Origin') === 'http://localhost:3000',
    'S10-01.3: SecurityHeadersAndCorsMiddleware attaches nosniff, DENY, and allowlisted CORS headers'
);

// Verify X-Demo-Principal is stripped and rejected through the real Laravel 11 HTTP Kernel
$unauthReq = Request::create('/api/v1/auth/me', 'GET', [], [], [], [
    'HTTP_X_DEMO_PRINCIPAL' => 'usr-owner-01',
]);
$unauthRes = $app->handle($unauthReq);
check(
    $unauthRes->getStatusCode() === 401,
    'S10-01.4 (B1): X-Demo-Principal header rejected with 401 through real Laravel 11 HTTP Kernel'
);

// Login via real Laravel 11 HTTP Kernel
$loginReq = Request::create(
    '/api/v1/auth/login',
    'POST',
    [],
    [],
    [],
    ['CONTENT_TYPE' => 'application/json'],
    (string) json_encode(['email' => 'admin@hegoweb.local', 'password' => 'HegoSentinel!2026'])
);
$loginRes = $app->handle($loginReq);
$loginData = json_decode((string) $loginRes->getContent(), true) ?: [];
$ownerToken = (string) ($loginData['data']['token'] ?? '');
check(
    $loginRes->getStatusCode() === 200 && str_starts_with($ownerToken, 'hst_'),
    'S10-01.5: POST /api/v1/auth/login issues session token via Laravel 11 HTTP Kernel'
);

$meReq = Request::create('/api/v1/auth/me', 'GET', [], [], [], [
    'HTTP_AUTHORIZATION' => 'Bearer ' . $ownerToken,
]);
$meRes = $app->handle($meReq);
$meBody = json_decode((string) $meRes->getContent(), true) ?: [];
check(
    $meRes->getStatusCode() === 200 && ($meBody['data']['user_id'] ?? '') === 'usr-owner-01',
    'S10-01.6: GET /api/v1/auth/me authenticates Bearer token via Laravel 11 HTTP Kernel'
);

// 3. Eloquent ORM & BelongsToOrganization Global Scope Verification
TenantRlsContext::clear();
$unboundCount = Project::query()->count();
check(
    $unboundCount === 0,
    'S10-01.7: Eloquent BelongsToOrganization Global Scope fails closed (0 rows) when TenantRlsContext is unbound'
);

$createUnboundRejected = false;
try {
    Project::query()->create([
        'id' => 'proj-unbound-test',
        'organization_id' => 'org-hegoweb-sec',
        'name' => 'Unbound',
        'slug' => 'unbound',
        'environment' => 'staging',
        'stack_json' => '["laravel"]',
        'description' => 'Should fail',
        'is_demo' => 0,
        'created_by_user_id' => 'usr-owner-01',
        'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
    ]);
} catch (\RuntimeException $e) {
    $createUnboundRejected = $e->getCode() === 403;
}
check($createUnboundRejected, 'S10-01.8: Eloquent model creation is rejected (403) when TenantRlsContext is unbound');

$ownerPrincipal = $service->getPrincipalById('usr-owner-01', 'org-hegoweb-sec');
TenantRlsContext::set('org-hegoweb-sec', $ownerPrincipal);

$orgAProjects = Project::query()->pluck('id')->all();
check(
    in_array('proj-laravel-commerce', $orgAProjects, true)
    && !in_array('proj-beta-core', $orgAProjects, true),
    'S10-01.9: Eloquent Project::query() returns only org-hegoweb-sec projects and excludes org-beta-isolated',
    json_encode($orgAProjects)
);

$crossTenantEloquentCreateRejected = false;
try {
    Project::query()->create([
        'id' => 'proj-spoofed-org',
        'organization_id' => 'org-beta-isolated',
        'name' => 'Spoofed Org',
        'slug' => 'spoofed-org',
        'environment' => 'staging',
        'stack_json' => '["laravel"]',
        'description' => 'Should fail',
        'is_demo' => 0,
        'created_by_user_id' => 'usr-owner-01',
        'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
    ]);
} catch (\RuntimeException $e) {
    $crossTenantEloquentCreateRejected = $e->getCode() === 403;
}
check($crossTenantEloquentCreateRejected, 'S10-01.10: Eloquent creating guard rejects cross-tenant organization_id spoofing (403)');

// 4. Laravel Gate & Policy RBAC Verification
$ownerUser = User::query()->find('usr-owner-01');
$orgModel = Organization::query()->find('org-hegoweb-sec');
$projModel = Project::query()->find('proj-laravel-commerce');
$scanModel = ScanRun::query()->first();
$taskModel = RemediationTask::query()->first();

check(
    $ownerUser !== null && $orgModel !== null && $projModel !== null
    && Gate::forUser($ownerUser)->allows('manageTeam', $orgModel)
    && Gate::forUser($ownerUser)->allows('approveScope', $projModel)
    && Gate::forUser($ownerUser)->allows('triggerScan', $projModel),
    'S10-01.11: Laravel Policies allow Owner to manageTeam, approveScope, and triggerScan on own tenant'
);

$viewerPrincipal = $service->getPrincipalById('usr-viewer-01', 'org-hegoweb-sec');
$viewerUser = User::query()->find('usr-viewer-01');
TenantRlsContext::set('org-hegoweb-sec', $viewerPrincipal);

check(
    $viewerUser !== null
    && Gate::forUser($viewerUser)->allows('view', $projModel)
    && !Gate::forUser($viewerUser)->allows('triggerScan', $projModel)
    && !Gate::forUser($viewerUser)->allows('approveScope', $projModel)
    && !Gate::forUser($viewerUser)->allows('manageTeam', $orgModel)
    && ($scanModel === null || !Gate::forUser($viewerUser)->allows('export', $scanModel))
    && ($taskModel === null || !Gate::forUser($viewerUser)->allows('update', $taskModel)),
    'S10-01.12: Laravel Policies allow Viewer read-only view and deny triggerScan, approveScope, manageTeam, export, and task update'
);

TenantRlsContext::clear();

// 5. S10-03 Queue Plane, Idempotency, Heartbeat, < 2s Emergency Stop SLA, and Blocked Restart of Cancelled Scans
$scanJobObj = new ExecuteAuthorizedScanJob([], 'SCAN-TEST-QUEUE', 'offline-fixture');
$recheckJobObj = new ExecuteRecheckComparisonJob('RECHK-KEY', [], []);
$notifJobObj = new DispatchApprovedNotificationJob('NOTIF-1', 'org-hegoweb-sec', 'proj-laravel-commerce', 'email', 'dev@hegoweb.local', 'Clean');

check(
    $scanJobObj->queue === 'hegosentinel-scans'
    && $recheckJobObj->queue === 'hegosentinel-rechecks'
    && $notifJobObj->queue === 'hegosentinel-notifications',
    'S10-03.1: Queue jobs bind to hegosentinel-scans, hegosentinel-rechecks, and hegosentinel-notifications'
);

$idemKey = 'idem-sprint10-' . bin2hex(random_bytes(4));
$idemReq1 = Request::create(
    '/api/v1/scans',
    'POST',
    [],
    [],
    [],
    ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer ' . $ownerToken],
    (string) json_encode([
        'project_id' => 'proj-laravel-commerce',
        'grant_id' => 'GRANT-LARAVEL-2026-001',
        'mode' => 'offline-fixture',
        'fixture_variant' => 'baseline',
        'idempotency_key' => $idemKey,
    ])
);
$idemRes1 = json_decode((string) $app->handle($idemReq1)->getContent(), true) ?: [];
$idemRes2 = json_decode((string) $app->handle($idemReq1)->getContent(), true) ?: [];
$idemScanId1 = (string) ($idemRes1['data']['id'] ?? '');
$idemScanId2 = (string) ($idemRes2['data']['id'] ?? '');

check(
    $idemScanId1 !== '' && $idemScanId1 === $idemScanId2,
    'S10-03.2: Duplicate scan request with identical idempotency_key is deduplicated cleanly (' . $idemScanId1 . ')'
);

$queueJobMeta = $idemRes1['data']['queue_job'] ?? [];
check(
    !empty($queueJobMeta['heartbeat_at'])
    && !empty($queueJobMeta['supervisor_container_id'])
    && ($queueJobMeta['queue_name'] ?? '') === 'hegosentinel-scans',
    'S10-03.3: ScanQueueJob records worker heartbeat_at, supervisor_container_id, and queue_name=hegosentinel-scans'
);

// Trigger Emergency Stop on the scan and measure < 2000ms (< 2s) SLA
$stopReq = Request::create(
    '/api/v1/emergency-stop',
    'POST',
    [],
    [],
    [],
    ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer ' . $ownerToken],
    (string) json_encode([
        'project_id' => 'proj-laravel-commerce',
        'scan_run_id' => $idemScanId1,
        'reason' => 'S10-03 SLA verification emergency stop',
    ])
);
$stopRes = json_decode((string) $app->handle($stopReq)->getContent(), true) ?: [];
$latencyMs = (int) ($stopRes['data']['cancellation_latency_ms'] ?? 99999);
$withinSla = (bool) ($stopRes['data']['within_sla_2000ms'] ?? false);

check(
    $withinSla && $latencyMs < 2000,
    sprintf('S10-03.4: Emergency Stop cancels scan and terminates worker within < 2s SLA (measured=%dms)', $latencyMs)
);

// Verify cancelled scan cannot be restarted (via restart_scan_run_id OR via its cancelled idempotency_key)
$restartReq = Request::create(
    '/api/v1/scans',
    'POST',
    [],
    [],
    [],
    ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer ' . $ownerToken],
    (string) json_encode([
        'project_id' => 'proj-laravel-commerce',
        'grant_id' => 'GRANT-LARAVEL-2026-001',
        'restart_scan_run_id' => $idemScanId1,
    ])
);
$restartRes = $app->handle($restartReq);

$idemReplayAfterCancel = $app->handle($idemReq1);
check(
    $restartRes->getStatusCode() === 409 && $idemReplayAfterCancel->getStatusCode() === 409,
    'S10-03.5: Cancelled scan cannot be restarted via restart_scan_run_id or replayed idempotency_key (409 Conflict)'
);

// Queue & Horizon telemetry endpoint
$qStatusReq = Request::create('/api/v1/queues/status', 'GET', [], [], [], [
    'HTTP_AUTHORIZATION' => 'Bearer ' . $ownerToken,
]);
$qStatusRes = json_decode((string) $app->handle($qStatusReq)->getContent(), true) ?: [];
check(
    ($qStatusRes['ok'] ?? false) === true
    && ($qStatusRes['data']['queues'] ?? []) === ['hegosentinel-scans', 'hegosentinel-rechecks', 'hegosentinel-notifications'],
    'S10-03.6: GET /api/v1/queues/status returns Horizon supervisor and 3-queue telemetry'
);

echo "------------------------------------------------------------------------\n";
echo sprintf("Laravel 11 Kernel & Queue Summary: %d passed, %d failed\n", $passed, $failed);
echo "========================================================================\n";

exit($failed > 0 ? 1 : 0);
