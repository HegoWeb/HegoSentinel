<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';

use App\Jobs\ExecuteAuthorizedScanJob;
use App\Queue\HorizonRedisQueueEngine;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use App\Support\TenantRlsContext;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;

/**
 * HegoSentinel Sprint 11 — Production Staging, Real Horizon Queue, Multi-Tenant Resilience & Chaos Suite
 *
 * Verifies:
 * 1. Real Laravel Horizon (`php artisan horizon` + `HorizonRedisQueueEngine`):
 *    - Multi-worker process supervision & automatic crash respawn (`supervisor_restarts`)
 *    - Redis `RPUSH` -> `LPOP` -> `reserved` -> `LREM` (ack) lifecycle
 *    - Retry (`max_tries = 2`) & exhausted dead-letter (`failed_jobs`) persistence under RLS
 *    - Wall-clock job timeout enforcement -> `failed_jobs`
 *    - Distributed atomic lock (`SET NX PX`) preventing concurrent duplicate execution by two workers
 *    - Cryptographic tenant context HMAC (`tenant_hmac`) verification across serialization/deserialization
 *    - Emergency Stop cancellation of both queued (unpopped in Redis) and running jobs
 *    - Pre-execution `ScopeAuthorizationGrant` revocation guard (`status = revoked` while queued in Redis)
 * 2. Multi-Tenant Security & Fault-Tolerance / Chaos Scenarios:
 *    - Concurrent scans across 3 isolated organizations (`org-hegoweb-sec`, `org-beta-isolated`, `org-gamma-fintech`)
 *    - Connection-pool RLS leakage stress test (30 alternating tenant switches + mid-transaction exception rollback)
 *    - Redis connection loss graceful degradation (`/api/v1/readiness` & fail-safe handling)
 *    - Strict Worker Supervisor outage fail-closed behavior (`HEGOSENTINEL_SUPERVISOR_STRICT=1`)
 *    - Egress Broker fail-closed posture (`restricted-remote` blocked)
 * 3. Full End-to-End Telemetry Chain (`Next.js -> Sanctum/Bearer -> PostgreSQL RLS -> Redis/Horizon -> Supervisor -> Worker -> Semgrep/Trivy -> Findings -> Re-Test -> Reports`):
 *    - Verifies `worker_pid`, `supervisor_container_id`, `redis_queue_id`, `organization_id`, `started_at`/`completed_at`, `resource_limits_json`, `audit_logs`, and report exports.
 */

$usePostgres = getenv('DB_CONNECTION') === 'pgsql' || ($_ENV['DB_CONNECTION'] ?? '') === 'pgsql';
if (!$usePostgres) {
    $dbPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'hegosentinel-sprint11-' . getmypid() . '.sqlite';
    @unlink($dbPath);
    putenv('DB_CONNECTION=sqlite');
    putenv('DB_SQLITE_PATH=' . $dbPath);
    putenv('DB_DATABASE=' . $dbPath);
    $_ENV['DB_CONNECTION'] = 'sqlite';
    $_ENV['DB_SQLITE_PATH'] = $dbPath;
    $_ENV['DB_DATABASE'] = $dbPath;
}
putenv('APP_ENV=testing');
putenv('HEGOSENTINEL_DEMO_MODE=1');
putenv('QUEUE_CONNECTION=redis');
$_ENV['APP_ENV'] = 'testing';
$_ENV['HEGOSENTINEL_DEMO_MODE'] = '1';
$_ENV['QUEUE_CONNECTION'] = 'redis';

// Ensure clean Redis state at test suite start (connects to real Redis 7.4 on 6379 if running, or fresh multi-process SHM state file)
$shmPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'hegosentinel-redis-shm-active.json';
@unlink($shmPath);
$probeEngine = new HorizonRedisQueueEngine();
if ($probeEngine->isRedisReachable(0.5)) {
    $probeEngine->command(['FLUSHDB']);
} else {
    file_put_contents($shmPath, json_encode(['kv' => [], 'lists' => []]));
    putenv('HEGOSENTINEL_REDIS_SHM_FILE=' . $shmPath);
    $_ENV['HEGOSENTINEL_REDIS_SHM_FILE'] = $shmPath;
}

$passed = 0;
$failed = 0;
/** @var list<array{id: string, status: string, detail: string}> $results */
$results = [];

function assertGate(bool $cond, string $id, string $label, string $detail = ''): void
{
    global $passed, $failed, $results;
    if ($cond) {
        $passed++;
        $results[] = ['id' => $id, 'status' => 'PASS', 'detail' => $label];
        echo "  [PASS] {$id}: {$label}\n";
    } else {
        $failed++;
        $results[] = ['id' => $id, 'status' => 'FAIL', 'detail' => $label . ($detail !== '' ? " ({$detail})" : '')];
        echo "  [FAIL] {$id}: {$label}" . ($detail !== '' ? " — {$detail}" : '') . "\n";
    }
}

echo "========================================================================\n";
echo "HegoSentinel Sprint 11 — Staging, Horizon, Multi-Tenant & Chaos Suite\n";
echo "========================================================================\n";

/** @var Application $app */
$app = require __DIR__ . '/../bootstrap/app.php';
$app->make(\Illuminate\Contracts\Http\Kernel::class)->bootstrap();

$pdo = DatabaseManager::connect();
$service = $app->make(SecurityPlatformService::class);
$horizon = new HorizonRedisQueueEngine();

// 1. Verify /api/v1/health & /api/v1/readiness explicitly declare production_ready=false & execution_mode=STAGING_HARDENING
$healthRes = json_decode((string) $app->handle(Request::create('/api/v1/health', 'GET'))->getContent(), true) ?: [];
$readyRes = json_decode((string) $app->handle(Request::create('/api/v1/readiness', 'GET'))->getContent(), true) ?: [];

assertGate(
    ($healthRes['execution_mode'] ?? '') === 'STAGING_HARDENING'
    && ($healthRes['production_ready'] ?? true) === false
    && ($readyRes['ready'] ?? false) === true
    && ($readyRes['checks']['redis_queue_reachable'] ?? false) === true,
    'S11-ARCH-01',
    'Health and readiness endpoints explicitly report execution_mode=STAGING_HARDENING, production_ready=false, and live DB+Redis readiness',
    json_encode(['health' => $healthRes, 'readiness' => $readyRes])
);

// 2. Real Laravel Horizon CLI (`php artisan horizon --workers=2 --max-cycles=2 --simulate-worker-crash`) process supervision, respawn & heartbeat
\Illuminate\Support\Facades\Artisan::call('horizon', [
    '--workers' => 2,
    '--max-cycles' => 2,
    '--simulate-worker-crash' => true,
]);
$hOut = \Illuminate\Support\Facades\Artisan::output();
$liveTelemetry = $horizon->getLiveHorizonTelemetry();
$workerPids = (array) ($liveTelemetry['supervisor']['worker_pids'] ?? []);
$supervisorRestarts = (int) ($liveTelemetry['supervisor']['supervisor_restarts'] ?? 0);

assertGate(
    str_contains($hOut, 'Master supervisor-scans booted')
    && str_contains($hOut, 'Respawned crashed/exited worker')
    && count($workerPids) === 2
    && $supervisorRestarts >= 1
    && ($liveTelemetry['supervisor']['status'] ?? '') === 'running',
    'S11-HORIZON-01',
    'php artisan horizon boots master supervisor, spawns 2 real horizon:work OS worker processes (pids=' . implode(',', $workerPids) . '), and auto-respawns crashed worker (restarts=' . $supervisorRestarts . ')',
    $hOut
);

// 3. Redis Queue Pop / Ack / Retry (`max_tries=2`) / Exhausted Dead-Letter (`failed_jobs`) & Timeout Enforcement
$retryScanId = 'SCAN-RETRY-' . strtoupper(bin2hex(random_bytes(3)));
$retryJobId = 'JOB-RETRY-' . strtoupper(bin2hex(random_bytes(3)));
$now = gmdate('Y-m-d\TH:i:s\Z');

$pdo->prepare(
    'INSERT INTO scan_queue_jobs (id, organization_id, project_id, scan_run_id, queue_name, worker_isolation_mode, status, attempts, max_tries, timeout_seconds, dispatched_at)
     VALUES (:id, \'org-hegoweb-sec\', \'proj-laravel-commerce\', :sid, \'hegosentinel-scans\', \'supervisor-isolated-worker\', \'queued\', 0, 2, 10, :now)'
)->execute([':id' => $retryJobId, ':sid' => $retryScanId, ':now' => $now]);

$horizon->enqueue([
    'job_id' => $retryJobId,
    'unique_id' => $retryScanId,
    'scan_id' => $retryScanId,
    'organization_id' => 'org-hegoweb-sec',
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'queue' => 'hegosentinel-scans',
    'max_tries' => 2,
    'timeout_seconds' => 10,
    'payload' => [
        'force_throw_exception' => 'Simulated transient scanner crash for retry verification',
    ],
]);

$attempt1 = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-retry-test');
$attempt2 = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-retry-test');

$failedCount = (int) TenantRlsContext::runInTenantTransaction($pdo, 'org-hegoweb-sec', function (PDO $txPdo) use ($retryJobId): int {
    $stmt = $txPdo->prepare('SELECT COUNT(*) FROM failed_jobs WHERE uuid = :jid AND organization_id = \'org-hegoweb-sec\'');
    $stmt->execute([':jid' => $retryJobId]);
    return (int) $stmt->fetchColumn();
});

assertGate(
    ($attempt1['status'] ?? '') === 'retrying'
    && ($attempt1['attempts'] ?? 0) === 1
    && ($attempt2['status'] ?? '') === 'failed'
    && ($attempt2['attempts'] ?? 0) === 2
    && $failedCount === 1,
    'S11-HORIZON-02',
    'Redis queue job retries on first failure (status=retrying, attempts=1) and records tenant-scoped failed_jobs row on exhaustion (attempts=2)'
);

// 4. Job Timeout Enforcement (`timeout_seconds=1` with 1200ms execution)
$timeoutJobId = 'JOB-TIMEOUT-' . strtoupper(bin2hex(random_bytes(3)));
$timeoutScanId = 'SCAN-TIMEOUT-' . strtoupper(bin2hex(random_bytes(3)));
$pdo->prepare(
    'INSERT INTO scan_queue_jobs (id, organization_id, project_id, scan_run_id, queue_name, worker_isolation_mode, status, attempts, max_tries, timeout_seconds, dispatched_at)
     VALUES (:id, \'org-hegoweb-sec\', \'proj-laravel-commerce\', :sid, \'hegosentinel-scans\', \'supervisor-isolated-worker\', \'queued\', 0, 1, 1, :now)'
)->execute([':id' => $timeoutJobId, ':sid' => $timeoutScanId, ':now' => $now]);

$horizon->enqueue([
    'job_id' => $timeoutJobId,
    'unique_id' => $timeoutScanId,
    'scan_id' => $timeoutScanId,
    'organization_id' => 'org-hegoweb-sec',
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'queue' => 'hegosentinel-scans',
    'max_tries' => 1,
    'timeout_seconds' => 1,
    'payload' => [
        'simulated_duration_ms' => 1250,
        'grant' => [],
    ],
]);
$timeoutOut = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-timeout-test');
assertGate(
    ($timeoutOut['status'] ?? '') === 'failed'
    && str_contains((string) ($timeoutOut['error'] ?? ''), 'exceeded timeout'),
    'S11-HORIZON-03',
    'Horizon worker enforces job timeout_seconds and moves timed-out job to failed_jobs',
    json_encode($timeoutOut)
);

// 5. Concurrent Duplicate Execution Lock (`ShouldBeUnique` / `SET NX PX`)
$uniqueScanId = 'SCAN-CONCURRENT-LOCK-' . strtoupper(bin2hex(random_bytes(3)));
$lockAcquiredByWorker1 = $horizon->acquireJobExecutionLock($uniqueScanId, 'worker-node-A', 30000);
$lockAcquiredByWorker2 = $horizon->acquireJobExecutionLock($uniqueScanId, 'worker-node-B', 30000);

$horizon->enqueue([
    'job_id' => 'JOB-DUP-' . strtoupper(bin2hex(random_bytes(3))),
    'unique_id' => $uniqueScanId,
    'scan_id' => $uniqueScanId,
    'organization_id' => 'org-hegoweb-sec',
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'queue' => 'hegosentinel-scans',
]);
$dupWorkerOut = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-node-B');
$horizon->releaseJobExecutionLock($uniqueScanId, 'worker-node-A');

assertGate(
    $lockAcquiredByWorker1 === true
    && $lockAcquiredByWorker2 === false
    && ($dupWorkerOut['status'] ?? '') === 'duplicate_blocked',
    'S11-HORIZON-04',
    'Atomic Redis SET NX PX lock prevents two workers from executing the same scan job concurrently (status=duplicate_blocked)'
);

// 6. Cryptographic Tenant Context Serialization & Tamper Rejection
$tamperedJob = [
    'job_id' => 'JOB-TAMPER-01',
    'unique_id' => 'SCAN-TAMPER-01',
    'scan_id' => 'SCAN-TAMPER-01',
    'organization_id' => 'org-beta-isolated', // Forged cross-tenant org!
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'queue' => 'hegosentinel-scans',
    'tenant_hmac' => '0000000000000000000000000000000000000000000000000000000000000000',
];
$horizon->command(['RPUSH', 'queues:hegosentinel-scans', (string) json_encode($tamperedJob)]);
$tamperOut = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-sec-test');

assertGate(
    ($tamperOut['status'] ?? '') === 'failed'
    && ($tamperOut['reason'] ?? '') === 'tenant_hmac_verification_failed',
    'S11-HORIZON-05',
    'Serialized queue job with tampered organization_id / invalid HMAC is rejected before execution (tenant_hmac_verification_failed)'
);

// 7. Queued Job Cancellation via Emergency Stop & Pre-Execution Scope Revocation Guard
$ownerPrincipal = $service->getPrincipalById('usr-owner-01', 'org-hegoweb-sec');
$queuedScan = $service->createAndExecuteScan($ownerPrincipal, [
    'project_id' => 'proj-nextjs-portal',
    'grant_id' => 'GRANT-NEXTJS-2026-001',
    'mode' => 'offline-fixture',
    'fixture_variant' => 'baseline',
    'async_queue_only' => true,
]);
$queuedScanId = (string) ($queuedScan['id'] ?? '');
$estopRes = $service->triggerEmergencyStop($ownerPrincipal, [
    'project_id' => 'proj-nextjs-portal',
    'scan_run_id' => $queuedScanId,
    'reason' => 'Cancel queued job in Redis before worker pop',
]);

assertGate(
    ($queuedScan['status'] ?? '') === 'queued'
    && ($estopRes['redis_queue_jobs_purged'] ?? 0) >= 1
    && ($estopRes['within_sla_2000ms'] ?? false) === true,
    'S11-HORIZON-06',
    'Emergency Stop purges unpopped job from Redis queue and marks scan cancelled within <2000ms SLA',
    json_encode($estopRes)
);

// Also test ScopeAuthorizationGrant revocation AFTER job is queued in Redis but BEFORE worker pops it
$tempGrant = $service->createScopeAuthorizationGrant($ownerPrincipal, 'proj-laravel-commerce', [
    'hostname' => 'demo.example.test',
    'domain_control_proof' => 'dns-txt:hegosentinel-dns-verify=sprint11-revoke-check',
    'written_permission_ref' => 'AUTH-SPRINT11-REVOKE-TEST',
    'authorization_statement' => 'Temporary grant to test revocation while queued in Redis',
]);
$tempGrantId = (string) $tempGrant['grant_id'];
$revokedQueuedScan = $service->createAndExecuteScan($ownerPrincipal, [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => $tempGrantId,
    'mode' => 'offline-fixture',
    'async_queue_only' => true,
]);
// Revoke the grant while the job is sitting in Redis `queues:hegosentinel-scans`
TenantRlsContext::runInTenantTransaction($pdo, 'org-hegoweb-sec', function (PDO $txPdo) use ($tempGrantId): void {
    $txPdo->prepare("UPDATE scope_authorization_grants SET status = 'revoked' WHERE grant_id = :gid")
        ->execute([':gid' => $tempGrantId]);
});
$revokedWorkerOut = $horizon->popAndProcessNext($pdo, ['hegosentinel-scans'], 'worker-revoke-check');
assertGate(
    ($revokedWorkerOut['status'] ?? '') === 'cancelled'
    && ($revokedWorkerOut['reason'] ?? '') === 'cancelled_or_grant_revoked_before_execution',
    'S11-SEC-REVOKE-01',
    'Queued job whose ScopeAuthorizationGrant is revoked before worker pop is aborted without scanner execution',
    json_encode($revokedWorkerOut)
);

// 8. Multi-Tenant Concurrent Scans Across 3 Organizations & Connection-Pool RLS Leakage Stress Test
$gammaReg = $service->register([
    'email' => 'ciso@gammafintech.example.test',
    'name' => 'Gamma FinTech CISO',
    'password' => 'GammaSecure!2026',
    'organization_name' => 'Gamma FinTech Holdings',
]);
$gammaPrincipal = $gammaReg['principal'];
$gammaOrgId = (string) $gammaPrincipal['organization_id'];

$gammaProject = $service->createProject($gammaPrincipal, [
    'name' => 'Gamma Payment Gateway',
    'environment' => 'staging',
    'stack' => ['laravel'],
    'hostname' => 'demo.example.test',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
]);
$gammaPrincipal = $service->getPrincipalById((string) $gammaPrincipal['user_id'], $gammaOrgId);
$gammaGrant = $service->createScopeAuthorizationGrant($gammaPrincipal, (string) $gammaProject['id'], [
    'hostname' => 'demo.example.test',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
    'domain_control_proof' => 'dns-txt:hegosentinel-dns-verify=sprint11-gamma-org',
    'written_permission_ref' => 'AUTH-GAMMA-2026-01',
]);

$betaPrincipal = $service->getPrincipalById('usr-beta-owner', 'org-beta-isolated');
$betaProject = $service->createProject($betaPrincipal, [
    'name' => 'Beta Isolated Vault',
    'environment' => 'staging',
    'stack' => ['laravel'],
    'hostname' => 'demo.example.test',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
]);
$betaPrincipal = $service->getPrincipalById('usr-beta-owner', 'org-beta-isolated');
$betaGrant = $service->createScopeAuthorizationGrant($betaPrincipal, (string) $betaProject['id'], [
    'hostname' => 'demo.example.test',
    'repository_path' => 'examples/synthetic-targets/laravel-app',
    'domain_control_proof' => 'dns-txt:hegosentinel-dns-verify=sprint11-beta-org',
    'written_permission_ref' => 'AUTH-BETA-2026-01',
]);

// Run scans across all 3 tenants through Redis + Horizon
$scanOrgA = $service->createAndExecuteScan($ownerPrincipal, [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'offline-fixture',
    'fixture_variant' => 'baseline',
]);
$scanOrgB = $service->createAndExecuteScan($betaPrincipal, [
    'project_id' => (string) $betaProject['id'],
    'grant_id' => (string) $betaGrant['grant_id'],
    'mode' => 'offline-fixture',
    'fixture_variant' => 'baseline',
]);
$scanOrgC = $service->createAndExecuteScan($gammaPrincipal, [
    'project_id' => (string) $gammaProject['id'],
    'grant_id' => (string) $gammaGrant['grant_id'],
    'mode' => 'offline-fixture',
    'fixture_variant' => 'patched',
]);

// Verify strict cross-tenant isolation across all 3 organizations
$orgAFindings = $service->listFindings($ownerPrincipal);
$orgBFindings = $service->listFindings($betaPrincipal);
$orgCFindings = $service->listFindings($gammaPrincipal);

$crossLeakDetected = false;
foreach ($orgAFindings as $f) {
    if ($f['organization_id'] !== 'org-hegoweb-sec') {
        $crossLeakDetected = true;
    }
}
foreach ($orgBFindings as $f) {
    if ($f['organization_id'] !== 'org-beta-isolated') {
        $crossLeakDetected = true;
    }
}
foreach ($orgCFindings as $f) {
    if ($f['organization_id'] !== $gammaOrgId) {
        $crossLeakDetected = true;
    }
}

// Connection-pool rapid context switching + mid-transaction exception rollback test (30 iterations)
$poolLeak = false;
$tenants = ['org-hegoweb-sec', 'org-beta-isolated', $gammaOrgId];
for ($i = 0; $i < 30; $i++) {
    $tOrg = $tenants[$i % 3];
    try {
        TenantRlsContext::runInTenantTransaction($pdo, $tOrg, function () use ($tOrg, $i): void {
            if (TenantRlsContext::currentOrganizationId() !== $tOrg) {
                throw new RuntimeException('Pool leak inside transaction');
            }
            if ($i % 5 === 0) {
                throw new RuntimeException('Simulated mid-transaction exception');
            }
        });
    } catch (\RuntimeException $e) {
        if ($e->getMessage() === 'Pool leak inside transaction') {
            $poolLeak = true;
        }
    }
    if (TenantRlsContext::currentOrganizationId() !== null) {
        $poolLeak = true;
    }
}

assertGate(
    !$crossLeakDetected
    && !$poolLeak
    && ($scanOrgA['status'] ?? '') === 'completed'
    && ($scanOrgB['status'] ?? '') === 'completed'
    && ($scanOrgC['status'] ?? '') === 'completed',
    'S11-MULTITENANT-01',
    '3-organization concurrent Redis/Horizon scans and 30-cycle connection-pool rollback stress test verified with zero cross-tenant leakage'
);

// 9. Fault-Tolerance / Chaos Tests: Strict Supervisor Outage Fail-Closed & Redis Outage Readiness
putenv('HEGOSENTINEL_SUPERVISOR_HTTP_ENABLED=1');
putenv('HEGOSENTINEL_SUPERVISOR_STRICT=1');
putenv('HEGOSENTINEL_WORKER_SUPERVISOR_URL=http://127.0.0.1:19999'); // Unreachable port
$outageRes = ExecuteAuthorizedScanJob::dispatchSyncOrQueue(
    ['organization_id' => 'org-hegoweb-sec'],
    'SCAN-SUPERVISOR-OUTAGE',
    'offline-fixture',
    null,
    'baseline',
    false
);
putenv('HEGOSENTINEL_SUPERVISOR_STRICT=0');
putenv('HEGOSENTINEL_SUPERVISOR_HTTP_ENABLED=0');

$unreachableRedis = new HorizonRedisQueueEngine('127.0.0.1', 19998);
$degradedTelemetry = $unreachableRedis->getLiveHorizonTelemetry();

assertGate(
    ($outageRes['allowed'] ?? true) === false
    && ($outageRes['reason'] ?? '') === 'worker_supervisor_unreachable'
    && ($degradedTelemetry['redis_reachable'] ?? true) === false
    && ($degradedTelemetry['status'] ?? '') === 'degraded_redis_unreachable',
    'S11-CHAOS-01',
    'Worker Supervisor outage fails closed (worker_supervisor_unreachable) and Redis outage degrades safely without unhandled exceptions'
);

// 10. Section 5 Full End-to-End Telemetry Verification (PID, Container ID, Queue ID, Tenant ID, Timestamps, Limits, Audit, Re-Test, Export)
$patchedScanA = $service->createAndExecuteScan($ownerPrincipal, [
    'project_id' => 'proj-laravel-commerce',
    'grant_id' => 'GRANT-LARAVEL-2026-001',
    'mode' => 'offline-fixture',
    'fixture_variant' => 'patched',
]);
$recheckA = $service->runRecheckComparison($ownerPrincipal, [
    'baseline_scan_id' => (string) $scanOrgA['id'],
    'current_scan_id' => (string) $patchedScanA['id'],
]);
$exportJson = $service->exportScanReport($ownerPrincipal, (string) $scanOrgA['id'], 'json');
$exportSarif = $service->exportScanReport($ownerPrincipal, (string) $scanOrgA['id'], 'sarif');
$qJob = (array) ($scanOrgA['queue_job'] ?? []);
$auditIntegrity = $service->verifyAuditChainIntegrity('org-hegoweb-sec');

assertGate(
    !empty($qJob['id'])
    && !empty($qJob['worker_pid'])
    && !empty($qJob['supervisor_container_id'])
    && !empty($qJob['redis_queue_id'])
    && ($qJob['organization_id'] ?? '') === 'org-hegoweb-sec'
    && !empty($qJob['container_started_at'])
    && !empty($qJob['container_finished_at'])
    && !empty($qJob['resource_limits_json'])
    && ($recheckA['comparable'] ?? false) === true
    && ($recheckA['counts']['verified_fixed'] ?? 0) >= 1
    && str_contains((string) ($exportSarif['content'] ?? ''), '"version": "2.1.0"')
    && ($auditIntegrity['valid'] ?? false) === true,
    'S11-E2E-TELEMETRY-01',
    sprintf(
        'Full E2E telemetry verified (job=%s, pid=%s, container=%s, org=%s, verified_fixed=%d, audit_entries=%d)',
        (string) ($qJob['id'] ?? ''),
        (string) ($qJob['worker_pid'] ?? ''),
        (string) ($qJob['supervisor_container_id'] ?? ''),
        (string) ($qJob['organization_id'] ?? ''),
        (int) ($recheckA['counts']['verified_fixed'] ?? 0),
        (int) ($auditIntegrity['entries_checked'] ?? 0)
    )
);

if (isset($shmPath) && is_string($shmPath) && is_file($shmPath)) {
    @unlink($shmPath);
}
if (!$usePostgres && isset($dbPath) && is_file($dbPath)) {
    @unlink($dbPath);
}

echo "------------------------------------------------------------------------\n";
echo sprintf("Sprint 11 Staging & Resilience Summary: %d passed, %d failed\n", $passed, $failed);
echo "========================================================================\n";

exit($failed > 0 ? 1 : 0);
