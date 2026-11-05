<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';
require_once __DIR__ . '/../database/migrations/2026_11_05_000002_enable_postgresql_row_level_security.php';

use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use App\Support\TenantRlsContext;
use Database\Migrations\EnablePostgresqlRowLevelSecurity;

/**
 * HegoSentinel Sprint 10 — S10-02: PostgreSQL 16 & Row-Level Security (RLS) Verification Suite
 *
 * Verifies against a live PostgreSQL 16 database:
 * 1. `ENABLE ROW LEVEL SECURITY` & `FORCE ROW LEVEL SECURITY` on all tenant tables (`pg_class`)
 * 2. `hegosentinel_app` role has `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` (`pg_roles`)
 * 3. Referential integrity foreign key constraints (`pg_constraint`)
 * 4. Fail-closed behavior when `app.current_organization_id` is unset/empty (`0` rows on SELECT, `42501` on INSERT)
 * 5. Positive tenant-scoped access with `SET LOCAL app.current_organization_id = 'org-hegoweb-sec'`
 * 6. Cross-tenant SELECT / INSERT / UPDATE / DELETE rejection at the PostgreSQL 16 RLS engine layer
 * 7. Connection-pool safety: `app.current_organization_id` is reset after transaction completion
 */

if (!extension_loaded('pdo_pgsql')) {
    echo "[SKIP] pdo_pgsql extension is not loaded in this PHP runtime.\n";
    exit(0);
}

$pgHost = getenv('DB_HOST') ?: '127.0.0.1';
$pgPort = getenv('DB_PORT') ?: '54329';
$pgDb = getenv('DB_DATABASE') ?: 'hegosentinel';
$pgAdminUser = getenv('DB_ADMIN_USERNAME') ?: (getenv('DB_USERNAME') ?: 'postgres');
$pgAdminPass = getenv('DB_ADMIN_PASSWORD') ?: (getenv('DB_PASSWORD') ?: '');

$dsn = sprintf('pgsql:host=%s;port=%s;dbname=%s', $pgHost, $pgPort, $pgDb);
try {
    $pdo = new PDO($dsn, $pgAdminUser, $pgAdminPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 3,
    ]);
} catch (Throwable $e) {
    if (getenv('CI') === 'true' || getenv('REQUIRE_POSTGRES_RLS') === '1') {
        fwrite(STDERR, "[FAIL] PostgreSQL 16 connection failed ({$dsn}): " . $e->getMessage() . "\n");
        exit(1);
    }
    echo sprintf("[SKIP] Live PostgreSQL 16 instance not reachable at %s (%s)\n", $dsn, $e->getMessage());
    exit(0);
}

putenv('APP_ENV=testing');
putenv('HEGOSENTINEL_DEMO_MODE=1');
$_ENV['APP_ENV'] = 'testing';
$_ENV['HEGOSENTINEL_DEMO_MODE'] = '1';

// Clean and migrate schema + RLS policies on PostgreSQL
foreach (array_reverse(EnablePostgresqlRowLevelSecurity::tenantTables()) as $tbl) {
    $pdo->exec("DROP TABLE IF EXISTS {$tbl} CASCADE");
}
$pdo->exec('DROP TABLE IF EXISTS organizations CASCADE');
$pdo->exec('DROP TABLE IF EXISTS password_reset_tokens CASCADE');
$pdo->exec('DROP TABLE IF EXISTS auth_login_attempts CASCADE');
$pdo->exec('DROP TABLE IF EXISTS users CASCADE');

DatabaseManager::resetConnection($pdo, 'pgsql');
$service = new SecurityPlatformService($pdo);

$passed = 0;
$failed = 0;

function rlsOk(bool $cond, string $label, string $detail = ''): void
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
echo "HegoSentinel Sprint 10 — PostgreSQL 16 Row-Level Security (S10-02) Suite\n";
echo "========================================================================\n";

$pgVersion = (string) $pdo->query('SHOW server_version')->fetchColumn();
rlsOk($pgVersion !== '', 'S10-02.1: Connected to live PostgreSQL server (version=' . $pgVersion . ')');

// 1. Verify hegosentinel_app role attributes (NOSUPERUSER, NOBYPASSRLS)
$roleRow = $pdo->query("SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = 'hegosentinel_app'")->fetch();
rlsOk(
    is_array($roleRow)
    && $roleRow['rolsuper'] === false
    && $roleRow['rolcreatedb'] === false
    && $roleRow['rolcreaterole'] === false
    && $roleRow['rolbypassrls'] === false,
    'S10-02.2: Role hegosentinel_app enforces NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
    json_encode($roleRow)
);

// 2. Verify ENABLE ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY on all tenant tables
$expectedTables = array_merge(EnablePostgresqlRowLevelSecurity::tenantTables(), ['organizations']);
$missingRls = [];
foreach ($expectedTables as $tbl) {
    $stmt = $pdo->prepare('SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t LIMIT 1');
    $stmt->execute([':t' => $tbl]);
    $row = $stmt->fetch();
    if (!$row || !$row['relrowsecurity'] || !$row['relforcerowsecurity']) {
        $missingRls[] = $tbl . ':' . json_encode($row);
    }
}
rlsOk(
    $missingRls === [],
    sprintf('S10-02.3: All %d tenant tables have ENABLE ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY active', count($expectedTables)),
    implode(', ', $missingRls)
);

// 3. Verify PostgreSQL Foreign Key constraints exist
$fkCount = (int) $pdo->query("SELECT COUNT(*) FROM pg_constraint WHERE contype = 'f' AND conname LIKE 'fk_%'")->fetchColumn();
rlsOk($fkCount >= 20, sprintf('S10-02.4: PostgreSQL foreign key constraints active (%d constraints)', $fkCount));

// 4. Negative Control: Missing tenant context fails closed (0 rows on SELECT, 42501 on INSERT)
TenantRlsContext::runInTenantTransaction($pdo, null, static function (PDO $txPdo): void {
    $projCount = (int) $txPdo->query('SELECT COUNT(*) FROM projects')->fetchColumn();
    $scanCount = (int) $txPdo->query('SELECT COUNT(*) FROM scan_runs')->fetchColumn();
    $findCount = (int) $txPdo->query('SELECT COUNT(*) FROM findings')->fetchColumn();
    $auditCount = (int) $txPdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
    rlsOk(
        $projCount === 0 && $scanCount === 0 && $findCount === 0 && $auditCount === 0,
        'S10-02.5: Missing app.current_organization_id fails closed (0 rows returned across projects, scans, findings, audit_logs)',
        "proj={$projCount} scan={$scanCount} find={$findCount} audit={$auditCount}"
    );
});

$insertWithoutContextBlocked = false;
try {
    TenantRlsContext::runInTenantTransaction($pdo, null, static function (PDO $txPdo): void {
        $txPdo->exec("
            INSERT INTO projects (id, organization_id, name, slug, environment, stack_json, description, is_demo, created_by_user_id, created_at)
            VALUES ('proj-unauth', 'org-hegoweb-sec', 'Unauth', 'unauth', 'staging', '[]', 'desc', 0, 'usr-owner-01', '2026-11-05T00:00:00Z')
        ");
    });
} catch (PDOException $e) {
    $insertWithoutContextBlocked = $e->getCode() === '42501' || str_contains($e->getMessage(), 'row-level security');
}
rlsOk($insertWithoutContextBlocked, 'S10-02.6: INSERT without app.current_organization_id is rejected by PostgreSQL RLS (SQLSTATE 42501)');

// 5. Positive Control & Cross-Tenant Read Isolation: Bound to org-hegoweb-sec
TenantRlsContext::runInTenantTransaction($pdo, 'org-hegoweb-sec', static function (PDO $txPdo): void {
    $projects = $txPdo->query('SELECT id, organization_id FROM projects')->fetchAll();
    $ids = array_column($projects, 'id');
    rlsOk(
        in_array('proj-laravel-commerce', $ids, true)
        && !in_array('proj-beta-core', $ids, true),
        'S10-02.7: SELECT on projects with app.current_organization_id=org-hegoweb-sec returns only org-A rows and hides org-beta-isolated',
        json_encode($ids)
    );

    // Cross-tenant direct SELECT by primary key returns 0 rows
    $betaStmt = $txPdo->prepare("SELECT * FROM projects WHERE id = 'proj-beta-core'");
    $betaStmt->execute();
    rlsOk($betaStmt->fetch() === false, 'S10-02.8: Direct SELECT for foreign tenant row (proj-beta-core) returns 0 rows under PostgreSQL RLS');

    // Cross-tenant UPDATE affects 0 rows
    $updStmt = $txPdo->prepare("UPDATE projects SET name = 'Tampered By Org A' WHERE id = 'proj-beta-core'");
    $updStmt->execute();
    rlsOk($updStmt->rowCount() === 0, 'S10-02.9: Cross-tenant UPDATE on proj-beta-core affects 0 rows under PostgreSQL RLS');

    // Cross-tenant DELETE affects 0 rows
    $delStmt = $txPdo->prepare("DELETE FROM projects WHERE id = 'proj-beta-core'");
    $delStmt->execute();
    rlsOk($delStmt->rowCount() === 0, 'S10-02.10: Cross-tenant DELETE on proj-beta-core affects 0 rows under PostgreSQL RLS');
});

// 6. Cross-Tenant INSERT Spoofing Blocked by PostgreSQL RLS WITH CHECK (SQLSTATE 42501)
$crossTenantInsertBlocked = false;
try {
    TenantRlsContext::runInTenantTransaction($pdo, 'org-hegoweb-sec', static function (PDO $txPdo): void {
        $txPdo->exec("
            INSERT INTO projects (id, organization_id, name, slug, environment, stack_json, description, is_demo, created_by_user_id, created_at)
            VALUES ('proj-forged-into-beta', 'org-beta-isolated', 'Forged', 'forged', 'staging', '[]', 'desc', 0, 'usr-owner-01', '2026-11-05T00:00:00Z')
        ");
    });
} catch (PDOException $e) {
    $crossTenantInsertBlocked = $e->getCode() === '42501' || str_contains($e->getMessage(), 'row-level security');
}
rlsOk($crossTenantInsertBlocked, 'S10-02.11: Cross-tenant INSERT (org-A trying to insert row with organization_id=org-beta-isolated) rejected by PostgreSQL RLS WITH CHECK (42501)');

// 7. Cross-Tenant UPDATE of organization_id column Blocked by PostgreSQL RLS WITH CHECK (SQLSTATE 42501)
$crossTenantUpdateOrgIdBlocked = false;
try {
    TenantRlsContext::runInTenantTransaction($pdo, 'org-hegoweb-sec', static function (PDO $txPdo): void {
        $txPdo->exec("UPDATE projects SET organization_id = 'org-beta-isolated' WHERE id = 'proj-laravel-commerce'");
    });
} catch (PDOException $e) {
    $crossTenantUpdateOrgIdBlocked = $e->getCode() === '42501' || str_contains($e->getMessage(), 'row-level security');
}
rlsOk($crossTenantUpdateOrgIdBlocked, 'S10-02.12: Cross-tenant UPDATE moving own row to organization_id=org-beta-isolated rejected by PostgreSQL RLS WITH CHECK (42501)');

// 8. Verify Beta Tenant still has its project intact and isolated
TenantRlsContext::runInTenantTransaction($pdo, 'org-beta-isolated', static function (PDO $txPdo): void {
    $betaProjects = $txPdo->query('SELECT id, name FROM projects')->fetchAll();
    rlsOk(
        count($betaProjects) === 1
        && $betaProjects[0]['id'] === 'proj-beta-core'
        && $betaProjects[0]['name'] === 'Beta Isolated Banking Core',
        'S10-02.13: Beta tenant data remains 100% intact and sees only proj-beta-core when bound to org-beta-isolated'
    );
});

// 9. Verify connection-pool safety: app.current_organization_id is reset to empty outside transaction
$leakedSetting = (string) $pdo->query("SELECT current_setting('app.current_organization_id', true)")->fetchColumn();
rlsOk(
    $leakedSetting === '',
    'S10-02.14: Connection-pool safety verified — app.current_organization_id is reset to empty after tenant transaction'
);

echo "------------------------------------------------------------------------\n";
echo sprintf("PostgreSQL 16 RLS Summary: %d passed, %d failed\n", $passed, $failed);
echo "========================================================================\n";

exit($failed > 0 ? 1 : 0);
