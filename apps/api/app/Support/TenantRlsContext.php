<?php

declare(strict_types=1);

namespace App\Support;

use Closure;
use PDO;
use RuntimeException;
use Throwable;

/**
 * TenantRlsContext (Sprint 10 — S10-01 & S10-02)
 *
 * Manages server-verified tenant context for both:
 * 1. Laravel Eloquent Global Scope (`BelongsToOrganization`)
 * 2. PostgreSQL 16 Row-Level Security (`SET LOCAL app.current_organization_id`)
 *
 * Enforces fail-closed semantics when tenant context is missing and resets session
 * settings on completion so connection-pooled PostgreSQL backends never leak tenant state.
 */
final class TenantRlsContext
{
    private static ?string $currentOrganizationId = null;

    /** @var array<string, mixed>|null */
    private static ?array $currentPrincipal = null;

    public static function currentOrganizationId(): ?string
    {
        return self::$currentOrganizationId;
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function currentPrincipal(): ?array
    {
        return self::$currentPrincipal;
    }

    /**
     * @param array<string, mixed>|null $principal
     */
    public static function set(?string $organizationId, ?array $principal = null, ?PDO $pdo = null): void
    {
        if ($organizationId !== null) {
            $organizationId = trim($organizationId);
            if ($organizationId === '' || preg_match('/^[a-zA-Z0-9\-_]{1,64}$/', $organizationId) !== 1) {
                throw new RuntimeException('Invalid organization_id format for TenantRlsContext', 403);
            }
        }

        self::$currentOrganizationId = $organizationId;
        self::$currentPrincipal = $principal;

        if ($pdo !== null && self::isPostgres($pdo)) {
            self::applySessionTenantSetting($pdo, $organizationId);
        }
    }

    public static function clear(?PDO $pdo = null): void
    {
        self::$currentOrganizationId = null;
        self::$currentPrincipal = null;

        if ($pdo !== null && self::isPostgres($pdo)) {
            self::resetSessionTenantSetting($pdo);
        }
    }

    /**
     * Executes a callback inside a PostgreSQL transaction with `SET LOCAL app.current_organization_id`
     * (and role switching to `hegosentinel_app` when connected as a migration/admin user),
     * guaranteeing automatic cleanup on commit or rollback (zero connection-pool leakage).
     *
     * @template T
     * @param Closure(PDO): T $callback
     * @param array<string, mixed>|null $principal
     * @return T
     */
    public static function runInTenantTransaction(
        PDO $pdo,
        ?string $organizationId,
        Closure $callback,
        ?array $principal = null,
        bool $enforceAppRole = true
    ): mixed {
        $prevOrg = self::$currentOrganizationId;
        $prevPrincipal = self::$currentPrincipal;

        if ($organizationId !== null && $organizationId !== '') {
            if (preg_match('/^[a-zA-Z0-9\-_]{1,64}$/', $organizationId) !== 1) {
                throw new RuntimeException('Invalid tenant identifier for RLS transaction', 403);
            }
        }

        self::$currentOrganizationId = ($organizationId !== null && $organizationId !== '') ? $organizationId : null;
        self::$currentPrincipal = $principal;

        $isPg = self::isPostgres($pdo);
        $startedTx = false;

        try {
            if ($isPg && !$pdo->inTransaction()) {
                $pdo->beginTransaction();
                $startedTx = true;
            }

            if ($isPg) {
                if ($enforceAppRole && self::roleExists($pdo, 'hegosentinel_app')) {
                    $pdo->exec('SET LOCAL ROLE hegosentinel_app');
                }
                $val = self::$currentOrganizationId ?? '';
                $stmt = $pdo->prepare("SELECT set_config('app.current_organization_id', :org_id, true)");
                $stmt->execute([':org_id' => $val]);
            }

            $result = $callback($pdo);

            if ($startedTx && $pdo->inTransaction()) {
                $pdo->commit();
            }

            return $result;
        } catch (Throwable $e) {
            if ($startedTx && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        } finally {
            self::$currentOrganizationId = $prevOrg;
            self::$currentPrincipal = $prevPrincipal;
            if ($isPg && !$pdo->inTransaction()) {
                self::resetSessionTenantSetting($pdo);
            }
        }
    }

    public static function applySessionTenantSetting(PDO $pdo, ?string $organizationId): void
    {
        if (!self::isPostgres($pdo)) {
            return;
        }
        $val = ($organizationId !== null && $organizationId !== '') ? $organizationId : '';
        $localOnly = $pdo->inTransaction();
        $stmt = $pdo->prepare('SELECT set_config(\'app.current_organization_id\', :org_id, ' . ($localOnly ? 'true' : 'false') . ')');
        $stmt->execute([':org_id' => $val]);
    }

    public static function resetSessionTenantSetting(PDO $pdo): void
    {
        if (!self::isPostgres($pdo)) {
            return;
        }
        try {
            $pdo->exec("SELECT set_config('app.current_organization_id', '', false)");
        } catch (Throwable) {
            // Ignore if transaction is in aborted state prior to rollback
        }
    }

    public static function isPostgres(PDO $pdo): bool
    {
        return strtolower((string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME)) === 'pgsql';
    }

    private static function roleExists(PDO $pdo, string $roleName): bool
    {
        $stmt = $pdo->prepare('SELECT 1 FROM pg_roles WHERE rolname = :r LIMIT 1');
        $stmt->execute([':r' => $roleName]);
        return (bool) $stmt->fetchColumn();
    }
}

