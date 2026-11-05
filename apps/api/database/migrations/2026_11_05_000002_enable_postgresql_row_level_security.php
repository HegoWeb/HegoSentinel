<?php

declare(strict_types=1);

namespace Database\Migrations;

use PDO;

/**
 * HegoSentinel Sprint 10 — S10-02: PostgreSQL 16 Row-Level Security (RLS) & Foreign Key Migration
 *
 * Enforces:
 * 1. Referential integrity (`REFERENCES organizations(id) ON DELETE CASCADE`, `REFERENCES projects(id) ON DELETE CASCADE`).
 * 2. Dedicated non-superuser application role `hegosentinel_app` (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`).
 * 3. `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` on all 13 tenant-bound tables.
 * 4. Restrictive + permissive RLS policies bound to `current_setting('app.current_organization_id', true)`
 *    that fail closed when tenant context is unset/empty and block cross-tenant `SELECT`, `INSERT`, `UPDATE`, and `DELETE`.
 */
final class EnablePostgresqlRowLevelSecurity
{
    /**
     * All tenant-bound tables protected by PostgreSQL 16 Row-Level Security.
     *
     * @return list<string>
     */
    public static function tenantTables(): array
    {
        return [
            'user_sessions',
            'organization_members',
            'projects',
            'target_assets',
            'scope_authorization_grants',
            'scan_runs',
            'scan_queue_jobs',
            'findings',
            'false_positive_suppressions',
            'remediation_tasks',
            'recheck_comparisons',
            'approved_notifications',
            'audit_logs',
            'emergency_stop_events',
        ];
    }

    public static function migrate(PDO $pdo): void
    {
        $driver = strtolower((string) $pdo->getAttribute(PDO::ATTR_DRIVER_NAME));
        if ($driver !== 'pgsql') {
            return;
        }

        // 1. Ensure non-superuser NOBYPASSRLS application role exists
        $pdo->exec("
            DO \$\$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hegosentinel_app') THEN
                    CREATE ROLE hegosentinel_app LOGIN PASSWORD 'hegosentinel_app_rls_pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                ELSE
                    ALTER ROLE hegosentinel_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                END IF;
            END
            \$\$;
        ");

        // 2. Grant table and sequence privileges to hegosentinel_app
        $pdo->exec('GRANT USAGE ON SCHEMA public TO hegosentinel_app');
        $pdo->exec('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hegosentinel_app');
        $pdo->exec('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO hegosentinel_app');

        // 3. Add PostgreSQL foreign key constraints idempotently
        $foreignKeys = [
            ['organization_members', 'fk_org_members_org', 'organization_id', 'organizations', 'id'],
            ['organization_members', 'fk_org_members_user', 'user_id', 'users', 'id'],
            ['projects', 'fk_projects_org', 'organization_id', 'organizations', 'id'],
            ['target_assets', 'fk_target_assets_org', 'organization_id', 'organizations', 'id'],
            ['target_assets', 'fk_target_assets_proj', 'project_id', 'projects', 'id'],
            ['scope_authorization_grants', 'fk_scope_grants_org', 'organization_id', 'organizations', 'id'],
            ['scope_authorization_grants', 'fk_scope_grants_proj', 'project_id', 'projects', 'id'],
            ['scan_runs', 'fk_scan_runs_org', 'organization_id', 'organizations', 'id'],
            ['scan_runs', 'fk_scan_runs_proj', 'project_id', 'projects', 'id'],
            ['scan_queue_jobs', 'fk_scan_queue_jobs_org', 'organization_id', 'organizations', 'id'],
            ['findings', 'fk_findings_org', 'organization_id', 'organizations', 'id'],
            ['findings', 'fk_findings_proj', 'project_id', 'projects', 'id'],
            ['findings', 'fk_findings_scan', 'scan_run_id', 'scan_runs', 'id'],
            ['false_positive_suppressions', 'fk_suppressions_org', 'organization_id', 'organizations', 'id'],
            ['false_positive_suppressions', 'fk_suppressions_proj', 'project_id', 'projects', 'id'],
            ['remediation_tasks', 'fk_remediation_tasks_org', 'organization_id', 'organizations', 'id'],
            ['remediation_tasks', 'fk_remediation_tasks_proj', 'project_id', 'projects', 'id'],
            ['recheck_comparisons', 'fk_rechecks_org', 'organization_id', 'organizations', 'id'],
            ['recheck_comparisons', 'fk_rechecks_proj', 'project_id', 'projects', 'id'],
            ['approved_notifications', 'fk_notifications_org', 'organization_id', 'organizations', 'id'],
            ['approved_notifications', 'fk_notifications_proj', 'project_id', 'projects', 'id'],
            ['emergency_stop_events', 'fk_estop_org', 'organization_id', 'organizations', 'id'],
        ];

        foreach ($foreignKeys as [$table, $constraint, $column, $refTable, $refCol]) {
            $pdo->exec("
                DO \$\$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = '{$constraint}'
                    ) THEN
                        ALTER TABLE {$table}
                            ADD CONSTRAINT {$constraint}
                            FOREIGN KEY ({$column}) REFERENCES {$refTable}({$refCol}) ON DELETE CASCADE;
                    END IF;
                END
                \$\$;
            ");
        }

        // 4. Enable & Force Row-Level Security on every tenant table + organizations table
        foreach (self::tenantTables() as $table) {
            $pdo->exec("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY");
            $pdo->exec("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY");

            $pdo->exec("DROP POLICY IF EXISTS tenant_rls_restrictive ON {$table}");
            $pdo->exec("
                CREATE POLICY tenant_rls_restrictive ON {$table}
                    AS RESTRICTIVE
                    FOR ALL
                    TO hegosentinel_app
                    USING (
                        NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                        AND organization_id = current_setting('app.current_organization_id', true)
                    )
                    WITH CHECK (
                        NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                        AND organization_id = current_setting('app.current_organization_id', true)
                    )
            ");

            $pdo->exec("DROP POLICY IF EXISTS tenant_rls_permissive ON {$table}");
            $pdo->exec("
                CREATE POLICY tenant_rls_permissive ON {$table}
                    AS PERMISSIVE
                    FOR ALL
                    TO PUBLIC
                    USING (
                        current_user <> 'hegosentinel_app'
                        OR (
                            NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                            AND organization_id = current_setting('app.current_organization_id', true)
                        )
                    )
                    WITH CHECK (
                        current_user <> 'hegosentinel_app'
                        OR (
                            NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                            AND organization_id = current_setting('app.current_organization_id', true)
                        )
                    )
            ");
        }

        // Also protect organizations table by id = app.current_organization_id when queried by hegosentinel_app
        $pdo->exec('ALTER TABLE organizations ENABLE ROW LEVEL SECURITY');
        $pdo->exec('ALTER TABLE organizations FORCE ROW LEVEL SECURITY');
        $pdo->exec('DROP POLICY IF EXISTS org_rls_restrictive ON organizations');
        $pdo->exec("
            CREATE POLICY org_rls_restrictive ON organizations
                AS RESTRICTIVE
                FOR ALL
                TO hegosentinel_app
                USING (
                    NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                    AND id = current_setting('app.current_organization_id', true)
                )
                WITH CHECK (
                    NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                    AND id = current_setting('app.current_organization_id', true)
                )
        ");
        $pdo->exec('DROP POLICY IF EXISTS org_rls_permissive ON organizations');
        $pdo->exec("
            CREATE POLICY org_rls_permissive ON organizations
                AS PERMISSIVE
                FOR ALL
                TO PUBLIC
                USING (
                    current_user <> 'hegosentinel_app'
                    OR (
                        NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                        AND id = current_setting('app.current_organization_id', true)
                    )
                )
                WITH CHECK (
                    current_user <> 'hegosentinel_app'
                    OR (
                        NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                        AND id = current_setting('app.current_organization_id', true)
                    )
                )
        ");
    }
}
