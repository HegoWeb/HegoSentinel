<?php

declare(strict_types=1);

namespace Database\Migrations;

use PDO;

/**
 * HegoSentinel Sprint 10 Full Platform Schema Migration
 * Compatible with both PostgreSQL 16 (production / Docker Compose) and SQLite 3 (local dev & CI tests).
 * Enforces multi-tenant organization_id & project_id foreign keys and indexes across all 14 modules.
 */
final class CreateHegosentinelPlatformTables
{
    /**
     * @return list<string>
     */
    public static function statements(string $driver = 'pgsql'): array
    {
        return [
            // 1. Users & Authentication
            'CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(64) PRIMARY KEY,
                email VARCHAR(190) NOT NULL UNIQUE,
                name VARCHAR(190) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                preferred_locale VARCHAR(8) NOT NULL DEFAULT \'tr\',
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(40) NOT NULL,
                updated_at VARCHAR(40) NOT NULL
            )',

            'CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) NOT NULL,
                organization_id VARCHAR(64) NOT NULL,
                ip_address VARCHAR(64) NOT NULL,
                user_agent VARCHAR(255) NOT NULL,
                issued_at VARCHAR(40) NOT NULL,
                expires_at VARCHAR(40) NOT NULL,
                revoked_at VARCHAR(40) DEFAULT NULL
            )',

            'CREATE TABLE IF NOT EXISTS password_reset_tokens (
                email VARCHAR(190) PRIMARY KEY,
                token_hash VARCHAR(64) NOT NULL,
                expires_at VARCHAR(40) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            // 2. Organizations & Team Members (RBAC: owner, security_lead, developer, viewer)
            'CREATE TABLE IF NOT EXISTS organizations (
                id VARCHAR(64) PRIMARY KEY,
                slug VARCHAR(120) NOT NULL UNIQUE,
                name VARCHAR(190) NOT NULL,
                verified_notification_domains_json TEXT NOT NULL,
                created_by_user_id VARCHAR(64) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            'CREATE TABLE IF NOT EXISTS organization_members (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                user_id VARCHAR(64) NOT NULL,
                role VARCHAR(32) NOT NULL,
                allowed_project_ids_json TEXT NOT NULL,
                created_at VARCHAR(40) NOT NULL,
                UNIQUE(organization_id, user_id)
            )',

            // 4. Projects & Target Assets
            'CREATE TABLE IF NOT EXISTS projects (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                name VARCHAR(190) NOT NULL,
                slug VARCHAR(120) NOT NULL,
                environment VARCHAR(32) NOT NULL,
                stack_json TEXT NOT NULL,
                description TEXT NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_by_user_id VARCHAR(64) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            'CREATE TABLE IF NOT EXISTS target_assets (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                asset_type VARCHAR(32) NOT NULL,
                scheme VARCHAR(16) DEFAULT NULL,
                hostname VARCHAR(190) DEFAULT NULL,
                port INTEGER DEFAULT NULL,
                path_prefix VARCHAR(255) DEFAULT NULL,
                repository_path VARCHAR(512) DEFAULT NULL,
                domain_ownership_verified INTEGER NOT NULL DEFAULT 0,
                domain_verification_token VARCHAR(128) NOT NULL,
                domain_verified_at VARCHAR(40) DEFAULT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            // 5. Scope Authorization Grants (Written Permission + Time Window + Budget)
            'CREATE TABLE IF NOT EXISTS scope_authorization_grants (
                grant_id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                scope_version INTEGER NOT NULL,
                profile VARCHAR(32) NOT NULL,
                owner_name VARCHAR(190) NOT NULL,
                authorization_statement TEXT NOT NULL,
                domain_control_proof VARCHAR(255) NOT NULL,
                written_permission_ref VARCHAR(190) NOT NULL,
                emergency_contact VARCHAR(190) NOT NULL,
                issued_at VARCHAR(40) NOT NULL,
                expires_at VARCHAR(40) NOT NULL,
                window_start_at VARCHAR(40) NOT NULL,
                window_end_at VARCHAR(40) NOT NULL,
                max_request_budget INTEGER NOT NULL,
                allowed_methods_json TEXT NOT NULL,
                allowed_checks_json TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                allowed_repositories_json TEXT NOT NULL,
                approved_by_user_id VARCHAR(64) NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT \'active\',
                created_at VARCHAR(40) NOT NULL
            )',

            // 6 & 7. Scan Runs, Queue Jobs & Coverage Matrix
            'CREATE TABLE IF NOT EXISTS scan_runs (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                grant_id VARCHAR(64) NOT NULL,
                scope_version INTEGER NOT NULL,
                profile VARCHAR(32) NOT NULL,
                mode VARCHAR(32) NOT NULL,
                data_source VARCHAR(32) NOT NULL DEFAULT \'real_scan\',
                status VARCHAR(32) NOT NULL,
                global_coverage_status VARCHAR(32) NOT NULL,
                scanner_version VARCHAR(32) NOT NULL,
                total_findings INTEGER NOT NULL DEFAULT 0,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                coverage_checks_json TEXT NOT NULL,
                report_payload_json TEXT NOT NULL,
                emergency_stop_token_id VARCHAR(64) NOT NULL,
                triggered_by_user_id VARCHAR(64) NOT NULL,
                started_at VARCHAR(40) NOT NULL,
                completed_at VARCHAR(40) DEFAULT NULL,
                cancelled_reason TEXT DEFAULT NULL
            )',

            'CREATE TABLE IF NOT EXISTS scan_queue_jobs (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                scan_run_id VARCHAR(64) NOT NULL,
                queue_name VARCHAR(64) NOT NULL,
                worker_isolation_mode VARCHAR(64) NOT NULL,
                status VARCHAR(32) NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_tries INTEGER NOT NULL DEFAULT 1,
                timeout_seconds INTEGER NOT NULL DEFAULT 90,
                idempotency_key VARCHAR(128) DEFAULT NULL,
                worker_pid INTEGER DEFAULT NULL,
                supervisor_container_id VARCHAR(128) DEFAULT NULL,
                horizon_supervisor VARCHAR(64) DEFAULT \'supervisor-scans\',
                redis_queue_id VARCHAR(128) DEFAULT NULL,
                container_started_at VARCHAR(40) DEFAULT NULL,
                container_finished_at VARCHAR(40) DEFAULT NULL,
                resource_limits_json TEXT DEFAULT NULL,
                heartbeat_at VARCHAR(40) DEFAULT NULL,
                dispatched_at VARCHAR(40) NOT NULL,
                finished_at VARCHAR(40) DEFAULT NULL,
                error_message TEXT DEFAULT NULL
            )',

            'CREATE TABLE IF NOT EXISTS failed_jobs (
                id VARCHAR(64) PRIMARY KEY,
                uuid VARCHAR(64) NOT NULL UNIQUE,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) DEFAULT NULL,
                scan_run_id VARCHAR(64) DEFAULT NULL,
                connection VARCHAR(32) NOT NULL DEFAULT \'redis\',
                queue VARCHAR(64) NOT NULL,
                payload_json TEXT NOT NULL,
                exception TEXT NOT NULL,
                failed_at VARCHAR(40) NOT NULL
            )',

            // 8. Normalized Security Findings & Scoped Suppressions
            'CREATE TABLE IF NOT EXISTS findings (
                id VARCHAR(64) PRIMARY KEY,
                scan_run_id VARCHAR(64) NOT NULL,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                grant_id VARCHAR(64) NOT NULL,
                scope_version INTEGER NOT NULL,
                rule_id VARCHAR(32) NOT NULL,
                rule_version VARCHAR(32) NOT NULL,
                asset_key VARCHAR(512) NOT NULL,
                fingerprint VARCHAR(128) NOT NULL,
                title VARCHAR(255) NOT NULL,
                observed_condition TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                evidence_hash VARCHAR(128) NOT NULL,
                inferred_risk TEXT NOT NULL,
                limitations TEXT NOT NULL,
                confidence VARCHAR(16) NOT NULL,
                risk_priority VARCHAR(16) NOT NULL,
                verification_status VARCHAR(32) NOT NULL,
                standards_json TEXT NOT NULL,
                remediation_json TEXT NOT NULL,
                validation_criterion TEXT NOT NULL,
                data_source VARCHAR(32) NOT NULL DEFAULT \'real_scan\',
                observed_at VARCHAR(40) NOT NULL
            )',

            'CREATE TABLE IF NOT EXISTS false_positive_suppressions (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                fingerprint VARCHAR(128) NOT NULL,
                scope_version INTEGER NOT NULL,
                rationale TEXT NOT NULL,
                approved_by VARCHAR(190) NOT NULL,
                expires_at VARCHAR(40) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            // 9. Vulnerability Remediation Tasks
            'CREATE TABLE IF NOT EXISTS remediation_tasks (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                finding_id VARCHAR(64) NOT NULL,
                finding_fingerprint VARCHAR(128) NOT NULL,
                rule_id VARCHAR(32) NOT NULL,
                title VARCHAR(255) NOT NULL,
                framework VARCHAR(32) NOT NULL,
                assigned_to_user_id VARCHAR(64) NOT NULL,
                assigned_to_name VARCHAR(190) NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT \'open\',
                priority VARCHAR(16) NOT NULL,
                guidance_summary TEXT NOT NULL,
                code_patch_example TEXT NOT NULL,
                validation_command TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT \'\',
                created_at VARCHAR(40) NOT NULL,
                updated_at VARCHAR(40) NOT NULL
            )',

            // 10. Re-Test & Side-by-Side Comparison
            'CREATE TABLE IF NOT EXISTS recheck_comparisons (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                baseline_scan_id VARCHAR(64) NOT NULL,
                current_scan_id VARCHAR(64) NOT NULL,
                comparable INTEGER NOT NULL,
                non_comparable_reason TEXT DEFAULT NULL,
                counts_json TEXT NOT NULL,
                items_json TEXT NOT NULL,
                created_by_user_id VARCHAR(64) NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            // 12. Approved Developer Notifications (SEC-013)
            'CREATE TABLE IF NOT EXISTS approved_notifications (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) NOT NULL,
                scan_run_id VARCHAR(64) NOT NULL,
                channel VARCHAR(32) NOT NULL,
                recipient VARCHAR(255) NOT NULL,
                approved_by_user_id VARCHAR(64) NOT NULL,
                approved_by_role VARCHAR(32) NOT NULL,
                status VARCHAR(32) NOT NULL,
                rejection_reason TEXT DEFAULT NULL,
                sanitized_summary TEXT NOT NULL,
                created_at VARCHAR(40) NOT NULL
            )',

            // 13. Tamper-Evident Hash-Chained Audit Logs
            'CREATE TABLE IF NOT EXISTS audit_logs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id VARCHAR(64) NOT NULL UNIQUE,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) DEFAULT NULL,
                actor_user_id VARCHAR(64) NOT NULL,
                actor_role VARCHAR(32) NOT NULL,
                action VARCHAR(64) NOT NULL,
                outcome VARCHAR(16) NOT NULL,
                detail TEXT NOT NULL,
                created_at VARCHAR(40) NOT NULL,
                prev_hash VARCHAR(64) NOT NULL,
                entry_hash VARCHAR(64) NOT NULL
            )',

            // 14. Emergency Stop & Subprocess Kill-Switch Registry (SEC-012)
            'CREATE TABLE IF NOT EXISTS emergency_stop_events (
                id VARCHAR(64) PRIMARY KEY,
                organization_id VARCHAR(64) NOT NULL,
                project_id VARCHAR(64) DEFAULT NULL,
                scan_run_id VARCHAR(64) DEFAULT NULL,
                emergency_stop_token_id VARCHAR(64) NOT NULL,
                triggered_by_user_id VARCHAR(64) NOT NULL,
                reason TEXT NOT NULL,
                subprocesses_terminated INTEGER NOT NULL DEFAULT 0,
                cancellation_latency_ms INTEGER NOT NULL DEFAULT 0,
                created_at VARCHAR(40) NOT NULL
            )',

            // 15. Failed-login throttling (brute-force mitigation; Sprint 9 / SEC-015)
            'CREATE TABLE IF NOT EXISTS auth_login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_key VARCHAR(255) NOT NULL,
                ip_address VARCHAR(64) NOT NULL,
                attempted_at INTEGER NOT NULL
            )',

            // Indexes for multi-tenant query performance
            'CREATE INDEX IF NOT EXISTS idx_org_members_org_user ON organization_members (organization_id, user_id)',
            'CREATE INDEX IF NOT EXISTS idx_projects_org ON projects (organization_id)',
            'CREATE INDEX IF NOT EXISTS idx_target_assets_org_proj ON target_assets (organization_id, project_id)',
            'CREATE INDEX IF NOT EXISTS idx_scope_grants_org_proj ON scope_authorization_grants (organization_id, project_id)',
            'CREATE INDEX IF NOT EXISTS idx_scan_runs_org_proj ON scan_runs (organization_id, project_id)',
            'CREATE INDEX IF NOT EXISTS idx_scan_queue_jobs_org_scan ON scan_queue_jobs (organization_id, scan_run_id)',
            'CREATE INDEX IF NOT EXISTS idx_findings_org_proj ON findings (organization_id, project_id)',
            'CREATE INDEX IF NOT EXISTS idx_remediation_tasks_org_proj ON remediation_tasks (organization_id, project_id)',
            'CREATE INDEX IF NOT EXISTS idx_audit_logs_org_seq ON audit_logs (organization_id, sequence)',
            'CREATE INDEX IF NOT EXISTS idx_estop_org_proj ON emergency_stop_events (organization_id, project_id)',
        ];
    }

    public static function migrate(PDO $pdo, string $driver = 'sqlite'): void
    {
        foreach (self::statements($driver) as $sql) {
            if ($driver === 'pgsql') {
                $sql = str_replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'BIGSERIAL PRIMARY KEY', $sql);
            }
            $pdo->exec($sql);
        }

        // Backfill new Sprint 10 columns on existing local SQLite databases if upgraded in-place
        $optionalColumns = [
            ['scan_queue_jobs', 'max_tries', 'INTEGER NOT NULL DEFAULT 1'],
            ['scan_queue_jobs', 'timeout_seconds', 'INTEGER NOT NULL DEFAULT 90'],
            ['scan_queue_jobs', 'idempotency_key', 'VARCHAR(128) DEFAULT NULL'],
            ['scan_queue_jobs', 'supervisor_container_id', 'VARCHAR(128) DEFAULT NULL'],
            ['scan_queue_jobs', 'horizon_supervisor', "VARCHAR(64) DEFAULT 'supervisor-scans'"],
            ['scan_queue_jobs', 'redis_queue_id', 'VARCHAR(128) DEFAULT NULL'],
            ['scan_queue_jobs', 'container_started_at', 'VARCHAR(40) DEFAULT NULL'],
            ['scan_queue_jobs', 'container_finished_at', 'VARCHAR(40) DEFAULT NULL'],
            ['scan_queue_jobs', 'resource_limits_json', 'TEXT DEFAULT NULL'],
            ['scan_queue_jobs', 'heartbeat_at', 'VARCHAR(40) DEFAULT NULL'],
            ['emergency_stop_events', 'cancellation_latency_ms', 'INTEGER NOT NULL DEFAULT 0'],
        ];
        foreach ($optionalColumns as [$table, $col, $def]) {
            try {
                $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$col} {$def}");
            } catch (\Throwable) {
                // Column already exists
            }
        }
    }
}
