<?php

declare(strict_types=1);

namespace App\Services;

use App\Jobs\DispatchApprovedNotificationJob;
use App\Jobs\ExecuteAuthorizedScanJob;
use App\Jobs\ExecuteRecheckComparisonJob;
use App\Support\DatabaseManager;
use App\Support\RuntimeMode;
use PDO;
use RuntimeException;

require_once __DIR__ . '/../Support/DatabaseManager.php';
require_once __DIR__ . '/../Support/RuntimeMode.php';
require_once __DIR__ . '/WorkerSupervisorClient.php';
require_once __DIR__ . '/../Jobs/ExecuteAuthorizedScanJob.php';
require_once __DIR__ . '/../Jobs/ExecuteRecheckComparisonJob.php';
require_once __DIR__ . '/../Jobs/DispatchApprovedNotificationJob.php';

/**
 * HegoSentinel Stage 2 / Sprint 10 Security Platform Service
 * Implements all 14 backend modules with server-side multi-tenant & project isolation (SEC-011),
 * RBAC enforcement, EmergencyStopRegistry (SEC-012), Approved Notifications (SEC-013),
 * WorkerSupervisorClient delegation (S10-03 / S10-04), and SHA-256 hash-chained Audit Logs.
 */
final class SecurityPlatformService
{
    private const BLOCKED_PUBLIC_NOTIFICATION_SINKS = [
        'slack.com',
        'hooks.slack.com',
        'discord.com',
        'discordapp.com',
        'webhook.site',
        'requestbin',
        'pastebin.com',
        'ngrok.io',
        'ngrok-free.app',
        'telegram.org',
    ];

    private PDO $pdo;

    public function __construct(?PDO $pdo = null)
    {
        $this->pdo = $pdo ?? DatabaseManager::connection();
        $this->ensureSeeded();
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    public function seedInitialStateIfEmpty(): void
    {
        $this->ensureSeeded();
    }

    public function ensureSeeded(): void
    {
        // SECURITY (B1): the demo dataset ships KNOWN credentials. It is only ever created when the
        // operator explicitly enables demo mode via the process environment (never via HTTP input),
        // and never when APP_ENV=production. An empty production database stays empty.
        if (!RuntimeMode::demoModeEnabled()) {
            return;
        }

        $count = (int) $this->pdo->query('SELECT COUNT(*) FROM organizations')->fetchColumn();
        if ($count > 0) {
            return;
        }

        $now = gmdate('Y-m-d\TH:i:s\Z');

        // 1. Seed Primary Organization (org-hegoweb-sec) & Isolated Secondary Tenant (org-beta-isolated)
        $stmtOrg = $this->pdo->prepare(
            'INSERT INTO organizations (id, slug, name, verified_notification_domains_json, created_by_user_id, created_at)
             VALUES (:id, :slug, :name, :domains, :creator, :created_at)'
        );
        $stmtOrg->execute([
            ':id' => 'org-hegoweb-sec',
            ':slug' => 'hegoweb-security',
            ':name' => 'HegoWeb Security Engineering',
            ':domains' => json_encode(['hegoweb.local', 'security.example.test']),
            ':creator' => 'usr-owner-01',
            ':created_at' => $now,
        ]);
        $stmtOrg->execute([
            ':id' => 'org-beta-isolated',
            ':slug' => 'beta-tenant-isolated',
            ':name' => 'Beta FinTech Corp (Isolated Tenant)',
            ':domains' => json_encode(['betafintech.example.test']),
            ':creator' => 'usr-beta-owner',
            ':created_at' => $now,
        ]);

        // 2. Seed Users across RBAC roles (owner, security_lead, developer, viewer) + Beta tenant owner
        $stmtUser = $this->pdo->prepare(
            'INSERT INTO users (id, email, name, password_hash, preferred_locale, mfa_enabled, created_at, updated_at)
             VALUES (:id, :email, :name, :hash, :locale, :mfa, :created_at, :updated_at)'
        );
        $defaultUsers = [
            ['usr-owner-01', 'admin@hegoweb.local', 'Demo Owner', 'HegoSentinel!2026', 'tr', 1],
            ['usr-seclead-01', 'sec-lead@hegoweb.local', 'Demo Security Lead', 'HegoSentinel!2026', 'tr', 1],
            ['usr-dev-01', 'dev@hegoweb.local', 'Demo Developer', 'HegoSentinel!2026', 'tr', 0],
            ['usr-viewer-01', 'auditor@hegoweb.local', 'Demo Viewer', 'HegoSentinel!2026', 'en', 0],
            ['usr-beta-owner', 'owner@betafintech.example.test', 'Beta Tenant Owner', 'HegoSentinel!2026', 'en', 1],
        ];
        foreach ($defaultUsers as [$uid, $email, $name, $pass, $locale, $mfa]) {
            $stmtUser->execute([
                ':id' => $uid,
                ':email' => $email,
                ':name' => $name,
                ':hash' => password_hash($pass, PASSWORD_BCRYPT),
                ':locale' => $locale,
                ':mfa' => $mfa,
                ':created_at' => $now,
                ':updated_at' => $now,
            ]);
        }

        // 3. Seed Organization Memberships (RBAC)
        $stmtMember = $this->pdo->prepare(
            'INSERT INTO organization_members (id, organization_id, user_id, role, allowed_project_ids_json, created_at)
             VALUES (:id, :org_id, :user_id, :role, :projects, :created_at)'
        );
        $members = [
            ['mem-01', 'org-hegoweb-sec', 'usr-owner-01', 'owner', ['proj-laravel-commerce', 'proj-nextjs-portal', 'proj-demo-sandbox']],
            ['mem-02', 'org-hegoweb-sec', 'usr-seclead-01', 'security_lead', ['proj-laravel-commerce', 'proj-nextjs-portal', 'proj-demo-sandbox']],
            ['mem-03', 'org-hegoweb-sec', 'usr-dev-01', 'developer', ['proj-laravel-commerce', 'proj-nextjs-portal']],
            ['mem-04', 'org-hegoweb-sec', 'usr-viewer-01', 'viewer', ['proj-laravel-commerce', 'proj-demo-sandbox']],
            ['mem-05', 'org-beta-isolated', 'usr-beta-owner', 'owner', ['proj-beta-core']],
        ];
        foreach ($members as [$mid, $orgId, $uid, $role, $projIds]) {
            $stmtMember->execute([
                ':id' => $mid,
                ':org_id' => $orgId,
                ':user_id' => $uid,
                ':role' => $role,
                ':projects' => json_encode($projIds),
                ':created_at' => $now,
            ]);
        }

        // 4. Seed Projects (Real vs Demo explicitly separated via is_demo)
        $stmtProj = $this->pdo->prepare(
            'INSERT INTO projects (id, organization_id, name, slug, environment, stack_json, description, is_demo, created_by_user_id, created_at)
             VALUES (:id, :org_id, :name, :slug, :env, :stack, :desc, :is_demo, :creator, :created_at)'
        );
        $projects = [
            [
                'proj-laravel-commerce',
                'org-hegoweb-sec',
                'Laravel Order & Checkout API',
                'laravel-order-api',
                'staging',
                ['laravel', 'generic-web'],
                'Production-mirror Laravel 11 API + Composer lockfile & SQL query surface target.',
                0,
                'usr-owner-01',
            ],
            [
                'proj-nextjs-portal',
                'org-hegoweb-sec',
                'Next.js Customer Portal',
                'nextjs-customer-portal',
                'staging',
                ['nextjs', 'generic-web'],
                'App Router customer storefront tested for CSP, cookie prefix integrity, and DOM XSS sinks.',
                0,
                'usr-seclead-01',
            ],
            [
                'proj-demo-sandbox',
                'org-hegoweb-sec',
                'Synthetic Offline Demo Target (Demo)',
                'synthetic-demo-sandbox',
                'local-demo',
                ['laravel', 'nextjs', 'generic-web'],
                'Deterministic offline synthetic baseline/patched demonstration target.',
                1,
                'usr-owner-01',
            ],
            [
                'proj-beta-core',
                'org-beta-isolated',
                'Beta Isolated Banking Core',
                'beta-banking-core',
                'staging',
                ['laravel'],
                'Confidential project belonging to org-beta-isolated for cross-tenant isolation testing.',
                0,
                'usr-beta-owner',
            ],
        ];
        foreach ($projects as [$pid, $orgId, $name, $slug, $env, $stack, $desc, $isDemo, $creator]) {
            $stmtProj->execute([
                ':id' => $pid,
                ':org_id' => $orgId,
                ':name' => $name,
                ':slug' => $slug,
                ':env' => $env,
                ':stack' => json_encode($stack),
                ':desc' => $desc,
                ':is_demo' => $isDemo,
                ':creator' => $creator,
                ':created_at' => $now,
            ]);
        }

        // 5. Seed Target Assets
        $stmtAsset = $this->pdo->prepare(
            'INSERT INTO target_assets (id, organization_id, project_id, asset_type, scheme, hostname, port, path_prefix, repository_path, domain_ownership_verified, domain_verification_token, domain_verified_at, created_at)
             VALUES (:id, :org_id, :proj_id, :type, :scheme, :host, :port, :path, :repo, :verified, :token, :verified_at, :created_at)'
        );
        $stmtAsset->execute([
            ':id' => 'ast-laravel-web',
            ':org_id' => 'org-hegoweb-sec',
            ':proj_id' => 'proj-laravel-commerce',
            ':type' => 'domain',
            ':scheme' => 'https',
            ':host' => 'demo.example.test',
            ':port' => 443,
            ':path' => '/',
            ':repo' => 'examples/synthetic-targets/laravel-app',
            ':verified' => 1,
            ':token' => 'hegosentinel-dns-verify=9f8a7b6c5d4e3f2a1b',
            ':verified_at' => $now,
            ':created_at' => $now,
        ]);
        $stmtAsset->execute([
            ':id' => 'ast-nextjs-web',
            ':org_id' => 'org-hegoweb-sec',
            ':proj_id' => 'proj-nextjs-portal',
            ':type' => 'domain',
            ':scheme' => 'https',
            ':host' => 'demo.example.test',
            ':port' => 443,
            ':path' => '/',
            ':repo' => 'examples/synthetic-targets/nextjs-app',
            ':verified' => 1,
            ':token' => 'hegosentinel-dns-verify=3c4d5e6f7a8b9c0d1e',
            ':verified_at' => $now,
            ':created_at' => $now,
        ]);

        // 6. Seed Active Scope Authorization Grants
        $stmtGrant = $this->pdo->prepare(
            'INSERT INTO scope_authorization_grants (
                grant_id, organization_id, project_id, scope_version, profile, owner_name,
                authorization_statement, domain_control_proof, written_permission_ref, emergency_contact,
                issued_at, expires_at, window_start_at, window_end_at, max_request_budget,
                allowed_methods_json, allowed_checks_json, targets_json, allowed_repositories_json,
                approved_by_user_id, status, created_at
            ) VALUES (
                :grant_id, :org_id, :proj_id, :scope_version, :profile, :owner,
                :statement, :proof, :written_ref, :contact,
                :issued_at, :expires_at, :win_start, :win_end, :budget,
                :methods, :checks, :targets, :repos,
                :approved_by, :status, :created_at
            )'
        );

        $stmtGrant->execute([
            ':grant_id' => 'GRANT-LARAVEL-2026-001',
            ':org_id' => 'org-hegoweb-sec',
            ':proj_id' => 'proj-laravel-commerce',
            ':scope_version' => 1,
            ':profile' => 'local-demo',
            ':owner' => 'Demo Owner',
            ':statement' => 'Explicit written authorization for passive web header/cookie/TLS observation and offline Semgrep/Trivy source scan.',
            ':proof' => 'dns-txt:hegosentinel-dns-verify=9f8a7b6c5d4e3f2a1b',
            ':written_ref' => 'AUTH-DOC-2026-LARAVEL-01',
            ':contact' => 'sec-lead@hegoweb.local',
            ':issued_at' => '2026-01-01T00:00:00.000Z',
            ':expires_at' => '2030-12-31T23:59:59.000Z',
            ':win_start' => '2026-01-01T00:00:00.000Z',
            ':win_end' => '2030-12-31T23:59:59.000Z',
            ':budget' => 10,
            ':methods' => json_encode(['GET', 'HEAD']),
            ':checks' => json_encode(['WEB-HEADER-001', 'WEB-COOKIE-001', 'WEB-TLS-001', 'WEB-REDIRECT-001', 'CODE-001', 'DEP-001']),
            ':targets' => json_encode([['scheme' => 'https', 'hostname' => 'demo.example.test', 'port' => 443, 'path_prefix' => '/']]),
            ':repos' => json_encode([RuntimeMode::resolveRepositoryPath('examples/synthetic-targets/laravel-app')]),
            ':approved_by' => 'usr-owner-01',
            ':status' => 'active',
            ':created_at' => $now,
        ]);

        $stmtGrant->execute([
            ':grant_id' => 'GRANT-NEXTJS-2026-001',
            ':org_id' => 'org-hegoweb-sec',
            ':proj_id' => 'proj-nextjs-portal',
            ':scope_version' => 1,
            ':profile' => 'local-demo',
            ':owner' => 'Demo Security Lead',
            ':statement' => 'Written authorization for Next.js portal passive headers and source/lockfile assessment.',
            ':proof' => 'dns-txt:hegosentinel-dns-verify=3c4d5e6f7a8b9c0d1e',
            ':written_ref' => 'AUTH-DOC-2026-NEXTJS-01',
            ':contact' => 'sec-lead@hegoweb.local',
            ':issued_at' => '2026-01-01T00:00:00.000Z',
            ':expires_at' => '2030-12-31T23:59:59.000Z',
            ':win_start' => '2026-01-01T00:00:00.000Z',
            ':win_end' => '2030-12-31T23:59:59.000Z',
            ':budget' => 10,
            ':methods' => json_encode(['GET', 'HEAD']),
            ':checks' => json_encode(['WEB-HEADER-001', 'WEB-COOKIE-001', 'WEB-TLS-001', 'WEB-REDIRECT-001', 'CODE-001', 'DEP-001']),
            ':targets' => json_encode([['scheme' => 'https', 'hostname' => 'demo.example.test', 'port' => 443, 'path_prefix' => '/']]),
            ':repos' => json_encode([RuntimeMode::resolveRepositoryPath('examples/synthetic-targets/nextjs-app')]),
            ':approved_by' => 'usr-seclead-01',
            ':status' => 'active',
            ':created_at' => $now,
        ]);

        $this->appendAuditLog(
            'org-hegoweb-sec',
            'proj-laravel-commerce',
            'usr-owner-01',
            'owner',
            'platform_initialized',
            'allow',
            'Initialized HegoSentinel multi-tenant security platform schema and RBAC roles'
        );

        // Execute initial real baseline scan for proj-laravel-commerce so the dashboard & tables have real Semgrep/Trivy findings immediately
        try {
            $this->createAndExecuteScan(
                $this->getPrincipalById('usr-owner-01', 'org-hegoweb-sec'),
                [
                    'project_id' => 'proj-laravel-commerce',
                    'grant_id' => 'GRANT-LARAVEL-2026-001',
                    'mode' => 'offline-fixture',
                    'fixture_variant' => 'baseline',
                    'repository_path' => 'examples/synthetic-targets/laravel-app',
                    'data_source' => 'real_scan',
                ]
            );
        } catch (\Throwable) {
            // Ignore if CLI bridge fails during minimal unit bootstrap
        }
    }

    /**
     * Module 1: Authentication (Login, Register, Logout, Password Reset, Session Validation)
     * @return array<string, mixed>
     */
    public function login(string $email, string $password, string $ip = '127.0.0.1', string $ua = 'HegoSentinel-Web'): array
    {
        $emailKey = strtolower(trim($email));
        $this->assertLoginNotThrottled($emailKey, $ip);

        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(:email) LIMIT 1');
        $stmt->execute([':email' => trim($email)]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, (string) $user['password_hash'])) {
            $this->recordFailedLogin($emailKey, $ip);
            throw new RuntimeException('Invalid email or password credentials', 401);
        }

        $this->pdo->prepare('DELETE FROM auth_login_attempts WHERE email_key = :k')->execute([':k' => $emailKey]);
        $memStmt = $this->pdo->prepare('SELECT * FROM organization_members WHERE user_id = :uid LIMIT 1');
        $memStmt->execute([':uid' => $user['id']]);
        $membership = $memStmt->fetch();
        if (!$membership) {
            throw new RuntimeException('User has no active organization membership', 403);
        }

        $rawToken = 'hst_' . bin2hex(random_bytes(24));
        $tokenHash = hash('sha256', $rawToken);
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $expiresAt = gmdate('Y-m-d\TH:i:s\Z', time() + 86400);

        $ins = $this->pdo->prepare(
            'INSERT INTO user_sessions (token_hash, user_id, organization_id, ip_address, user_agent, issued_at, expires_at)
             VALUES (:th, :uid, :org, :ip, :ua, :issued, :expires)'
        );
        $ins->execute([
            ':th' => $tokenHash,
            ':uid' => $user['id'],
            ':org' => $membership['organization_id'],
            ':ip' => substr($ip, 0, 64),
            ':ua' => substr($ua, 0, 255),
            ':issued' => $now,
            ':expires' => $expiresAt,
        ]);

        $principal = $this->getPrincipalById((string) $user['id'], (string) $membership['organization_id']);
        $this->appendAuditLog(
            $principal['organization_id'],
            null,
            $principal['user_id'],
            $principal['role'],
            'auth_login',
            'allow',
            'Authenticated user session issued for ' . $user['email']
        );

        return [
            'token' => $rawToken,
            'expires_at' => $expiresAt,
            'principal' => $principal,
        ];
    }

    /**
     * Brute-force mitigation (SEC-015): 5 failures / 15 min per account, 30 failures / 15 min per source IP.
     */
    private function assertLoginNotThrottled(string $emailKey, string $ip): void
    {
        $since = time() - 900;
        $byEmail = $this->pdo->prepare('SELECT COUNT(*) FROM auth_login_attempts WHERE email_key = :k AND attempted_at >= :s');
        $byEmail->execute([':k' => $emailKey, ':s' => $since]);
        $byIp = $this->pdo->prepare('SELECT COUNT(*) FROM auth_login_attempts WHERE ip_address = :ip AND attempted_at >= :s');
        $byIp->execute([':ip' => substr($ip, 0, 64), ':s' => $since]);
        if ((int) $byEmail->fetchColumn() >= 5 || (int) $byIp->fetchColumn() >= 30) {
            throw new RuntimeException('Too many failed login attempts; try again later', 429);
        }
    }

    private function recordFailedLogin(string $emailKey, string $ip): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_login_attempts (email_key, ip_address, attempted_at) VALUES (:k, :ip, :t)'
        )->execute([':k' => substr($emailKey, 0, 255), ':ip' => substr($ip, 0, 64), ':t' => time()]);
        $this->pdo->prepare('DELETE FROM auth_login_attempts WHERE attempted_at < :old')->execute([':old' => time() - 86400]);
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function register(array $payload): array
    {
        $email = trim((string) ($payload['email'] ?? ''));
        $name = trim((string) ($payload['name'] ?? ''));
        $password = (string) ($payload['password'] ?? '');
        $orgName = trim((string) ($payload['organization_name'] ?? ($name . ' Security Org')));
        $locale = in_array(($payload['preferred_locale'] ?? 'tr'), ['tr', 'en'], true)
            ? (string) ($payload['preferred_locale'] ?? 'tr')
            : 'tr';

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($name) < 2 || strlen($password) < 10) {
            throw new RuntimeException('Valid email, name (>=2 chars), and password (>=10 chars) are required', 422);
        }

        $exists = $this->pdo->prepare('SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(:email)');
        $exists->execute([':email' => $email]);
        if ((int) $exists->fetchColumn() > 0) {
            throw new RuntimeException('Email address is already registered', 409);
        }

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $userId = 'usr-' . bin2hex(random_bytes(6));
        // SECURITY (B1/F-09): self-registration ALWAYS creates a brand-new organization owned by the
        // new user. Client-supplied organization_id / role / allowed_project_ids are ignored so an
        // anonymous caller can never join (or become owner of) an existing tenant.
        $orgId = 'org-' . bin2hex(random_bytes(6));
        $role = 'owner';

        $this->pdo->prepare(
            'INSERT INTO users (id, email, name, password_hash, preferred_locale, mfa_enabled, created_at, updated_at)
             VALUES (:id, :email, :name, :hash, :locale, 0, :c, :u)'
        )->execute([
            ':id' => $userId,
            ':email' => $email,
            ':name' => $name,
            ':hash' => password_hash($password, PASSWORD_BCRYPT),
            ':locale' => $locale,
            ':c' => $now,
            ':u' => $now,
        ]);

        // Create organization if new
        $orgCheck = $this->pdo->prepare('SELECT COUNT(*) FROM organizations WHERE id = :id');
        $orgCheck->execute([':id' => $orgId]);
        if ((int) $orgCheck->fetchColumn() === 0) {
            $emailDomain = substr(strrchr($email, '@') ?: '@hegoweb.local', 1);
            $this->pdo->prepare(
                'INSERT INTO organizations (id, slug, name, verified_notification_domains_json, created_by_user_id, created_at)
                 VALUES (:id, :slug, :name, :domains, :creator, :created_at)'
            )->execute([
                ':id' => $orgId,
                ':slug' => strtolower(preg_replace('/[^a-zA-Z0-9]+/', '-', $orgName) ?: 'org') . '-' . substr($orgId, -4),
                ':name' => $orgName,
                ':domains' => json_encode([$emailDomain]),
                ':creator' => $userId,
                ':created_at' => $now,
            ]);
        }

        $this->pdo->prepare(
            'INSERT INTO organization_members (id, organization_id, user_id, role, allowed_project_ids_json, created_at)
             VALUES (:id, :org_id, :uid, :role, :projs, :c)'
        )->execute([
            ':id' => 'mem-' . bin2hex(random_bytes(6)),
            ':org_id' => $orgId,
            ':uid' => $userId,
            ':role' => $role,
            ':projs' => json_encode([]),
            ':c' => $now,
        ]);

        return $this->login($email, $password);
    }

    public function logout(string $rawToken): void
    {
        $tokenHash = hash('sha256', $rawToken);
        $stmt = $this->pdo->prepare('UPDATE user_sessions SET revoked_at = :now WHERE token_hash = :th');
        $stmt->execute([
            ':now' => gmdate('Y-m-d\TH:i:s\Z'),
            ':th' => $tokenHash,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    public function requestPasswordReset(string $email): array
    {
        $stmt = $this->pdo->prepare('SELECT id, email FROM users WHERE LOWER(email) = LOWER(:email) LIMIT 1');
        $stmt->execute([':email' => trim($email)]);
        $user = $stmt->fetch();
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $expiresAt = gmdate('Y-m-d\TH:i:s\Z', time() + 1800);

        if ($user) {
            $rawReset = 'hs_rst_' . bin2hex(random_bytes(16));
            $this->pdo->prepare('DELETE FROM password_reset_tokens WHERE email = :email')
                ->execute([':email' => $user['email']]);
            $this->pdo->prepare(
                'INSERT INTO password_reset_tokens (email, token_hash, expires_at, created_at)
                 VALUES (:email, :th, :exp, :c)'
            )->execute([
                ':email' => $user['email'],
                ':th' => hash('sha256', $rawReset),
                ':exp' => $expiresAt,
                ':c' => $now,
            ]);
        }

        return [
            'status' => 'accepted',
            'message' => 'If the account exists in an authorized organization, a time-limited reset token has been recorded.',
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Resolves the authenticated principal from a server-issued Bearer session token ONLY.
     *
     * SECURITY (B1): there is intentionally no header/query/body based identity fallback. Any
     * client-controllable value (e.g. the removed `X-Demo-Principal`) must never determine identity.
     * @return array<string, mixed>
     */
    public function authenticateRequest(?string $bearerToken): array
    {
        if ($bearerToken !== null && trim($bearerToken) !== '') {
            $clean = preg_replace('/^Bearer\s+/i', '', trim($bearerToken)) ?? '';
            $tokenHash = hash('sha256', $clean);
            $stmt = $this->pdo->prepare(
                'SELECT * FROM user_sessions WHERE token_hash = :th AND revoked_at IS NULL LIMIT 1'
            );
            $stmt->execute([':th' => $tokenHash]);
            $session = $stmt->fetch();
            if (!$session) {
                throw new RuntimeException('Invalid or revoked session token', 401);
            }
            if (strtotime((string) $session['expires_at']) <= time()) {
                throw new RuntimeException('Session token has expired', 401);
            }
            return $this->getPrincipalById((string) $session['user_id'], (string) $session['organization_id']);
        }

        throw new RuntimeException('Authentication required: missing Bearer token', 401);
    }

    /**
     * @return array<string, mixed>
     */
    public function getPrincipalById(string $userId, string $organizationId): array
    {
        $uStmt = $this->pdo->prepare('SELECT id, email, name, preferred_locale, mfa_enabled FROM users WHERE id = :id LIMIT 1');
        $uStmt->execute([':id' => $userId]);
        $user = $uStmt->fetch();
        if (!$user) {
            throw new RuntimeException('User principal not found', 401);
        }

        $mStmt = $this->pdo->prepare(
            'SELECT role, allowed_project_ids_json FROM organization_members WHERE user_id = :uid AND organization_id = :org LIMIT 1'
        );
        $mStmt->execute([':uid' => $userId, ':org' => $organizationId]);
        $mem = $mStmt->fetch();
        if (!$mem) {
            throw new RuntimeException('User is not a member of organization ' . $organizationId, 403);
        }

        $oStmt = $this->pdo->prepare('SELECT id, slug, name, verified_notification_domains_json FROM organizations WHERE id = :org LIMIT 1');
        $oStmt->execute([':org' => $organizationId]);
        $org = $oStmt->fetch();

        return [
            'user_id' => (string) $user['id'],
            'email' => (string) $user['email'],
            'name' => (string) $user['name'],
            'preferred_locale' => (string) $user['preferred_locale'],
            'mfa_enabled' => (bool) $user['mfa_enabled'],
            'organization_id' => $organizationId,
            'organization_name' => (string) ($org['name'] ?? $organizationId),
            'organization_slug' => (string) ($org['slug'] ?? $organizationId),
            'verified_notification_domains' => json_decode((string) ($org['verified_notification_domains_json'] ?? '[]'), true) ?: [],
            'role' => (string) $mem['role'],
            'project_ids' => json_decode((string) $mem['allowed_project_ids_json'], true) ?: [],
        ];
    }

    /**
     * Module 3: RBAC & Multi-Tenant Isolation Enforcement (SEC-011)
     * Mirrors packages/policy-engine authorizeTenantResourceAccess & authorizeReportTenantAccess.
     * @param array<string, mixed> $principal
     */
    public function assertTenantAndRoleAccess(
        array $principal,
        string $resourceOrgId,
        ?string $resourceProjectId,
        string $action
    ): void {
        if ($principal['organization_id'] !== $resourceOrgId) {
            // The denial is logged in the CALLER's tenant trail. It must never disclose the foreign
            // organization/project identifiers (oracle for BOLA enumeration); a short one-way
            // reference keeps incidents correlatable for operators without revealing the ids.
            $this->appendAuditLog(
                (string) $principal['organization_id'],
                null,
                (string) $principal['user_id'],
                (string) $principal['role'],
                $action,
                'deny',
                sprintf(
                    'Cross-organization access denied: principal cannot access a resource of a different organization (foreign_ref=%s) (SEC-011)',
                    substr(hash('sha256', $resourceOrgId), 0, 12)
                )
            );
            throw new RuntimeException('Cross-organization access denied (SEC-011)', 403);
        }

        $role = (string) $principal['role'];
        $allowedProjects = (array) ($principal['project_ids'] ?? []);
        if ($resourceProjectId !== null && $role !== 'owner' && !in_array($resourceProjectId, $allowedProjects, true)) {
            $this->appendAuditLog(
                $resourceOrgId,
                $resourceProjectId,
                (string) $principal['user_id'],
                $role,
                $action,
                'deny',
                sprintf(
                    'Cross-project access denied: principal "%s" is not authorized for project "%s" (SEC-011)',
                    $principal['user_id'],
                    $resourceProjectId
                )
            );
            throw new RuntimeException('Cross-project access denied (SEC-011)', 403);
        }

        $roleMatrix = [
            'owner' => [
                'read_report', 'trigger_scan', 'approve_scope', 'suppress_finding',
                'Emergency_stop', 'emergency_stop', 'export_artifact', 'manage_project',
                'manage_remediation', 'approve_notification', 'manage_team', 'read_audit',
            ],
            'security_lead' => [
                'read_report', 'trigger_scan', 'approve_scope', 'suppress_finding',
                'emergency_stop', 'export_artifact', 'manage_project',
                'manage_remediation', 'approve_notification', 'read_audit',
            ],
            'developer' => [
                'read_report', 'trigger_scan', 'export_artifact', 'manage_remediation',
            ],
            'viewer' => [
                'read_report',
            ],
        ];

        $permitted = $roleMatrix[$role] ?? [];
        if (!in_array($action, $permitted, true)) {
            $this->appendAuditLog(
                $resourceOrgId,
                $resourceProjectId,
                (string) $principal['user_id'],
                $role,
                $action,
                'deny',
                sprintf('RBAC denied: role "%s" is not permitted to perform "%s" (SEC-011)', $role, $action)
            );
            throw new RuntimeException(sprintf('RBAC denied: role "%s" cannot perform "%s" (SEC-011)', $role, $action), 403);
        }
    }

    /**
     * Module 2 & 9 (Settings / Team): List organization members & settings
     * @param array<string, mixed> $principal
     * @return array<string, mixed>
     */
    public function getOrganizationOverview(array $principal): array
    {
        $orgId = (string) $principal['organization_id'];
        $stmt = $this->pdo->prepare(
            'SELECT m.id AS membership_id, m.role, m.allowed_project_ids_json, m.created_at,
                    u.id AS user_id, u.email, u.name, u.preferred_locale, u.mfa_enabled
             FROM organization_members m
             JOIN users u ON u.id = m.user_id
             WHERE m.organization_id = :org
             ORDER BY m.created_at ASC'
        );
        $stmt->execute([':org' => $orgId]);
        $members = [];
        foreach ($stmt->fetchAll() as $row) {
            $members[] = [
                'membership_id' => $row['membership_id'],
                'user_id' => $row['user_id'],
                'email' => $row['email'],
                'name' => $row['name'],
                'role' => $row['role'],
                'preferred_locale' => $row['preferred_locale'],
                'mfa_enabled' => (bool) $row['mfa_enabled'],
                'allowed_project_ids' => json_decode((string) $row['allowed_project_ids_json'], true) ?: [],
                'created_at' => $row['created_at'],
            ];
        }

        return [
            'organization_id' => $orgId,
            'organization_name' => $principal['organization_name'],
            'organization_slug' => $principal['organization_slug'],
            'verified_notification_domains' => $principal['verified_notification_domains'],
            'members' => $members,
        ];
    }

    /**
     * Module 2 & 3: Invite or Update Organization Team Member & RBAC Role
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function inviteOrUpdateMember(array $principal, array $payload): array
    {
        $orgId = (string) $principal['organization_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, null, 'manage_team');

        $role = trim((string) ($payload['role'] ?? 'viewer'));
        if (!in_array($role, ['owner', 'security_lead', 'developer', 'viewer'], true)) {
            throw new RuntimeException('Invalid RBAC role', 422);
        }

        $email = trim((string) ($payload['email'] ?? ''));
        $name = trim((string) ($payload['name'] ?? 'Team Member'));
        $allowedProjectIds = is_array($payload['allowed_project_ids'] ?? null)
            ? array_values($payload['allowed_project_ids'])
            : [];

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('Valid email address is required', 422);
        }

        // Project scopes may only reference projects of THIS organization (no cross-tenant grants).
        $ownProjects = $this->pdo->prepare('SELECT id FROM projects WHERE organization_id = :org');
        $ownProjects->execute([':org' => $orgId]);
        $ownProjectIds = array_map('strval', $ownProjects->fetchAll(PDO::FETCH_COLUMN));
        $allowedProjectIds = array_values(array_unique(array_map('strval', $allowedProjectIds)));
        foreach ($allowedProjectIds as $pid) {
            if (!in_array($pid, $ownProjectIds, true)) {
                throw new RuntimeException('allowed_project_ids must reference projects of this organization', 422);
            }
        }

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $uStmt = $this->pdo->prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(:email) LIMIT 1');
        $uStmt->execute([':email' => $email]);
        $user = $uStmt->fetch();

        if (!$user) {
            // SECURITY: no built-in default password. The inviter must supply an initial password
            // (>= 10 chars) that is communicated out-of-band; mfa is NOT claimed as enabled.
            $initialPassword = (string) ($payload['password'] ?? '');
            if (strlen($initialPassword) < 10) {
                throw new RuntimeException('An initial password of at least 10 characters is required for new team members', 422);
            }
            $userId = 'usr-' . bin2hex(random_bytes(5));
            $this->pdo->prepare(
                'INSERT INTO users (id, email, name, password_hash, preferred_locale, mfa_enabled, created_at, updated_at)
                 VALUES (:id, :email, :name, :hash, \'tr\', 0, :c, :u)'
            )->execute([
                ':id' => $userId,
                ':email' => $email,
                ':name' => $name,
                ':hash' => password_hash($initialPassword, PASSWORD_BCRYPT),
                ':c' => $now,
                ':u' => $now,
            ]);
        } else {
            $userId = (string) $user['id'];
        }

        $mStmt = $this->pdo->prepare('SELECT * FROM organization_members WHERE organization_id = :org AND user_id = :uid LIMIT 1');
        $mStmt->execute([':org' => $orgId, ':uid' => $userId]);
        $existingMem = $mStmt->fetch();

        if ($existingMem) {
            $this->pdo->prepare(
                'UPDATE organization_members SET role = :role, allowed_project_ids_json = :projs WHERE id = :id'
            )->execute([
                ':role' => $role,
                ':projs' => json_encode($allowedProjectIds),
                ':id' => $existingMem['id'],
            ]);
        } else {
            $this->pdo->prepare(
                'INSERT INTO organization_members (id, organization_id, user_id, role, allowed_project_ids_json, created_at)
                 VALUES (:id, :org, :uid, :role, :projs, :c)'
            )->execute([
                ':id' => 'mem-' . bin2hex(random_bytes(5)),
                ':org' => $orgId,
                ':uid' => $userId,
                ':role' => $role,
                ':projs' => json_encode($allowedProjectIds),
                ':c' => $now,
            ]);
        }

        $this->appendAuditLog(
            $orgId,
            null,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'manage_team',
            'allow',
            sprintf('Configured RBAC role "%s" for %s (%s)', $role, $email, $userId)
        );

        return $this->getOrganizationOverview($principal);
    }

    /**
     * Module 4: Projects & Target Assets Management
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listProjects(array $principal, ?bool $includeDemo = true): array
    {
        $orgId = (string) $principal['organization_id'];
        $role = (string) $principal['role'];
        $allowedProjs = (array) ($principal['project_ids'] ?? []);

        $stmt = $this->pdo->prepare('SELECT * FROM projects WHERE organization_id = :org ORDER BY is_demo ASC, created_at DESC');
        $stmt->execute([':org' => $orgId]);
        $rows = $stmt->fetchAll();

        $result = [];
        foreach ($rows as $row) {
            $pid = (string) $row['id'];
            if ($role !== 'owner' && !in_array($pid, $allowedProjs, true)) {
                continue;
            }
            if ($includeDemo === false && (int) $row['is_demo'] === 1) {
                continue;
            }

            $assetStmt = $this->pdo->prepare('SELECT * FROM target_assets WHERE project_id = :pid AND organization_id = :org');
            $assetStmt->execute([':pid' => $pid, ':org' => $orgId]);

            $grantStmt = $this->pdo->prepare('SELECT * FROM scope_authorization_grants WHERE project_id = :pid AND organization_id = :org ORDER BY scope_version DESC');
            $grantStmt->execute([':pid' => $pid, ':org' => $orgId]);

            $scanStmt = $this->pdo->prepare('SELECT id, status, global_coverage_status, total_findings, critical_count, high_count, medium_count, low_count, started_at, data_source FROM scan_runs WHERE project_id = :pid AND organization_id = :org ORDER BY started_at DESC LIMIT 5');
            $scanStmt->execute([':pid' => $pid, ':org' => $orgId]);

            $result[] = [
                'id' => $pid,
                'organization_id' => $orgId,
                'name' => $row['name'],
                'slug' => $row['slug'],
                'environment' => $row['environment'],
                'stack' => json_decode((string) $row['stack_json'], true) ?: [],
                'description' => $row['description'],
                'is_demo' => (bool) $row['is_demo'],
                'created_by_user_id' => $row['created_by_user_id'],
                'created_at' => $row['created_at'],
                'assets' => $assetStmt->fetchAll(),
                'grants' => array_map([$this, 'hydrateGrantRow'], $grantStmt->fetchAll()),
                'recent_scans' => $scanStmt->fetchAll(),
            ];
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function createProject(array $principal, array $payload): array
    {
        $orgId = (string) $principal['organization_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, null, 'manage_project');

        $name = trim((string) ($payload['name'] ?? ''));
        if (strlen($name) < 3) {
            throw new RuntimeException('Project name must be at least 3 characters', 422);
        }

        $env = (string) ($payload['environment'] ?? 'staging');
        if (!in_array($env, ['local-demo', 'staging', 'production'], true)) {
            throw new RuntimeException('Invalid project environment', 422);
        }

        $rawStack = is_array($payload['stack'] ?? null) ? $payload['stack'] : ['laravel', 'generic-web'];
        $validStacks = ['laravel', 'nextjs', 'generic-web'];
        $stack = array_values(array_intersect($rawStack, $validStacks));
        if (empty($stack)) {
            $stack = ['generic-web'];
        }

        // Validate attacker-controllable target inputs BEFORE any row is created (no orphan projects).
        $hostname = trim((string) ($payload['hostname'] ?? 'demo.example.test'));
        $this->validateHostnameSafety($hostname);
        $repoPath = RuntimeMode::toRepoRelative(
            RuntimeMode::resolveRepositoryPath((string) ($payload['repository_path'] ?? 'examples/synthetic-targets/laravel-app'))
        );

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $projectId = 'proj-' . bin2hex(random_bytes(5));
        $slug = strtolower(preg_replace('/[^a-zA-Z0-9]+/', '-', $name) ?: 'project') . '-' . substr($projectId, -4);
        $isDemo = !empty($payload['is_demo']) ? 1 : 0;

        $this->pdo->prepare(
            'INSERT INTO projects (id, organization_id, name, slug, environment, stack_json, description, is_demo, created_by_user_id, created_at)
             VALUES (:id, :org, :name, :slug, :env, :stack, :desc, :demo, :creator, :c)'
        )->execute([
            ':id' => $projectId,
            ':org' => $orgId,
            ':name' => $name,
            ':slug' => $slug,
            ':env' => $env,
            ':stack' => json_encode($stack),
            ':desc' => trim((string) ($payload['description'] ?? 'Authorized security target project')),
            ':demo' => $isDemo,
            ':creator' => $principal['user_id'],
            ':c' => $now,
        ]);

        // Add project to creator's allowed_project_ids and refresh principal
        $this->grantProjectMembershipToUser($orgId, (string) $principal['user_id'], $projectId);
        $principal = $this->getPrincipalById((string) $principal['user_id'], $orgId);

        // Optional initial target asset & scope grant creation (hostname/repoPath validated above)
        $writtenRef = trim((string) ($payload['written_permission_ref'] ?? ''));

        $assetId = 'ast-' . bin2hex(random_bytes(5));
        $verifyToken = 'hegosentinel-dns-verify=' . bin2hex(random_bytes(8));
        $this->pdo->prepare(
            'INSERT INTO target_assets (id, organization_id, project_id, asset_type, scheme, hostname, port, path_prefix, repository_path, domain_ownership_verified, domain_verification_token, domain_verified_at, created_at)
             VALUES (:id, :org, :pid, :type, :scheme, :host, :port, :path, :repo, 1, :token, :v_at, :c)'
        )->execute([
            ':id' => $assetId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':type' => 'domain',
            ':scheme' => 'https',
            ':host' => $hostname,
            ':port' => (int) ($payload['port'] ?? 443),
            ':path' => (string) ($payload['path_prefix'] ?? '/'),
            ':repo' => $repoPath,
            ':token' => $verifyToken,
            ':v_at' => $now,
            ':c' => $now,
        ]);

        if ($writtenRef !== '') {
            $this->createScopeAuthorizationGrant($principal, $projectId, [
                'written_permission_ref' => $writtenRef,
                'domain_control_proof' => 'dns-txt:' . $verifyToken,
                'authorization_statement' => (string) ($payload['authorization_statement'] ?? 'Authorized passive web & offline SAST/SCA assessment'),
                'hostname' => $hostname,
                'port' => (int) ($payload['port'] ?? 443),
                'path_prefix' => (string) ($payload['path_prefix'] ?? '/'),
                'repository_path' => $repoPath,
                'allowed_checks' => $payload['allowed_checks'] ?? ['WEB-HEADER-001', 'WEB-COOKIE-001', 'WEB-TLS-001', 'WEB-REDIRECT-001', 'CODE-001', 'DEP-001'],
            ]);
        }

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'create_project',
            'allow',
            sprintf('Created project "%s" (%s) with target host %s', $name, $projectId, $hostname)
        );

        foreach ($this->listProjects($this->getPrincipalById((string) $principal['user_id'], $orgId)) as $proj) {
            if ($proj['id'] === $projectId) {
                return $proj;
            }
        }
        throw new RuntimeException('Failed to load created project');
    }

    /**
     * Module 5: Scope Authorization Grants (Written Permission + SSRF/Wildcard Validation — SEC-001 & SEC-002)
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function createScopeAuthorizationGrant(array $principal, string $projectId, array $payload): array
    {
        $proj = $this->getProjectRowOrFail($projectId);
        $orgId = (string) $proj['organization_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'approve_scope');

        $writtenRef = trim((string) ($payload['written_permission_ref'] ?? ''));
        $domainProof = trim((string) ($payload['domain_control_proof'] ?? ''));
        if ($writtenRef === '' || $domainProof === '' || $writtenRef === $domainProof) {
            $this->appendAuditLog(
                $orgId,
                $projectId,
                (string) $principal['user_id'],
                (string) $principal['role'],
                'approve_scope',
                'deny',
                'Rejected scope grant: distinct domain_control_proof and written_permission_ref are mandatory (SEC-001)'
            );
            throw new RuntimeException('Distinct domain_control_proof and written_permission_ref are required (SEC-001)', 422);
        }

        $hostname = trim((string) ($payload['hostname'] ?? 'demo.example.test'));
        $this->validateHostnameSafety($hostname);

        $verStmt = $this->pdo->prepare('SELECT COALESCE(MAX(scope_version), 0) FROM scope_authorization_grants WHERE project_id = :pid');
        $verStmt->execute([':pid' => $projectId]);
        $nextVersion = ((int) $verStmt->fetchColumn()) + 1;

        $grantId = 'GRANT-' . strtoupper(substr(preg_replace('/[^a-zA-Z0-9]/', '', $projectId) ?: 'PROJ', 0, 8)) . '-V' . $nextVersion . '-' . strtoupper(bin2hex(random_bytes(2)));
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $expiresAt = (string) ($payload['expires_at'] ?? '2030-12-31T23:59:59.000Z');
        $allowedRepositories = isset($payload['repository_path']) && trim((string) $payload['repository_path']) !== ''
            ? [RuntimeMode::resolveRepositoryPath((string) $payload['repository_path'])]
            : $this->projectRepositoryPaths($projectId, $orgId);

        $targets = [[
            'scheme' => 'https',
            'hostname' => $hostname,
            'port' => (int) ($payload['port'] ?? 443),
            'path_prefix' => (string) ($payload['path_prefix'] ?? '/'),
        ]];

        $allowedChecks = $payload['allowed_checks'] ?? ['WEB-HEADER-001', 'WEB-COOKIE-001', 'WEB-TLS-001', 'WEB-REDIRECT-001', 'CODE-001', 'DEP-001'];

        $this->pdo->prepare(
            'INSERT INTO scope_authorization_grants (
                grant_id, organization_id, project_id, scope_version, profile, owner_name,
                authorization_statement, domain_control_proof, written_permission_ref, emergency_contact,
                issued_at, expires_at, window_start_at, window_end_at, max_request_budget,
                allowed_methods_json, allowed_checks_json, targets_json, allowed_repositories_json,
                approved_by_user_id, status, created_at
            ) VALUES (
                :gid, :org, :pid, :ver, :prof, :owner,
                :stmt, :proof, :wref, :contact,
                :issued, :expires, :wstart, :wend, :budget,
                :methods, :checks, :targets, :repos,
                :approver, \'active\', :c
            )'
        )->execute([
            ':gid' => $grantId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':ver' => $nextVersion,
            ':prof' => (string) ($payload['profile'] ?? 'local-demo'),
            ':owner' => (string) $principal['name'],
            ':stmt' => (string) ($payload['authorization_statement'] ?? 'Authorized security scan scope'),
            ':proof' => $domainProof,
            ':wref' => $writtenRef,
            ':contact' => (string) ($payload['emergency_contact'] ?? $principal['email']),
            ':issued' => $now,
            ':expires' => $expiresAt,
            ':wstart' => '2026-01-01T00:00:00.000Z',
            ':wend' => $expiresAt,
            ':budget' => min(max((int) ($payload['max_request_budget'] ?? 10), 1), 25),
            ':methods' => json_encode(['GET', 'HEAD']),
            ':checks' => json_encode(array_values((array) $allowedChecks)),
            ':targets' => json_encode($targets),
            ':repos' => json_encode($allowedRepositories),
            ':approver' => $principal['user_id'],
            ':c' => $now,
        ]);

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'approve_scope',
            'allow',
            sprintf('Approved scope grant %s (v%d, ref=%s)', $grantId, $nextVersion, $writtenRef)
        );

        $gStmt = $this->pdo->prepare('SELECT * FROM scope_authorization_grants WHERE grant_id = :gid');
        $gStmt->execute([':gid' => $grantId]);
        return $this->hydrateGrantRow($gStmt->fetch());
    }

    /**
     * Module 6 & 7: Authorized Scan Creation, Isolated Queue Execution & Coverage Matrix
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function createAndExecuteScan(array $principal, array $payload): array
    {
        $projectId = trim((string) ($payload['project_id'] ?? ''));
        $proj = $this->getProjectRowOrFail($projectId);
        $orgId = (string) $proj['organization_id'];

        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'trigger_scan');

        $grantId = trim((string) ($payload['grant_id'] ?? ''));
        if ($grantId === '') {
            $gStmt = $this->pdo->prepare(
                'SELECT * FROM scope_authorization_grants WHERE project_id = :pid AND organization_id = :org AND status = \'active\' ORDER BY scope_version DESC LIMIT 1'
            );
            $gStmt->execute([':pid' => $projectId, ':org' => $orgId]);
            $grantRow = $gStmt->fetch();
        } else {
            $gStmt = $this->pdo->prepare(
                'SELECT * FROM scope_authorization_grants WHERE grant_id = :gid AND project_id = :pid AND organization_id = :org LIMIT 1'
            );
            $gStmt->execute([':gid' => $grantId, ':pid' => $projectId, ':org' => $orgId]);
            $grantRow = $gStmt->fetch();
        }

        if (!$grantRow || $grantRow['status'] !== 'active') {
            $this->appendAuditLog(
                $orgId,
                $projectId,
                (string) $principal['user_id'],
                (string) $principal['role'],
                'trigger_scan',
                'deny',
                'Scan denied: missing or revoked ScopeAuthorizationGrant (SEC-001)'
            );
            throw new RuntimeException('Cannot start scan without an active ScopeAuthorizationGrant (SEC-001)', 403);
        }

        $grantObj = $this->buildScannerGrantObject($proj, $grantRow);
        $mode = (string) ($payload['mode'] ?? 'offline-fixture');
        $fixtureVariant = (string) ($payload['fixture_variant'] ?? 'baseline');
        $dataSource = ((int) $proj['is_demo'] === 1 || ($payload['data_source'] ?? '') === 'demo_seed')
            ? 'demo_seed'
            : 'real_scan';

        $scanId = 'SCAN-' . strtoupper(bin2hex(random_bytes(5)));
        $stopTokenId = 'ESTOP-' . strtoupper(bin2hex(random_bytes(5)));
        $now = gmdate('Y-m-d\TH:i:s\Z');

        // S10-03: Prevent restarting or re-running a cancelled scan (SEC-012)
        if (!empty($payload['restart_scan_run_id'])) {
            $restartId = trim((string) $payload['restart_scan_run_id']);
            $existingScan = $this->getScanById($principal, $restartId);
            if (in_array((string) ($existingScan['status'] ?? ''), ['cancelled', 'denied', 'killed'], true)) {
                $this->appendAuditLog(
                    $orgId,
                    $projectId,
                    (string) $principal['user_id'],
                    (string) $principal['role'],
                    'trigger_scan',
                    'deny',
                    sprintf('Rejected attempt to restart cancelled/denied scan %s (SEC-012 / S10-03)', $restartId)
                );
                throw new RuntimeException('Cancelled or denied scans cannot be restarted; issue a new authorized scan request (SEC-012)', 409);
            }
        }

        // S10-03: Idempotency & duplicate job prevention on `hegosentinel-scans`
        $idempotencyKey = isset($payload['idempotency_key']) && trim((string) $payload['idempotency_key']) !== ''
            ? substr(trim((string) $payload['idempotency_key']), 0, 128)
            : null;
        if ($idempotencyKey !== null) {
            $dupStmt = $this->pdo->prepare(
                'SELECT scan_run_id, status FROM scan_queue_jobs WHERE organization_id = :org AND project_id = :pid AND idempotency_key = :ikey ORDER BY dispatched_at DESC LIMIT 1'
            );
            $dupStmt->execute([':org' => $orgId, ':pid' => $projectId, ':ikey' => $idempotencyKey]);
            $dupJob = $dupStmt->fetch();
            if ($dupJob) {
                if (in_array((string) $dupJob['status'], ['killed', 'cancelled'], true)) {
                    throw new RuntimeException('Scan associated with this idempotency_key was cancelled by Emergency Stop and cannot be restarted (SEC-012)', 409);
                }
                return $this->getScanById($principal, (string) $dupJob['scan_run_id']);
            }
        }

        // Check if an emergency stop has been triggered for this project (SEC-012).
        // A project-wide stop (no scan_run_id) HOLDS new scans for a cooldown window regardless of any
        // client-supplied flag; the previous `honor_project_stop` opt-in let any caller bypass it.
        $holdSeconds = max(60, (int) (getenv('HEGOSENTINEL_ESTOP_HOLD_SECONDS') ?: 900));
        $holdSince = gmdate('Y-m-d\TH:i:s\Z', time() - $holdSeconds);
        $stopCheck = $this->pdo->prepare(
            'SELECT COUNT(*) FROM emergency_stop_events
             WHERE organization_id = :org
               AND (((project_id = :pid OR project_id IS NULL) AND scan_run_id IS NULL AND created_at >= :since) OR emergency_stop_token_id = :tok)'
        );
        $stopCheck->execute([
            ':org' => $orgId,
            ':pid' => $projectId,
            ':since' => $holdSince,
            ':tok' => (string) ($payload['emergency_stop_token_id'] ?? $stopTokenId),
        ]);
        $isCancelled = ((int) $stopCheck->fetchColumn()) > 0;

        // Server-side confinement of the repository path (BOLA / path traversal) BEFORE any job row exists
        $repoPath = $this->resolveScanRepositoryPath($principal, $proj, $grantRow, $payload['repository_path'] ?? null);

        // S10-03 Lifecycle Step 1: Enqueue job in `queued` state on `hegosentinel-scans`
        $jobId = 'JOB-' . strtoupper(bin2hex(random_bytes(5)));
        $containerId = 'hs-wkr-' . strtolower(substr($scanId, 5));
        $this->pdo->prepare(
            'INSERT INTO scan_queue_jobs (
                id, organization_id, project_id, scan_run_id, queue_name, worker_isolation_mode,
                status, attempts, max_tries, timeout_seconds, idempotency_key, supervisor_container_id, heartbeat_at, dispatched_at
            ) VALUES (
                :id, :org, :pid, :sid, \'hegosentinel-scans\', :iso,
                \'queued\', 0, 1, 90, :ikey, :cid, :hb, :now
            )'
        )->execute([
            ':id' => $jobId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':sid' => $scanId,
            ':iso' => $mode === 'restricted-remote' ? 'egress-broker-blocked' : 'supervisor-isolated-worker',
            ':ikey' => $idempotencyKey,
            ':cid' => $containerId,
            ':hb' => $now,
            ':now' => $now,
        ]);

        // S10-03 Lifecycle Step 2: Transition `queued -> running` and record worker heartbeat
        $runningHeartbeat = gmdate('Y-m-d\TH:i:s\Z');
        $this->pdo->prepare(
            'UPDATE scan_queue_jobs SET status = \'running\', attempts = 1, heartbeat_at = :hb WHERE id = :id'
        )->execute([':hb' => $runningHeartbeat, ':id' => $jobId]);

        $jobInstance = new ExecuteAuthorizedScanJob(
            $grantObj,
            $scanId,
            $mode,
            $repoPath,
            $fixtureVariant,
            $isCancelled
        );
        $workerRes = $jobInstance->handle();

        $finishedAt = gmdate('Y-m-d\TH:i:s\Z');

        if (empty($workerRes['allowed'])) {
            $reason = (string) ($workerRes['reason'] ?? 'denied');
            $detail = (string) ($workerRes['detail'] ?? 'Scan denied by policy engine');
            $reportPayload = $workerRes['report'] ?? [
                'schema_version' => '1.0.0',
                'scan_id' => $scanId,
                'scanner_version' => '0.1.0-alpha.4',
                'generated_at' => $finishedAt,
                'organization_id' => $orgId,
                'project_id' => $projectId,
                'project_name' => $proj['name'],
                'grant_id' => $grantRow['grant_id'],
                'scope_version' => (int) $grantRow['scope_version'],
                'profile' => $grantRow['profile'],
                'mode' => $mode,
                'coverage' => ['global_status' => 'denied', 'checks' => []],
                'summary' => ['total_findings' => 0, 'by_priority' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0], 'informational_count' => 0],
                'findings' => [],
                'informational_notes' => [],
            ];

            $this->pdo->prepare(
                'UPDATE scan_queue_jobs SET status = \'failed\', finished_at = :fin, error_message = :err WHERE id = :id'
            )->execute([':fin' => $finishedAt, ':err' => $detail, ':id' => $jobId]);

            $this->pdo->prepare(
                'INSERT INTO scan_runs (
                    id, organization_id, project_id, grant_id, scope_version, profile, mode, data_source,
                    status, global_coverage_status, scanner_version, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    coverage_checks_json, report_payload_json, emergency_stop_token_id,
                    triggered_by_user_id, started_at, completed_at, cancelled_reason
                ) VALUES (
                    :id, :org, :pid, :gid, :ver, :prof, :mode, :ds,
                    \'denied\', \'denied\', \'0.1.0-alpha.4\', 0,
                    0, 0, 0, 0,
                    \'[]\', :rep, :stop,
                    :uid, :start, :fin, :reason
                )'
            )->execute([
                ':id' => $scanId,
                ':org' => $orgId,
                ':pid' => $projectId,
                ':gid' => $grantRow['grant_id'],
                ':ver' => (int) $grantRow['scope_version'],
                ':prof' => $grantRow['profile'],
                ':mode' => $mode,
                ':ds' => $dataSource,
                ':rep' => json_encode($reportPayload),
                ':stop' => $stopTokenId,
                ':uid' => $principal['user_id'],
                ':start' => $now,
                ':fin' => $finishedAt,
                ':reason' => $reason . ': ' . $detail,
            ]);

            $this->appendAuditLog(
                $orgId,
                $projectId,
                (string) $principal['user_id'],
                (string) $principal['role'],
                'trigger_scan',
                'deny',
                sprintf('Scan %s denied (%s): %s', $scanId, $reason, $detail)
            );

            return $this->getScanById($principal, $scanId);
        }

        /** @var array<string, mixed> $report */
        $report = $workerRes['report'];
        $summary = $report['summary'] ?? [];
        $byPriority = $summary['by_priority'] ?? ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        $globalCov = (string) ($report['coverage']['global_status'] ?? 'completed_with_gaps');
        $checks = (array) ($report['coverage']['checks'] ?? []);
        $findings = (array) ($report['findings'] ?? []);

        $this->pdo->prepare(
            'UPDATE scan_queue_jobs SET status = \'completed\', finished_at = :fin WHERE id = :id'
        )->execute([':fin' => $finishedAt, ':id' => $jobId]);

        $this->pdo->prepare(
            'INSERT INTO scan_runs (
                id, organization_id, project_id, grant_id, scope_version, profile, mode, data_source,
                status, global_coverage_status, scanner_version, total_findings,
                critical_count, high_count, medium_count, low_count,
                coverage_checks_json, report_payload_json, emergency_stop_token_id,
                triggered_by_user_id, started_at, completed_at
            ) VALUES (
                :id, :org, :pid, :gid, :ver, :prof, :mode, :ds,
                \'completed\', :gcov, :sver, :total,
                :crit, :high, :med, :low,
                :checks, :rep, :stop,
                :uid, :start, :fin
            )'
        )->execute([
            ':id' => $scanId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':gid' => $grantRow['grant_id'],
            ':ver' => (int) $grantRow['scope_version'],
            ':prof' => $grantRow['profile'],
            ':mode' => $mode,
            ':ds' => $dataSource,
            ':gcov' => $globalCov,
            ':sver' => (string) ($report['scanner_version'] ?? '0.1.0-alpha.4'),
            ':total' => count($findings),
            ':crit' => (int) ($byPriority['critical'] ?? 0),
            ':high' => (int) ($byPriority['high'] ?? 0),
            ':med' => (int) ($byPriority['medium'] ?? 0),
            ':low' => (int) ($byPriority['low'] ?? 0),
            ':checks' => json_encode($checks),
            ':rep' => json_encode($report),
            ':stop' => $stopTokenId,
            ':uid' => $principal['user_id'],
            ':start' => $now,
            ':fin' => $finishedAt,
        ]);

        // Persist normalized findings & auto-create remediation tasks for high/critical findings
        $insFinding = $this->pdo->prepare(
            'INSERT INTO findings (
                id, scan_run_id, organization_id, project_id, grant_id, scope_version,
                rule_id, rule_version, asset_key, fingerprint, title,
                observed_condition, evidence_summary, evidence_hash, inferred_risk, limitations,
                confidence, risk_priority, verification_status, standards_json, remediation_json,
                validation_criterion, data_source, observed_at
            ) VALUES (
                :id, :sid, :org, :pid, :gid, :ver,
                :rule, :rver, :asset, :fp, :title,
                :cond, :ev, :evh, :risk, :lim,
                :conf, :prio, :vstat, :std, :rem,
                :vcrit, :ds, :obs
            )'
        );

        foreach ($findings as $idx => $f) {
            $dbFindingId = $scanId . '-F' . str_pad((string) ($idx + 1), 3, '0', STR_PAD_LEFT);
            $insFinding->execute([
                ':id' => $dbFindingId,
                ':sid' => $scanId,
                ':org' => $orgId,
                ':pid' => $projectId,
                ':gid' => $grantRow['grant_id'],
                ':ver' => (int) $grantRow['scope_version'],
                ':rule' => (string) $f['rule_id'],
                ':rver' => (string) $f['rule_version'],
                ':asset' => (string) $f['asset_key'],
                ':fp' => (string) $f['fingerprint'],
                ':title' => (string) $f['title'],
                ':cond' => (string) $f['observed_condition'],
                ':ev' => (string) $f['evidence_summary'],
                ':evh' => (string) $f['evidence_hash'],
                ':risk' => (string) $f['inferred_risk'],
                ':lim' => (string) $f['limitations'],
                ':conf' => (string) $f['confidence'],
                ':prio' => (string) $f['risk_priority'],
                ':vstat' => (string) $f['verification_status'],
                ':std' => json_encode($f['standards'] ?? []),
                ':rem' => json_encode($f['remediation'] ?? []),
                ':vcrit' => (string) $f['validation_criterion'],
                ':ds' => $dataSource,
                ':obs' => (string) ($f['observed_at'] ?? $finishedAt),
            ]);

            // Auto-create a remediation task if one does not already exist for this project + fingerprint
            $taskCheck = $this->pdo->prepare(
                'SELECT COUNT(*) FROM remediation_tasks WHERE project_id = :pid AND finding_fingerprint = :fp'
            );
            $taskCheck->execute([':pid' => $projectId, ':fp' => (string) $f['fingerprint']]);
            if ((int) $taskCheck->fetchColumn() === 0 && $idx < 6) {
                $rem = (array) ($f['remediation'] ?? []);
                $frameworkExamples = (array) ($rem['framework_examples'] ?? []);
                $firstExample = $frameworkExamples[0] ?? ['framework' => 'laravel', 'snippet' => '// Apply hardened configuration'];
                $this->pdo->prepare(
                    'INSERT INTO remediation_tasks (
                        id, organization_id, project_id, finding_id, finding_fingerprint, rule_id,
                        title, framework, assigned_to_user_id, assigned_to_name, status, priority,
                        guidance_summary, code_patch_example, validation_command, notes, created_at, updated_at
                    ) VALUES (
                        :id, :org, :pid, :fid, :fp, :rule,
                        :title, :fw, :auid, :aname, \'open\', :prio,
                        :sum, :patch, :vcmd, \'\', :c, :u
                    )'
                )->execute([
                    ':id' => 'TASK-' . strtoupper(bin2hex(random_bytes(4))),
                    ':org' => $orgId,
                    ':pid' => $projectId,
                    ':fid' => $dbFindingId,
                    ':fp' => (string) $f['fingerprint'],
                    ':rule' => (string) $f['rule_id'],
                    ':title' => 'Remediate: ' . (string) $f['title'],
                    ':fw' => (string) ($firstExample['framework'] ?? 'laravel'),
                    ':auid' => 'usr-dev-01',
                    ':aname' => 'Demo Developer',
                    ':prio' => (string) $f['risk_priority'],
                    ':sum' => (string) ($rem['summary'] ?? 'Apply security hardening and re-test.'),
                    ':patch' => (string) ($firstExample['snippet'] ?? ''),
                    ':vcmd' => (string) ($f['validation_criterion'] ?? 'Re-run authorized scan and verify fix.'),
                    ':c' => $finishedAt,
                    ':u' => $finishedAt,
                ]);
            }
        }

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'trigger_scan',
            'allow',
            sprintf('Completed scan %s (coverage=%s, findings=%d)', $scanId, $globalCov, count($findings))
        );

        return $this->getScanById($principal, $scanId);
    }

    /**
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listScans(array $principal, ?string $projectId = null): array
    {
        $orgId = (string) $principal['organization_id'];
        if ($projectId !== null && $projectId !== '') {
            $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'read_report');
            $stmt = $this->pdo->prepare(
                'SELECT s.*, p.name AS project_name FROM scan_runs s JOIN projects p ON p.id = s.project_id
                 WHERE s.organization_id = :org AND s.project_id = :pid ORDER BY s.started_at DESC'
            );
            $stmt->execute([':org' => $orgId, ':pid' => $projectId]);
        } else {
            $stmt = $this->pdo->prepare(
                'SELECT s.*, p.name AS project_name FROM scan_runs s JOIN projects p ON p.id = s.project_id
                 WHERE s.organization_id = :org ORDER BY s.started_at DESC'
            );
            $stmt->execute([':org' => $orgId]);
        }

        $allowedProjs = (array) ($principal['project_ids'] ?? []);
        $role = (string) $principal['role'];
        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            if ($role !== 'owner' && !in_array($row['project_id'], $allowedProjs, true)) {
                continue;
            }
            $row['coverage_checks'] = json_decode((string) $row['coverage_checks_json'], true) ?: [];
            unset($row['coverage_checks_json'], $row['report_payload_json']);
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * @param array<string, mixed> $principal
     * @return array<string, mixed>
     */
    public function getScanById(array $principal, string $scanId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT s.*, p.name AS project_name FROM scan_runs s JOIN projects p ON p.id = s.project_id WHERE s.id = :id LIMIT 1'
        );
        $stmt->execute([':id' => $scanId]);
        $row = $stmt->fetch();
        if (!$row) {
            throw new RuntimeException('Scan run not found', 404);
        }

        $this->assertTenantAndRoleAccess($principal, (string) $row['organization_id'], (string) $row['project_id'], 'read_report');

        $row['coverage_checks'] = json_decode((string) $row['coverage_checks_json'], true) ?: [];
        $row['report'] = json_decode((string) $row['report_payload_json'], true) ?: [];
        unset($row['coverage_checks_json'], $row['report_payload_json']);

        $qStmt = $this->pdo->prepare('SELECT * FROM scan_queue_jobs WHERE scan_run_id = :sid ORDER BY dispatched_at DESC LIMIT 1');
        $qStmt->execute([':sid' => $scanId]);
        $row['queue_job'] = $qStmt->fetch() ?: null;

        return $row;
    }

    /**
     * Module 8: Security Findings & Scoped Suppressions (SEC-010)
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $filters
     * @return list<array<string, mixed>>
     */
    public function listFindings(array $principal, array $filters = []): array
    {
        $orgId = (string) $principal['organization_id'];
        $sql = 'SELECT f.*, p.name AS project_name FROM findings f JOIN projects p ON p.id = f.project_id WHERE f.organization_id = :org';
        $params = [':org' => $orgId];

        if (!empty($filters['project_id'])) {
            $this->assertTenantAndRoleAccess($principal, $orgId, (string) $filters['project_id'], 'read_report');
            $sql .= ' AND f.project_id = :pid';
            $params[':pid'] = (string) $filters['project_id'];
        }
        if (!empty($filters['scan_run_id'])) {
            $sql .= ' AND f.scan_run_id = :sid';
            $params[':sid'] = (string) $filters['scan_run_id'];
        }
        if (!empty($filters['risk_priority'])) {
            $sql .= ' AND f.risk_priority = :prio';
            $params[':prio'] = (string) $filters['risk_priority'];
        }
        if (!empty($filters['rule_id'])) {
            $sql .= ' AND f.rule_id = :rule';
            $params[':rule'] = (string) $filters['rule_id'];
        }
        if (!empty($filters['data_source'])) {
            $sql .= ' AND f.data_source = :ds';
            $params[':ds'] = (string) $filters['data_source'];
        }

        $sql .= ' ORDER BY f.observed_at DESC';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        $role = (string) $principal['role'];
        $allowedProjs = (array) ($principal['project_ids'] ?? []);
        $result = [];
        foreach ($stmt->fetchAll() as $row) {
            if ($role !== 'owner' && !in_array($row['project_id'], $allowedProjs, true)) {
                continue;
            }
            $row['standards'] = json_decode((string) $row['standards_json'], true) ?: [];
            $row['remediation'] = json_decode((string) $row['remediation_json'], true) ?: [];
            unset($row['standards_json'], $row['remediation_json']);
            $result[] = $row;
        }
        return $result;
    }

    /**
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function suppressFindingFalsePositive(array $principal, string $findingId, array $payload): array
    {
        $fStmt = $this->pdo->prepare('SELECT * FROM findings WHERE id = :id LIMIT 1');
        $fStmt->execute([':id' => $findingId]);
        $finding = $fStmt->fetch();
        if (!$finding) {
            throw new RuntimeException('Finding not found', 404);
        }

        $orgId = (string) $finding['organization_id'];
        $projectId = (string) $finding['project_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'suppress_finding');

        $rationale = trim((string) ($payload['rationale'] ?? ''));
        if (strlen($rationale) < 12) {
            throw new RuntimeException('False positive suppression requires a rationale of at least 12 characters (SEC-010)', 422);
        }

        $supId = 'SUP-' . strtoupper(bin2hex(random_bytes(5)));
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $expiresAt = (string) ($payload['expires_at'] ?? gmdate('Y-m-d\TH:i:s\Z', time() + 90 * 86400));

        $this->pdo->prepare(
            'INSERT INTO false_positive_suppressions (id, organization_id, project_id, fingerprint, scope_version, rationale, approved_by, expires_at, created_at)
             VALUES (:id, :org, :pid, :fp, :ver, :rat, :app, :exp, :c)'
        )->execute([
            ':id' => $supId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':fp' => $finding['fingerprint'],
            ':ver' => (int) $finding['scope_version'],
            ':rat' => $rationale,
            ':app' => $principal['email'],
            ':exp' => $expiresAt,
            ':c' => $now,
        ]);

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'suppress_finding',
            'allow',
            sprintf('Scoped false_positive suppression %s created for fingerprint %s (scope_version=%d)', $supId, substr((string) $finding['fingerprint'], 0, 16), (int) $finding['scope_version'])
        );

        return [
            'id' => $supId,
            'organization_id' => $orgId,
            'project_id' => $projectId,
            'fingerprint' => $finding['fingerprint'],
            'scope_version' => (int) $finding['scope_version'],
            'rationale' => $rationale,
            'approved_by' => $principal['email'],
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Module 9: Vulnerability Remediation Tasks
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listRemediationTasks(array $principal, ?string $projectId = null): array
    {
        $orgId = (string) $principal['organization_id'];
        if ($projectId !== null && $projectId !== '') {
            $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'read_report');
            $stmt = $this->pdo->prepare(
                'SELECT t.*, p.name AS project_name FROM remediation_tasks t JOIN projects p ON p.id = t.project_id
                 WHERE t.organization_id = :org AND t.project_id = :pid ORDER BY t.updated_at DESC'
            );
            $stmt->execute([':org' => $orgId, ':pid' => $projectId]);
        } else {
            $stmt = $this->pdo->prepare(
                'SELECT t.*, p.name AS project_name FROM remediation_tasks t JOIN projects p ON p.id = t.project_id
                 WHERE t.organization_id = :org ORDER BY t.updated_at DESC'
            );
            $stmt->execute([':org' => $orgId]);
        }

        $role = (string) $principal['role'];
        $allowedProjs = (array) ($principal['project_ids'] ?? []);
        $tasks = [];
        foreach ($stmt->fetchAll() as $row) {
            if ($role !== 'owner' && !in_array($row['project_id'], $allowedProjs, true)) {
                continue;
            }
            $tasks[] = $row;
        }
        return $tasks;
    }

    /**
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function updateRemediationTask(array $principal, string $taskId, array $payload): array
    {
        $tStmt = $this->pdo->prepare('SELECT * FROM remediation_tasks WHERE id = :id LIMIT 1');
        $tStmt->execute([':id' => $taskId]);
        $task = $tStmt->fetch();
        if (!$task) {
            throw new RuntimeException('Remediation task not found', 404);
        }

        $orgId = (string) $task['organization_id'];
        $projectId = (string) $task['project_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'manage_remediation');

        $status = (string) ($payload['status'] ?? $task['status']);
        if (!in_array($status, ['open', 'in_progress', 'ready_for_retest', 'verified_closed'], true)) {
            throw new RuntimeException('Invalid remediation task status', 422);
        }
        // A task may only become verified_closed through a comparable Re-Test (verified_fixed); it can
        // never be closed by hand, otherwise a developer could fake a "fixed" vulnerability.
        if ($status === 'verified_closed' && (string) $task['status'] !== 'verified_closed') {
            $this->appendAuditLog(
                $orgId,
                $projectId,
                (string) $principal['user_id'],
                (string) $principal['role'],
                'update_remediation_task',
                'deny',
                sprintf('Manual verified_closed denied for task %s: only a verified_fixed Re-Test may close a task', $taskId)
            );
            throw new RuntimeException('verified_closed can only be set by a verified Re-Test comparison', 422);
        }

        $assignedUserId = (string) ($payload['assigned_to_user_id'] ?? $task['assigned_to_user_id']);
        $assignedName = (string) ($payload['assigned_to_name'] ?? $task['assigned_to_name']);
        $notes = (string) ($payload['notes'] ?? $task['notes']);
        $now = gmdate('Y-m-d\TH:i:s\Z');

        $this->pdo->prepare(
            'UPDATE remediation_tasks SET status = :st, assigned_to_user_id = :auid, assigned_to_name = :aname, notes = :notes, updated_at = :u WHERE id = :id'
        )->execute([
            ':st' => $status,
            ':auid' => $assignedUserId,
            ':aname' => $assignedName,
            ':notes' => $notes,
            ':u' => $now,
            ':id' => $taskId,
        ]);

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'update_remediation_task',
            'allow',
            sprintf('Updated remediation task %s to status "%s"', $taskId, $status)
        );

        $tStmt->execute([':id' => $taskId]);
        return $tStmt->fetch();
    }

    /**
     * Module 10: Re-Test & Side-by-Side Comparison (SEC-009 / S1-05)
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function runRecheckComparison(array $principal, array $payload): array
    {
        $baselineId = trim((string) ($payload['baseline_scan_id'] ?? ''));
        $currentId = trim((string) ($payload['current_scan_id'] ?? ''));

        $baseRow = $this->getScanById($principal, $baselineId);
        $currRow = $this->getScanById($principal, $currentId);

        $orgId = (string) $baseRow['organization_id'];
        $projectId = (string) $baseRow['project_id'];
        if ($currRow['organization_id'] !== $orgId) {
            throw new RuntimeException('Cross-tenant scan comparison denied (SEC-011)', 403);
        }
        // Re-Test mutates remediation state (auto-closes tasks), so read-only roles must not run it,
        // and both scans must belong to the same project (no cross-project "fixed" claims).
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'manage_remediation');
        if ((string) $currRow['project_id'] !== $projectId) {
            throw new RuntimeException('Re-Test requires baseline and current scans of the same project', 422);
        }

        // Load active false_positive suppressions for this org + project
        $supStmt = $this->pdo->prepare(
            'SELECT * FROM false_positive_suppressions WHERE organization_id = :org AND project_id = :pid'
        );
        $supStmt->execute([':org' => $orgId, ':pid' => $projectId]);
        $suppressions = [];
        foreach ($supStmt->fetchAll() as $s) {
            $suppressions[] = [
                'organization_id' => $s['organization_id'],
                'project_id' => $s['project_id'],
                'fingerprint' => $s['fingerprint'],
                'scope_version' => (int) $s['scope_version'],
                'reviewer' => (string) $s['approved_by'],
                'reason' => (string) $s['rationale'],
                'rationale' => (string) $s['rationale'],
                'approved_by' => (string) $s['approved_by'],
                'approved_at' => $s['created_at'],
                'expires_at' => $s['expires_at'],
            ];
        }

        $recheckJob = new ExecuteRecheckComparisonJob(
            $projectId . ':' . $baselineId . ':' . $currentId,
            (array) $baseRow['report'],
            (array) $currRow['report'],
            $suppressions
        );
        $decoded = $recheckJob->handle();
        if (!is_array($decoded) || empty($decoded['comparison'])) {
            throw new RuntimeException('Recheck comparison failed');
        }

        $comp = $decoded['comparison'];
        $recheckId = 'RECHK-' . strtoupper(bin2hex(random_bytes(5)));
        $now = gmdate('Y-m-d\TH:i:s\Z');

        $this->pdo->prepare(
            'INSERT INTO recheck_comparisons (id, organization_id, project_id, baseline_scan_id, current_scan_id, comparable, non_comparable_reason, counts_json, items_json, created_by_user_id, created_at)
             VALUES (:id, :org, :pid, :bid, :cid, :comp, :reason, :counts, :items, :uid, :c)'
        )->execute([
            ':id' => $recheckId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':bid' => $baselineId,
            ':cid' => $currentId,
            ':comp' => !empty($comp['comparable']) ? 1 : 0,
            ':reason' => $comp['non_comparable_reason'] ?? null,
            ':counts' => json_encode($comp['counts'] ?? []),
            ':items' => json_encode($comp['items'] ?? []),
            ':uid' => $principal['user_id'],
            ':c' => $now,
        ]);

        // Automatically mark remediation tasks as verified_closed when their finding fingerprint reaches verified_fixed
        foreach (($comp['items'] ?? []) as $item) {
            if (($item['recheck_state'] ?? '') === 'verified_fixed' && !empty($item['fingerprint'])) {
                $this->pdo->prepare(
                    'UPDATE remediation_tasks SET status = \'verified_closed\', updated_at = :u WHERE project_id = :pid AND finding_fingerprint = :fp'
                )->execute([':u' => $now, ':pid' => $projectId, ':fp' => $item['fingerprint']]);
            }
        }

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'run_recheck_comparison',
            'allow',
            sprintf('Compared baseline %s against %s (comparable=%s)', $baselineId, $currentId, !empty($comp['comparable']) ? 'true' : 'false')
        );

        return [
            'id' => $recheckId,
            'organization_id' => $orgId,
            'project_id' => $projectId,
            'baseline_scan_id' => $baselineId,
            'current_scan_id' => $currentId,
            'comparable' => (bool) $comp['comparable'],
            'non_comparable_reason' => $comp['non_comparable_reason'] ?? null,
            'counts' => $comp['counts'] ?? [],
            'items' => $comp['items'] ?? [],
            'created_at' => $now,
        ];
    }

    /**
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listRecheckComparisons(array $principal, ?string $projectId = null): array
    {
        $orgId = (string) $principal['organization_id'];
        $stmt = $this->pdo->prepare(
            'SELECT * FROM recheck_comparisons WHERE organization_id = :org ORDER BY created_at DESC'
        );
        $stmt->execute([':org' => $orgId]);

        $role = (string) $principal['role'];
        $allowedProjs = (array) ($principal['project_ids'] ?? []);
        $rows = [];
        foreach ($stmt->fetchAll() as $row) {
            if ($projectId !== null && $projectId !== '' && $row['project_id'] !== $projectId) {
                continue;
            }
            if ($role !== 'owner' && !in_array($row['project_id'], $allowedProjs, true)) {
                continue;
            }
            $row['comparable'] = (bool) $row['comparable'];
            $row['counts'] = json_decode((string) $row['counts_json'], true) ?: [];
            $row['items'] = json_decode((string) $row['items_json'], true) ?: [];
            unset($row['counts_json'], $row['items_json']);
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * Module 11: Safe Report Export (JSON, Markdown, HTML, SARIF 2.1.0, Printable PDF-HTML)
     * Enforces authorizeReportTenantAccess (SEC-011) and 9-pass secret scrubbing (SEC-007 / SEC-009).
     * @param array<string, mixed> $principal
     * @return array{format: string, content_type: string, filename: string, content: string}
     */
    public function exportScanReport(array $principal, string $scanId, string $format = 'json'): array
    {
        $scan = $this->getScanById($principal, $scanId);
        $orgId = (string) $scan['organization_id'];
        $projectId = (string) $scan['project_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'export_artifact');

        $fmt = strtolower(trim($format));
        if (!in_array($fmt, ['json', 'md', 'html', 'sarif', 'pdf'], true)) {
            throw new RuntimeException('Unsupported report export format', 422);
        }

        // Verify every embedded finding inside the report belongs to the same tenant & project (SEC-011)
        $report = (array) ($scan['report'] ?? []);
        foreach (($report['findings'] ?? []) as $f) {
            if (($f['organization_id'] ?? '') !== $orgId || ($f['project_id'] ?? '') !== $projectId) {
                $this->appendAuditLog($orgId, $projectId, (string) $principal['user_id'], (string) $principal['role'], 'export_artifact', 'deny', 'Contaminated finding tenant detected inside report');
                throw new RuntimeException('Report contains finding outside authorized tenant boundary (SEC-011)', 403);
            }
        }

        $decoded = WorkerSupervisorClient::executeAuxAction([
            'action' => 'export',
            'export_format' => $fmt,
            'report' => $report,
        ]);
        if (!is_array($decoded) || empty($decoded['ok'])) {
            throw new RuntimeException('Failed to export report');
        }

        $ext = $fmt === 'sarif' ? 'sarif.json' : ($fmt === 'pdf' ? 'pdf.html' : $fmt);
        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'export_artifact',
            'allow',
            sprintf('Exported scan report %s in %s format', $scanId, strtoupper($fmt))
        );

        return [
            'format' => $fmt,
            'content_type' => (string) $decoded['content_type'],
            'filename' => sprintf('hegosentinel-%s.%s', strtolower($scanId), $ext),
            'content' => (string) $decoded['content'],
        ];
    }

    /**
     * Module 12: Approved Developer Notifications (SEC-013)
     * Blocks public webhook sinks, unverified recipient domains, non-owners/non-sec-leads, and unredacted secrets.
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function sendApprovedNotification(array $principal, array $payload): array
    {
        $projectId = trim((string) ($payload['project_id'] ?? ''));
        $scanId = trim((string) ($payload['scan_run_id'] ?? ''));
        $channel = trim((string) ($payload['channel'] ?? 'email'));
        $recipient = trim((string) ($payload['recipient'] ?? ''));
        $summaryText = trim((string) ($payload['summary'] ?? 'Authorized scan report summary ready for review.'));

        $proj = $this->getProjectRowOrFail($projectId);
        $orgId = (string) $proj['organization_id'];

        // SEC-013: Only owner or security_lead can approve notifications
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'approve_notification');

        $notifId = 'NOTIF-' . strtoupper(bin2hex(random_bytes(5)));
        $now = gmdate('Y-m-d\TH:i:s\Z');

        // 1. Block public webhook / chat / pastebin sinks
        $lowerRecip = strtolower($recipient);
        foreach (self::BLOCKED_PUBLIC_NOTIFICATION_SINKS as $sink) {
            if (str_contains($lowerRecip, $sink)) {
                $reason = sprintf('Blocked public sink "%s" in notification recipient (SEC-013)', $sink);
                $this->recordNotificationRow($notifId, $orgId, $projectId, $scanId, $channel, $recipient, $principal, 'denied', $reason, '[REDACTED]');
                $this->appendAuditLog($orgId, $projectId, (string) $principal['user_id'], (string) $principal['role'], 'approve_notification', 'deny', $reason);
                throw new RuntimeException($reason, 403);
            }
        }

        // 2. Verify recipient domain is in organization verified_notification_domains
        $verifiedDomains = (array) ($principal['verified_notification_domains'] ?? []);
        $recipDomain = '';
        if ($channel === 'email' && str_contains($recipient, '@')) {
            $recipDomain = strtolower(substr(strrchr($recipient, '@') ?: '', 1));
        } elseif ($channel === 'webhook') {
            $parsedHost = parse_url($recipient, PHP_URL_HOST);
            $recipDomain = is_string($parsedHost) ? strtolower($parsedHost) : '';
        }

        $domainAllowed = false;
        foreach ($verifiedDomains as $vd) {
            $vdLower = strtolower((string) $vd);
            if ($recipDomain === $vdLower || str_ends_with($recipDomain, '.' . $vdLower)) {
                $domainAllowed = true;
                break;
            }
        }

        if (!$domainAllowed) {
            $reason = sprintf('Recipient domain "%s" is not in organization verified_notification_domains (SEC-013)', $recipDomain ?: 'invalid');
            $this->recordNotificationRow($notifId, $orgId, $projectId, $scanId, $channel, $recipient, $principal, 'denied', $reason, '[REDACTED]');
            $this->appendAuditLog($orgId, $projectId, (string) $principal['user_id'], (string) $principal['role'], 'approve_notification', 'deny', $reason);
            throw new RuntimeException($reason, 403);
        }

        // 3. Reject payloads containing unredacted secrets/tokens (SEC-013)
        if (preg_match('/(Bearer\s+[A-Za-z0-9\-._~+\/]+=*|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|APP_KEY=base64:|postgres:\/\/[^:\s]+:[^@\s]+@)/i', $summaryText)) {
            $reason = 'Notification payload rejected: detected unredacted secret or credential token (SEC-013)';
            $this->recordNotificationRow($notifId, $orgId, $projectId, $scanId, $channel, $recipient, $principal, 'denied', $reason, '[REDACTED-SECRET]');
            $this->appendAuditLog($orgId, $projectId, (string) $principal['user_id'], (string) $principal['role'], 'approve_notification', 'deny', $reason);
            throw new RuntimeException($reason, 422);
        }

        $this->recordNotificationRow($notifId, $orgId, $projectId, $scanId, $channel, $recipient, $principal, 'dispatched', null, $summaryText);
        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'approve_notification',
            'allow',
            sprintf('Dispatched approved %s notification %s to verified recipient %s', $channel, $notifId, $recipient)
        );

        return [
            'id' => $notifId,
            'organization_id' => $orgId,
            'project_id' => $projectId,
            'scan_run_id' => $scanId,
            'channel' => $channel,
            'recipient' => $recipient,
            'status' => 'dispatched',
            'sanitized_summary' => $summaryText,
            'created_at' => $now,
        ];
    }

    /**
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listNotifications(array $principal): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM approved_notifications WHERE organization_id = :org ORDER BY created_at DESC');
        $stmt->execute([':org' => $principal['organization_id']]);
        return $this->filterRowsByProjectScope($principal, $stmt->fetchAll());
    }

    /**
     * Non-owner roles only see rows of projects they are assigned to (project-level isolation).
     *
     * @param array<string, mixed> $principal
     * @param list<array<string, mixed>> $rows
     * @return list<array<string, mixed>>
     */
    private function filterRowsByProjectScope(array $principal, array $rows): array
    {
        if ((string) $principal['role'] === 'owner') {
            return $rows;
        }
        $allowed = (array) ($principal['project_ids'] ?? []);
        return array_values(array_filter(
            $rows,
            static fn (array $r): bool => isset($r['project_id']) && $r['project_id'] !== null && in_array((string) $r['project_id'], $allowed, true)
        ));
    }

    /**
     * Module 14: Emergency Stop & Subprocess Cancellation (SEC-012)
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function triggerEmergencyStop(array $principal, array $payload): array
    {
        $orgId = (string) $principal['organization_id'];
        $projectId = !empty($payload['project_id']) ? (string) $payload['project_id'] : null;
        $scanId = !empty($payload['scan_run_id']) ? (string) $payload['scan_run_id'] : null;
        $reason = trim((string) ($payload['reason'] ?? 'Emergency stop triggered by operator'));

        if ($projectId !== null) {
            // The project must exist and belong to the caller's organization (no foreign/phantom project ids).
            $stopProject = $this->getProjectRowOrFail($projectId);
            $this->assertTenantAndRoleAccess($principal, (string) $stopProject['organization_id'], $projectId, 'emergency_stop');
        }
        $this->assertTenantAndRoleAccess($principal, $orgId, $projectId, 'emergency_stop');

        $stopStartNs = hrtime(true);
        $stopId = 'STOP-' . strtoupper(bin2hex(random_bytes(5)));
        $tokenId = (string) ($payload['emergency_stop_token_id'] ?? ('ESTOP-' . strtoupper(bin2hex(random_bytes(4)))));
        $now = gmdate('Y-m-d\TH:i:s\Z');

        $terminatedCount = 0;
        $cancelMeta = [
            'terminated' => true,
            'latency_ms' => 1,
            'signal_sequence' => 'SIGTERM -> SIGKILL',
            'supervisor_mode' => 'supervisor-registry-revocation',
        ];

        if ($scanId !== null && $scanId !== '') {
            $scanRow = $this->getScanById($principal, $scanId);
            $tokenId = (string) ($scanRow['emergency_stop_token_id'] ?? $tokenId);
            $projectId = (string) $scanRow['project_id'];
            $queueJob = is_array($scanRow['queue_job'] ?? null) ? $scanRow['queue_job'] : [];
            $containerId = isset($queueJob['supervisor_container_id']) ? (string) $queueJob['supervisor_container_id'] : null;
            $workerPid = isset($queueJob['worker_pid']) ? (int) $queueJob['worker_pid'] : null;

            $cancelMeta = WorkerSupervisorClient::cancelRunningScan($scanId, $containerId, $workerPid);

            $this->pdo->prepare(
                'UPDATE scan_runs SET status = \'cancelled\', global_coverage_status = \'denied\', cancelled_reason = :reason, completed_at = :now WHERE id = :id AND organization_id = :org'
            )->execute([':reason' => 'SEC-012 Emergency Stop: ' . $reason, ':now' => $now, ':id' => $scanId, ':org' => $orgId]);

            $this->pdo->prepare(
                'UPDATE scan_queue_jobs SET status = \'killed\', finished_at = :now, heartbeat_at = :now, error_message = :reason WHERE scan_run_id = :sid AND organization_id = :org'
            )->execute([':now' => $now, ':reason' => 'SIGTERM -> SIGKILL (' . $reason . ')', ':sid' => $scanId, ':org' => $orgId]);

            $terminatedCount = 1;
        } elseif ($projectId !== null) {
            // Project-wide stop: cancel all queued or running jobs for this project
            $activeStmt = $this->pdo->prepare(
                'SELECT scan_run_id, supervisor_container_id, worker_pid FROM scan_queue_jobs
                 WHERE organization_id = :org AND project_id = :pid AND status IN (\'queued\', \'running\')'
            );
            $activeStmt->execute([':org' => $orgId, ':pid' => $projectId]);
            foreach ($activeStmt->fetchAll() as $activeJob) {
                WorkerSupervisorClient::cancelRunningScan(
                    (string) $activeJob['scan_run_id'],
                    isset($activeJob['supervisor_container_id']) ? (string) $activeJob['supervisor_container_id'] : null,
                    isset($activeJob['worker_pid']) ? (int) $activeJob['worker_pid'] : null
                );
                $terminatedCount++;
            }
            $this->pdo->prepare(
                'UPDATE scan_queue_jobs SET status = \'killed\', finished_at = :now, error_message = :reason
                 WHERE organization_id = :org AND project_id = :pid AND status IN (\'queued\', \'running\')'
            )->execute([':now' => $now, ':reason' => 'SIGTERM -> SIGKILL (' . $reason . ')', ':org' => $orgId, ':pid' => $projectId]);

            $this->pdo->prepare(
                'UPDATE scan_runs SET status = \'cancelled\', global_coverage_status = \'denied\', cancelled_reason = :reason, completed_at = :now
                 WHERE organization_id = :org AND project_id = :pid AND status IN (\'queued\', \'running\')'
            )->execute([':reason' => 'SEC-012 Emergency Stop: ' . $reason, ':now' => $now, ':org' => $orgId, ':pid' => $projectId]);
        }

        // Also revoke active scope grants if project_level_revoke requested
        if (!empty($payload['revoke_project_grants']) && $projectId !== null) {
            $this->pdo->prepare(
                'UPDATE scope_authorization_grants SET status = \'revoked\' WHERE project_id = :pid AND organization_id = :org'
            )->execute([':pid' => $projectId, ':org' => $orgId]);
        }

        $totalLatencyMs = max(1, (int) round((hrtime(true) - $stopStartNs) / 1_000_000));

        $this->pdo->prepare(
            'INSERT INTO emergency_stop_events (id, organization_id, project_id, scan_run_id, emergency_stop_token_id, triggered_by_user_id, reason, subprocesses_terminated, cancellation_latency_ms, created_at)
             VALUES (:id, :org, :pid, :sid, :tok, :uid, :reason, :term, :lat, :c)'
        )->execute([
            ':id' => $stopId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':sid' => $scanId,
            ':tok' => $tokenId,
            ':uid' => $principal['user_id'],
            ':reason' => $reason,
            ':term' => $terminatedCount,
            ':lat' => $totalLatencyMs,
            ':c' => $now,
        ]);

        $this->appendAuditLog(
            $orgId,
            $projectId,
            (string) $principal['user_id'],
            (string) $principal['role'],
            'emergency_stop',
            'allow',
            sprintf('Emergency stop %s activated in %dms (scan=%s, token=%s): %s', $stopId, $totalLatencyMs, $scanId ?? 'all', $tokenId, $reason)
        );

        return [
            'id' => $stopId,
            'organization_id' => $orgId,
            'project_id' => $projectId,
            'scan_run_id' => $scanId,
            'emergency_stop_token_id' => $tokenId,
            'reason' => $reason,
            'subprocesses_terminated' => $terminatedCount,
            'cancellation_latency_ms' => $totalLatencyMs,
            'signal_sequence' => $cancelMeta['signal_sequence'],
            'within_sla_2000ms' => $totalLatencyMs < 2000,
            'created_at' => $now,
        ];
    }

    /**
     * @param array<string, mixed> $principal
     * @return list<array<string, mixed>>
     */
    public function listEmergencyStopEvents(array $principal): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM emergency_stop_events WHERE organization_id = :org ORDER BY created_at DESC');
        $stmt->execute([':org' => $principal['organization_id']]);
        return $this->filterRowsByProjectScope($principal, $stmt->fetchAll());
    }

    /**
     * Queue & Horizon Supervisor Telemetry (`S10-03`).
     *
     * @param array<string, mixed> $principal
     * @return array<string, mixed>
     */
    public function getQueueAndHorizonStatus(array $principal): array
    {
        $orgId = (string) $principal['organization_id'];
        $stmt = $this->pdo->prepare(
            'SELECT * FROM scan_queue_jobs WHERE organization_id = :org ORDER BY dispatched_at DESC LIMIT 50'
        );
        $stmt->execute([':org' => $orgId]);
        $jobs = $this->filterRowsByProjectScope($principal, $stmt->fetchAll());

        $byStatus = ['queued' => 0, 'running' => 0, 'completed' => 0, 'failed' => 0, 'killed' => 0];
        foreach ($jobs as $j) {
            $st = (string) ($j['status'] ?? 'completed');
            if (isset($byStatus[$st])) {
                $byStatus[$st]++;
            }
        }

        return [
            'organization_id' => $orgId,
            'horizon_supervisor' => 'supervisor-scans',
            'queues' => [
                'hegosentinel-scans',
                'hegosentinel-rechecks',
                'hegosentinel-notifications',
            ],
            'worker_isolation_plane' => 'WorkerSupervisorClient (API never mounts docker.sock)',
            'counts_by_status' => $byStatus,
            'recent_jobs' => $jobs,
        ];
    }

    /**
     * Module 13: Tamper-Evident Hash-Chained Audit Logs
     * Audit trails disclose activity across projects, so only roles holding `read_audit`
     * (owner, security_lead) may read them; entries are always limited to the caller's organization.
     * @param array<string, mixed> $principal
     * @return array<string, mixed>
     */
    public function listAndVerifyAuditLogs(array $principal): array
    {
        $orgId = (string) $principal['organization_id'];
        $this->assertTenantAndRoleAccess($principal, $orgId, null, 'read_audit');
        return $this->readAuditLogsUnchecked($orgId);
    }

    /**
     * @return array<string, mixed>
     */
    private function readAuditLogsUnchecked(string $orgId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM audit_logs WHERE organization_id = :org ORDER BY sequence DESC LIMIT 100');
        $stmt->execute([':org' => $orgId]);
        $entries = $stmt->fetchAll();

        $integrity = $this->verifyAuditChainIntegrity();
        return [
            'integrity' => $integrity,
            'entries' => $entries,
        ];
    }

    /**
     * Verifies the global SHA-256 hash chain across all audit_logs rows.
     * @return array{valid: bool, entries_checked: int, broken_at_sequence?: int}
     */
    public function verifyAuditChainIntegrity(): array
    {
        $rows = $this->pdo->query('SELECT * FROM audit_logs ORDER BY sequence ASC')->fetchAll();
        $expectedPrev = str_repeat('0', 64);
        $checked = 0;

        foreach ($rows as $row) {
            $checked++;
            if ($row['prev_hash'] !== $expectedPrev) {
                return ['valid' => false, 'entries_checked' => $checked, 'broken_at_sequence' => (int) $row['sequence']];
            }
            $canonical = implode('|', [
                $row['event_id'],
                $row['organization_id'],
                (string) ($row['project_id'] ?? ''),
                $row['actor_user_id'],
                $row['actor_role'],
                $row['action'],
                $row['outcome'],
                $row['detail'],
                $row['created_at'],
                $row['prev_hash'],
            ]);
            $computed = hash('sha256', $canonical);
            if (!hash_equals($computed, (string) $row['entry_hash'])) {
                return ['valid' => false, 'entries_checked' => $checked, 'broken_at_sequence' => (int) $row['sequence']];
            }
            $expectedPrev = $computed;
        }

        return ['valid' => true, 'entries_checked' => $checked];
    }

    /**
     * Dashboard Telemetry Summary
     * @param array<string, mixed> $principal
     * @return array<string, mixed>
     */
    public function getDashboardSummary(array $principal): array
    {
        $projects = $this->listProjects($principal, true);
        $scans = $this->listScans($principal);
        $findings = $this->listFindings($principal);
        $tasks = $this->listRemediationTasks($principal);
        $rechecks = $this->listRecheckComparisons($principal);
        $canReadAudit = in_array((string) $principal['role'], ['owner', 'security_lead'], true);
        $audit = $canReadAudit
            ? $this->readAuditLogsUnchecked((string) $principal['organization_id'])
            : ['integrity' => $this->verifyAuditChainIntegrity(), 'entries' => []];

        $riskDist = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        $realFindingsCount = 0;
        $demoFindingsCount = 0;
        foreach ($findings as $f) {
            $p = (string) ($f['risk_priority'] ?? 'low');
            if (isset($riskDist[$p])) {
                $riskDist[$p]++;
            }
            if (($f['data_source'] ?? 'real_scan') === 'demo_seed') {
                $demoFindingsCount++;
            } else {
                $realFindingsCount++;
            }
        }

        return [
            'organization_id' => $principal['organization_id'],
            'organization_name' => $principal['organization_name'],
            'principal' => $principal,
            'metrics' => [
                'total_projects' => count($projects),
                'real_projects' => count(array_filter($projects, fn ($p) => !$p['is_demo'])),
                'demo_projects' => count(array_filter($projects, fn ($p) => $p['is_demo'])),
                'total_scans' => count($scans),
                'total_findings' => count($findings),
                'real_scan_findings' => $realFindingsCount,
                'demo_seed_findings' => $demoFindingsCount,
                'open_remediation_tasks' => count(array_filter($tasks, fn ($t) => $t['status'] !== 'verified_closed')),
                'verified_closed_tasks' => count(array_filter($tasks, fn ($t) => $t['status'] === 'verified_closed')),
                'total_rechecks' => count($rechecks),
                'risk_distribution' => $riskDist,
            ],
            'security_posture' => [
                'restricted_remote_mode' => 'BLOCKED (Fail-Closed)',
                'worker_isolation' => 'source-offline (--network=none, 65532:65532, read-only)',
                'egress_broker_policy' => 'DROP by default (TrustedEgressBroker)',
                'pinned_semgrep_version' => '1.183.0',
                'pinned_trivy_version' => '0.76.1',
                'audit_chain_valid' => $audit['integrity']['valid'],
                'audit_entries_checked' => $audit['integrity']['entries_checked'],
            ],
            'recent_scans' => array_slice($scans, 0, 6),
            'recent_rechecks' => array_slice($rechecks, 0, 4),
            'recent_audit_entries' => array_slice($audit['entries'], 0, 8),
        ];
    }

    private function appendAuditLog(
        string $orgId,
        ?string $projectId,
        string $actorUserId,
        string $actorRole,
        string $action,
        string $outcome,
        string $detail
    ): void {
        $prevStmt = $this->pdo->query('SELECT entry_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1');
        $prevHash = (string) ($prevStmt->fetchColumn() ?: str_repeat('0', 64));

        $eventId = 'AUD-' . strtoupper(bin2hex(random_bytes(6)));
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $canonical = implode('|', [
            $eventId,
            $orgId,
            (string) ($projectId ?? ''),
            $actorUserId,
            $actorRole,
            $action,
            $outcome,
            $detail,
            $now,
            $prevHash,
        ]);
        $entryHash = hash('sha256', $canonical);

        $this->pdo->prepare(
            'INSERT INTO audit_logs (event_id, organization_id, project_id, actor_user_id, actor_role, action, outcome, detail, created_at, prev_hash, entry_hash)
             VALUES (:eid, :org, :pid, :uid, :role, :act, :out, :det, :c, :prev, :hash)'
        )->execute([
            ':eid' => $eventId,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':uid' => $actorUserId,
            ':role' => $actorRole,
            ':act' => $action,
            ':out' => $outcome,
            ':det' => $detail,
            ':c' => $now,
            ':prev' => $prevHash,
            ':hash' => $entryHash,
        ]);
    }

    /**
     * @param array<string, mixed> $principal
     */
    private function recordNotificationRow(
        string $id,
        string $orgId,
        string $projectId,
        string $scanId,
        string $channel,
        string $recipient,
        array $principal,
        string $status,
        ?string $rejectionReason,
        string $sanitizedSummary
    ): void {
        $this->pdo->prepare(
            'INSERT INTO approved_notifications (id, organization_id, project_id, scan_run_id, channel, recipient, approved_by_user_id, approved_by_role, status, rejection_reason, sanitized_summary, created_at)
             VALUES (:id, :org, :pid, :sid, :ch, :rec, :uid, :role, :st, :rej, :sum, :c)'
        )->execute([
            ':id' => $id,
            ':org' => $orgId,
            ':pid' => $projectId,
            ':sid' => $scanId,
            ':ch' => $channel,
            ':rec' => $recipient,
            ':uid' => $principal['user_id'],
            ':role' => $principal['role'],
            ':st' => $status,
            ':rej' => $rejectionReason,
            ':sum' => $sanitizedSummary,
            ':c' => gmdate('Y-m-d\TH:i:s\Z'),
        ]);
    }

    /**
     * Absolute, workspace-confined repository paths registered as target assets of a project.
     * Invalid/escaping legacy values are ignored (fail closed).
     *
     * @return list<string>
     */
    private function projectRepositoryPaths(string $projectId, string $orgId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT repository_path FROM target_assets WHERE project_id = :pid AND organization_id = :org'
        );
        $stmt->execute([':pid' => $projectId, ':org' => $orgId]);
        $paths = [];
        foreach ($stmt->fetchAll() as $row) {
            $raw = (string) ($row['repository_path'] ?? '');
            if ($raw === '') {
                continue;
            }
            try {
                $paths[] = RuntimeMode::resolveRepositoryPath($raw);
            } catch (RuntimeException) {
                continue;
            }
        }
        return array_values(array_unique($paths));
    }

    /**
     * Resolves the repository a scan may read. The request body may only NARROW the scope to a
     * sub-path of a repository that is (a) registered as an asset of THIS project and
     * (b) inside the grant's allowed_repositories. It can never widen it (path traversal / BOLA).
     *
     * @param array<string, mixed> $principal
     * @param array<string, mixed> $proj
     * @param array<string, mixed> $grantRow
     */
    private function resolveScanRepositoryPath(array $principal, array $proj, array $grantRow, mixed $requested): string
    {
        $orgId = (string) $proj['organization_id'];
        $projectId = (string) $proj['id'];
        $assetPaths = $this->projectRepositoryPaths($projectId, $orgId);

        $deny = function (string $message) use ($principal, $orgId, $projectId): never {
            $this->appendAuditLog(
                $orgId,
                $projectId,
                (string) $principal['user_id'],
                (string) $principal['role'],
                'trigger_scan',
                'deny',
                'Scan repository path rejected: ' . $message
            );
            throw new RuntimeException($message, 403);
        };

        if ($requested === null || $requested === '') {
            if ($assetPaths === []) {
                throw new RuntimeException('Project has no authorized repository asset to scan', 422);
            }
            $candidate = $assetPaths[0];
        } else {
            $candidate = RuntimeMode::resolveRepositoryPath((string) $requested);
        }

        $insideAsset = false;
        foreach ($assetPaths as $assetPath) {
            if (RuntimeMode::isInside($candidate, $assetPath)) {
                $insideAsset = true;
                break;
            }
        }
        if (!$insideAsset) {
            $deny('repository_path is not a registered asset of this project (cross-project/path traversal denied)');
        }

        $allowedRepos = json_decode((string) ($grantRow['allowed_repositories_json'] ?? '[]'), true) ?: [];
        foreach ($allowedRepos as $allowed) {
            $real = realpath((string) $allowed);
            if ($real !== false && RuntimeMode::isInside($candidate, $real)) {
                return $candidate;
            }
        }
        $deny('repository_path is outside the ScopeAuthorizationGrant allowed_repositories');
    }

    private function validateHostnameSafety(string $hostname): void
    {
        if ($hostname === '' || str_contains($hostname, '*')) {
            throw new RuntimeException('Wildcard or empty hostnames are prohibited in scope grants (SEC-001)', 422);
        }
        $lower = strtolower($hostname);
        if (
            $lower === 'localhost' ||
            str_ends_with($lower, '.local') ||
            str_ends_with($lower, '.internal') ||
            preg_match('/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/', $lower) ||
            str_contains($lower, ':')
        ) {
            throw new RuntimeException('Private, loopback, link-local, metadata, or IP literal targets are prohibited (SEC-002)', 422);
        }
    }

    private function grantProjectMembershipToUser(string $orgId, string $userId, string $projectId): void
    {
        $stmt = $this->pdo->prepare('SELECT id, allowed_project_ids_json FROM organization_members WHERE organization_id = :org AND user_id = :uid LIMIT 1');
        $stmt->execute([':org' => $orgId, ':uid' => $userId]);
        $row = $stmt->fetch();
        if ($row) {
            $projs = json_decode((string) $row['allowed_project_ids_json'], true) ?: [];
            if (!in_array($projectId, $projs, true)) {
                $projs[] = $projectId;
                $this->pdo->prepare('UPDATE organization_members SET allowed_project_ids_json = :p WHERE id = :id')
                    ->execute([':p' => json_encode(array_values($projs)), ':id' => $row['id']]);
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function getProjectRowOrFail(string $projectId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM projects WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $projectId]);
        $row = $stmt->fetch();
        if (!$row) {
            throw new RuntimeException('Project not found', 404);
        }
        return $row;
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    private function hydrateGrantRow(array $row): array
    {
        $row['scope_version'] = (int) $row['scope_version'];
        $row['max_request_budget'] = (int) $row['max_request_budget'];
        $row['allowed_methods'] = json_decode((string) $row['allowed_methods_json'], true) ?: ['GET', 'HEAD'];
        $row['allowed_checks'] = json_decode((string) $row['allowed_checks_json'], true) ?: [];
        $row['targets'] = json_decode((string) $row['targets_json'], true) ?: [];
        $row['allowed_repositories'] = json_decode((string) $row['allowed_repositories_json'], true) ?: [];
        unset($row['allowed_methods_json'], $row['allowed_checks_json'], $row['targets_json'], $row['allowed_repositories_json']);
        return $row;
    }

    /**
     * @param array<string, mixed> $proj
     * @param array<string, mixed> $grantRow
     * @return array<string, mixed>
     */
    private function buildScannerGrantObject(array $proj, array $grantRow): array
    {
        return [
            'schema_version' => '1.0.0',
            'grant_id' => (string) $grantRow['grant_id'],
            'scope_version' => (int) $grantRow['scope_version'],
            'organization_id' => (string) $grantRow['organization_id'],
            'project_id' => (string) $grantRow['project_id'],
            'project_name' => (string) $proj['name'],
            'stack' => json_decode((string) $proj['stack_json'], true) ?: ['laravel', 'generic-web'],
            'profile' => (string) $grantRow['profile'],
            'owner' => (string) $grantRow['owner_name'],
            'authorization_statement' => (string) $grantRow['authorization_statement'],
            'domain_control_proof' => (string) $grantRow['domain_control_proof'],
            'written_permission_ref' => (string) $grantRow['written_permission_ref'],
            'emergency_contact' => (string) $grantRow['emergency_contact'],
            'issued_at' => (string) $grantRow['issued_at'],
            'expires_at' => (string) $grantRow['expires_at'],
            'time_window' => [
                'start_at' => (string) $grantRow['window_start_at'],
                'end_at' => (string) $grantRow['window_end_at'],
            ],
            'max_request_budget' => (int) $grantRow['max_request_budget'],
            'allowed_methods' => json_decode((string) $grantRow['allowed_methods_json'], true) ?: ['GET', 'HEAD'],
            'allowed_checks' => json_decode((string) $grantRow['allowed_checks_json'], true) ?: [],
            'targets' => json_decode((string) $grantRow['targets_json'], true) ?: [],
            'allowed_repositories' => json_decode((string) $grantRow['allowed_repositories_json'], true) ?: [],
        ];
    }
}
