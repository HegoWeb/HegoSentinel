<?php

declare(strict_types=1);

namespace App\Providers;

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Models\Organization;
use App\Models\Project;
use App\Models\RemediationTask;
use App\Models\ScanRun;
use App\Models\User;
use App\Policies\OrganizationPolicy;
use App\Policies\ProjectPolicy;
use App\Policies\RemediationTaskPolicy;
use App\Policies\ScanRunPolicy;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use App\Support\TenantRlsContext;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SecurityPlatformService::class, static function (): SecurityPlatformService {
            return new SecurityPlatformService(DatabaseManager::connection());
        });

        $this->app->singleton(PlatformApiController::class, static function ($app): PlatformApiController {
            return new PlatformApiController($app->make(SecurityPlatformService::class));
        });
    }

    public function boot(): void
    {
        // Bind shared PDO connection into Laravel's Eloquent DatabaseManager
        if ($this->app->bound('db')) {
            try {
                $pdo = DatabaseManager::connection();
                $driver = DatabaseManager::driver();
                $this->app['db']->connection($driver)->setPdo($pdo)->setReadPdo($pdo);
            } catch (\Throwable) {
                // Ignore if database connection is not yet initialized
            }
        }

        // Register Eloquent Policies (S10-01)
        Gate::policy(Organization::class, OrganizationPolicy::class);
        Gate::policy(Project::class, ProjectPolicy::class);
        Gate::policy(ScanRun::class, ScanRunPolicy::class);
        Gate::policy(RemediationTask::class, RemediationTaskPolicy::class);

        // Register RBAC & Tenant Isolation Gate Abilities (SEC-011)
        $roleMatrix = [
            'owner' => [
                'read_report', 'trigger_scan', 'approve_scope', 'suppress_finding',
                'emergency_stop', 'export_artifact', 'manage_project',
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

        $allAbilities = $roleMatrix['owner'];
        foreach ($allAbilities as $ability) {
            Gate::define($ability, static function (?User $user, ?string $resourceOrgId = null, ?string $resourceProjectId = null) use ($ability, $roleMatrix): bool {
                $principal = TenantRlsContext::currentPrincipal();
                if ($principal === null) {
                    return false;
                }
                if ($resourceOrgId !== null && (string) ($principal['organization_id'] ?? '') !== $resourceOrgId) {
                    return false;
                }
                $role = (string) ($principal['role'] ?? '');
                $permitted = $roleMatrix[$role] ?? [];
                if (!in_array($ability, $permitted, true)) {
                    return false;
                }
                if ($resourceProjectId !== null && $role !== 'owner') {
                    $allowedProjs = array_map('strval', (array) ($principal['project_ids'] ?? []));
                    if (!in_array($resourceProjectId, $allowedProjs, true)) {
                        return false;
                    }
                }
                return true;
            });
        }

        // Rate Limiting for API and Authentication
        if (class_exists(RateLimiter::class)) {
            RateLimiter::for('api', static function (Request $request) {
                return Limit::perMinute(120)->by((string) ($request->user()?->id ?: $request->ip()));
            });
            RateLimiter::for('auth-login', static function (Request $request) {
                return Limit::perMinutes(15, 5)->by(strtolower((string) $request->input('email', '')) . '|' . (string) $request->ip());
            });
        }
    }
}
