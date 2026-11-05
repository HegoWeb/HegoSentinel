<?php

declare(strict_types=1);

namespace App\Models\Concerns;

use App\Models\Organization;
use App\Support\TenantRlsContext;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use RuntimeException;

/**
 * Laravel Eloquent Multi-Tenant Global Scope & Mutation Guard (S10-01 & SEC-011).
 *
 * Automatically scopes Eloquent queries to `TenantRlsContext::currentOrganizationId()`
 * (failing closed to zero rows when tenant context is missing) and prevents cross-tenant
 * `organization_id` spoofing during model creation or update.
 */
trait BelongsToOrganization
{
    public static function bootBelongsToOrganization(): void
    {
        static::addGlobalScope('tenant_organization', static function (Builder $builder): void {
            $orgId = TenantRlsContext::currentOrganizationId();
            $table = $builder->getModel()->getTable();
            if ($orgId === null || $orgId === '') {
                // Fail-closed when no authenticated tenant context is bound
                $builder->whereRaw('1 = 0');
                return;
            }
            $builder->where($table . '.organization_id', '=', $orgId);
        });

        static::creating(static function (Model $model): void {
            $orgId = TenantRlsContext::currentOrganizationId();
            if ($orgId === null || $orgId === '') {
                throw new RuntimeException('Tenant context required to create tenant-scoped Eloquent model (SEC-011)', 403);
            }
            $existing = $model->getAttribute('organization_id');
            if ($existing !== null && $existing !== '' && (string) $existing !== $orgId) {
                throw new RuntimeException('Cross-organization model creation denied (SEC-011)', 403);
            }
            $model->setAttribute('organization_id', $orgId);
        });

        static::updating(static function (Model $model): void {
            $orgId = TenantRlsContext::currentOrganizationId();
            if ($orgId === null || $orgId === '') {
                throw new RuntimeException('Tenant context required to update tenant-scoped Eloquent model (SEC-011)', 403);
            }
            $originalOrg = (string) $model->getOriginal('organization_id');
            $currentOrg = (string) $model->getAttribute('organization_id');
            if (($originalOrg !== '' && $originalOrg !== $orgId) || ($currentOrg !== '' && $currentOrg !== $orgId)) {
                throw new RuntimeException('Cross-organization model mutation denied (SEC-011)', 403);
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id', 'id');
    }
}
