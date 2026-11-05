<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Organization;
use App\Models\User;
use App\Support\TenantRlsContext;

final class OrganizationPolicy
{
    public function view(User $user, Organization $organization): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        return $principal !== null && (string) ($principal['organization_id'] ?? '') === (string) $organization->id;
    }

    public function manageTeam(User $user, Organization $organization): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        return $principal !== null
            && (string) ($principal['organization_id'] ?? '') === (string) $organization->id
            && (string) ($principal['role'] ?? '') === 'owner';
    }

    public function readAudit(User $user, Organization $organization): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        return $principal !== null
            && (string) ($principal['organization_id'] ?? '') === (string) $organization->id
            && in_array((string) ($principal['role'] ?? ''), ['owner', 'security_lead'], true);
    }
}
