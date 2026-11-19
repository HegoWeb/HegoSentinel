<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Project;
use App\Models\User;
use App\Support\TenantRlsContext;

final class ProjectPolicy
{
    public function view(User $user, Project $project): bool
    {
        return $this->hasProjectAccess($project, ['owner', 'security_lead', 'developer', 'viewer']);
    }

    public function create(User $user): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        return $principal !== null && in_array((string) ($principal['role'] ?? ''), ['owner', 'security_lead'], true);
    }

    public function approveScope(User $user, Project $project): bool
    {
        return $this->hasProjectAccess($project, ['owner', 'security_lead']);
    }

    public function triggerScan(User $user, Project $project): bool
    {
        return $this->hasProjectAccess($project, ['owner', 'security_lead', 'developer']);
    }

    public function emergencyStop(User $user, Project $project): bool
    {
        return $this->hasProjectAccess($project, ['owner', 'security_lead']);
    }

    public function approveNotification(User $user, Project $project): bool
    {
        return $this->hasProjectAccess($project, ['owner', 'security_lead']);
    }

    /**
     * @param list<string> $allowedRoles
     */
    private function hasProjectAccess(Project $project, array $allowedRoles): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        if ($principal === null) {
            return false;
        }
        if ((string) ($principal['organization_id'] ?? '') !== (string) $project->organization_id) {
            return false;
        }
        $role = (string) ($principal['role'] ?? '');
        if (!in_array($role, $allowedRoles, true)) {
            return false;
        }
        if ($role === 'owner') {
            return true;
        }
        $allowedProjectIds = array_map('strval', (array) ($principal['project_ids'] ?? []));
        return in_array((string) $project->id, $allowedProjectIds, true);
    }
}

