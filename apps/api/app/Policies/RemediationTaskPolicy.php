<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\RemediationTask;
use App\Models\User;
use App\Support\TenantRlsContext;

final class RemediationTaskPolicy
{
    public function view(User $user, RemediationTask $task): bool
    {
        return $this->hasTaskAccess($task, ['owner', 'security_lead', 'developer', 'viewer']);
    }

    public function update(User $user, RemediationTask $task): bool
    {
        return $this->hasTaskAccess($task, ['owner', 'security_lead', 'developer']);
    }

    /**
     * @param list<string> $allowedRoles
     */
    private function hasTaskAccess(RemediationTask $task, array $allowedRoles): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        if ($principal === null) {
            return false;
        }
        if ((string) ($principal['organization_id'] ?? '') !== (string) $task->organization_id) {
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
        return in_array((string) $task->project_id, $allowedProjectIds, true);
    }
}
