<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\ScanRun;
use App\Models\User;
use App\Support\TenantRlsContext;

final class ScanRunPolicy
{
    public function view(User $user, ScanRun $scanRun): bool
    {
        return $this->hasScanAccess($scanRun, ['owner', 'security_lead', 'developer', 'viewer']);
    }

    public function export(User $user, ScanRun $scanRun): bool
    {
        return $this->hasScanAccess($scanRun, ['owner', 'security_lead', 'developer']);
    }

    public function suppressFinding(User $user, ScanRun $scanRun): bool
    {
        return $this->hasScanAccess($scanRun, ['owner', 'security_lead']);
    }

    /**
     * @param list<string> $allowedRoles
     */
    private function hasScanAccess(ScanRun $scanRun, array $allowedRoles): bool
    {
        $principal = TenantRlsContext::currentPrincipal();
        if ($principal === null) {
            return false;
        }
        if ((string) ($principal['organization_id'] ?? '') !== (string) $scanRun->organization_id) {
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
        return in_array((string) $scanRun->project_id, $allowedProjectIds, true);
    }
}
