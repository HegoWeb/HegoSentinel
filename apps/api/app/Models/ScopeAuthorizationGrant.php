<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class ScopeAuthorizationGrant extends Model
{
    use BelongsToOrganization;

    protected $table = 'scope_authorization_grants';
    protected $primaryKey = 'grant_id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'grant_id',
        'organization_id',
        'project_id',
        'scope_version',
        'profile',
        'owner_name',
        'authorization_statement',
        'domain_control_proof',
        'written_permission_ref',
        'emergency_contact',
        'issued_at',
        'expires_at',
        'window_start_at',
        'window_end_at',
        'max_request_budget',
        'allowed_methods_json',
        'allowed_checks_json',
        'targets_json',
        'allowed_repositories_json',
        'approved_by_user_id',
        'status',
        'created_at',
    ];

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id', 'id');
    }
}
