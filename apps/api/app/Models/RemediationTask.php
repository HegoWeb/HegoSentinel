<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class RemediationTask extends Model
{
    use BelongsToOrganization;

    protected $table = 'remediation_tasks';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'finding_id',
        'finding_fingerprint',
        'rule_id',
        'title',
        'framework',
        'assigned_to_user_id',
        'assigned_to_name',
        'status',
        'priority',
        'guidance_summary',
        'code_patch_example',
        'validation_command',
        'notes',
        'created_at',
        'updated_at',
    ];
}
