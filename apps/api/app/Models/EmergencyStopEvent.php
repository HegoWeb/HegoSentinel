<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class EmergencyStopEvent extends Model
{
    use BelongsToOrganization;

    protected $table = 'emergency_stop_events';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'scan_run_id',
        'emergency_stop_token_id',
        'triggered_by_user_id',
        'reason',
        'subprocesses_terminated',
        'created_at',
    ];
}

