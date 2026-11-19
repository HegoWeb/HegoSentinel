<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class ApprovedNotification extends Model
{
    use BelongsToOrganization;

    protected $table = 'approved_notifications';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'scan_run_id',
        'channel',
        'recipient',
        'approved_by_user_id',
        'approved_by_role',
        'status',
        'rejection_reason',
        'sanitized_summary',
        'created_at',
    ];
}

