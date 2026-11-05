<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class AuditLog extends Model
{
    use BelongsToOrganization;

    protected $table = 'audit_logs';
    protected $primaryKey = 'sequence';
    public $incrementing = true;
    protected $keyType = 'int';
    public $timestamps = false;

    protected $fillable = [
        'event_id',
        'organization_id',
        'project_id',
        'actor_user_id',
        'actor_role',
        'action',
        'outcome',
        'detail',
        'created_at',
        'prev_hash',
        'entry_hash',
    ];
}

