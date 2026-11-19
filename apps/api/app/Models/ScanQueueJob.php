<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class ScanQueueJob extends Model
{
    use BelongsToOrganization;

    protected $table = 'scan_queue_jobs';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'scan_run_id',
        'queue_name',
        'worker_isolation_mode',
        'status',
        'attempts',
        'worker_pid',
        'dispatched_at',
        'finished_at',
        'error_message',
    ];
}

