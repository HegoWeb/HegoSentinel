<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class ScanRun extends Model
{
    use BelongsToOrganization;

    protected $table = 'scan_runs';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'grant_id',
        'scope_version',
        'profile',
        'mode',
        'data_source',
        'status',
        'global_coverage_status',
        'scanner_version',
        'total_findings',
        'critical_count',
        'high_count',
        'medium_count',
        'low_count',
        'coverage_checks_json',
        'report_payload_json',
        'emergency_stop_token_id',
        'triggered_by_user_id',
        'started_at',
        'completed_at',
        'cancelled_reason',
    ];

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id', 'id');
    }

    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class, 'scan_run_id', 'id');
    }
}

