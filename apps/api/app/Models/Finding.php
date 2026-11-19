<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class Finding extends Model
{
    use BelongsToOrganization;

    protected $table = 'findings';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'scan_run_id',
        'organization_id',
        'project_id',
        'grant_id',
        'scope_version',
        'rule_id',
        'rule_version',
        'asset_key',
        'fingerprint',
        'title',
        'observed_condition',
        'evidence_summary',
        'evidence_hash',
        'inferred_risk',
        'limitations',
        'confidence',
        'risk_priority',
        'verification_status',
        'standards_json',
        'remediation_json',
        'validation_criterion',
        'data_source',
        'observed_at',
    ];

    public function scanRun(): BelongsTo
    {
        return $this->belongsTo(ScanRun::class, 'scan_run_id', 'id');
    }

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id', 'id');
    }
}

