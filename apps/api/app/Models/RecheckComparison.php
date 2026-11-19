<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class RecheckComparison extends Model
{
    use BelongsToOrganization;

    protected $table = 'recheck_comparisons';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'baseline_scan_id',
        'current_scan_id',
        'comparable',
        'non_comparable_reason',
        'counts_json',
        'items_json',
        'created_by_user_id',
        'created_at',
    ];
}

