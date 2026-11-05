<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;

final class FalsePositiveSuppression extends Model
{
    use BelongsToOrganization;

    protected $table = 'false_positive_suppressions';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'fingerprint',
        'scope_version',
        'rationale',
        'approved_by',
        'expires_at',
        'created_at',
    ];
}
