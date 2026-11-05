<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class TargetAsset extends Model
{
    use BelongsToOrganization;

    protected $table = 'target_assets';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'project_id',
        'asset_type',
        'scheme',
        'hostname',
        'port',
        'path_prefix',
        'repository_path',
        'domain_ownership_verified',
        'domain_verification_token',
        'domain_verified_at',
        'created_at',
    ];

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id', 'id');
    }
}
