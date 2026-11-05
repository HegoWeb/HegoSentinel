<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class Project extends Model
{
    use BelongsToOrganization;

    protected $table = 'projects';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'organization_id',
        'name',
        'slug',
        'environment',
        'stack_json',
        'description',
        'is_demo',
        'created_by_user_id',
        'created_at',
    ];

    protected $casts = [
        'is_demo' => 'boolean',
    ];

    public function assets(): HasMany
    {
        return $this->hasMany(TargetAsset::class, 'project_id', 'id');
    }

    public function grants(): HasMany
    {
        return $this->hasMany(ScopeAuthorizationGrant::class, 'project_id', 'id');
    }

    public function scanRuns(): HasMany
    {
        return $this->hasMany(ScanRun::class, 'project_id', 'id');
    }
}

