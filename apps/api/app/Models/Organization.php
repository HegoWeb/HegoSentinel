<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class Organization extends Model
{
    protected $table = 'organizations';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'slug',
        'name',
        'verified_notification_domains_json',
        'created_by_user_id',
        'created_at',
    ];

    public function members(): HasMany
    {
        return $this->hasMany(OrganizationMember::class, 'organization_id', 'id');
    }

    public function projects(): HasMany
    {
        return $this->hasMany(Project::class, 'organization_id', 'id');
    }
}
