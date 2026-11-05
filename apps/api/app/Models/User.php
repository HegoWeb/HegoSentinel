<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

final class User extends Authenticatable
{
    use HasApiTokens;
    use Notifiable;

    protected $table = 'users';
    protected $primaryKey = 'id';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'id',
        'email',
        'name',
        'password_hash',
        'preferred_locale',
        'mfa_enabled',
        'created_at',
        'updated_at',
    ];

    protected $hidden = [
        'password_hash',
    ];

    protected $casts = [
        'mfa_enabled' => 'boolean',
    ];

    public function getAuthPassword(): string
    {
        return (string) $this->password_hash;
    }

    public function memberships(): HasMany
    {
        return $this->hasMany(OrganizationMember::class, 'user_id', 'id');
    }

    public function sessions(): HasMany
    {
        return $this->hasMany(UserSession::class, 'user_id', 'id');
    }
}
