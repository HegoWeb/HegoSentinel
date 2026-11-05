<?php

declare(strict_types=1);

namespace App\Models;

use App\Models\Concerns\BelongsToOrganization;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class UserSession extends Model
{
    use BelongsToOrganization;

    protected $table = 'user_sessions';
    protected $primaryKey = 'token_hash';
    public $incrementing = false;
    protected $keyType = 'string';
    public $timestamps = false;

    protected $fillable = [
        'token_hash',
        'user_id',
        'organization_id',
        'ip_address',
        'user_agent',
        'issued_at',
        'expires_at',
        'revoked_at',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}
