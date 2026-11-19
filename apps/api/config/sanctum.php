<?php

declare(strict_types=1);

return [
    'stateful' => explode(',', getenv('SANCTUM_STATEFUL_DOMAINS') ?: 'localhost,localhost:3000,127.0.0.1,127.0.0.1:3000,127.0.0.1:8000'),
    'guard' => ['web'],
    'expiration' => 1440,
    'token_prefix' => 'hst_',
    'middleware' => [
        'authenticate_session' => Laravel\Sanctum\Http\Middleware\AuthenticateSession::class,
        'encrypt_cookies' => Illuminate\Cookie\Middleware\EncryptCookies::class,
        'validate_csrf_token' => Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class,
    ],
];

