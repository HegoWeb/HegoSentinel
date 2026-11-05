<?php

declare(strict_types=1);

return [
    'name' => getenv('APP_NAME') ?: 'HegoSentinel API',
    'env' => getenv('APP_ENV') ?: ($_ENV['APP_ENV'] ?? 'local'),
    'debug' => (getenv('APP_DEBUG') ?: ($_ENV['APP_DEBUG'] ?? 'false')) === 'true',
    'url' => getenv('APP_URL') ?: 'http://127.0.0.1:8000',
    'frontend_url' => getenv('FRONTEND_URL') ?: 'http://127.0.0.1:3000',
    'timezone' => 'UTC',
    'locale' => 'tr',
    'fallback_locale' => 'en',
    'faker_locale' => 'en_US',
    'cipher' => 'AES-256-CBC',
    'key' => getenv('APP_KEY') ?: 'base64:SGVnb1NlbnRpbmVsU3ByaW50OEFwaUtleTIwMjZTZWN1cmU=',
    'previous_keys' => [],
    'maintenance' => [
        'driver' => 'file',
    ],
];
