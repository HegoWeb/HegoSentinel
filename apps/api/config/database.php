<?php

declare(strict_types=1);

return [
    'default' => getenv('DB_CONNECTION') ?: ($_ENV['DB_CONNECTION'] ?? 'sqlite'),

    'connections' => [
        'pgsql' => [
            'driver' => 'pgsql',
            'host' => getenv('DB_HOST') ?: ($_ENV['DB_HOST'] ?? '127.0.0.1'),
            'port' => getenv('DB_PORT') ?: ($_ENV['DB_PORT'] ?? '5432'),
            'database' => getenv('DB_DATABASE') ?: ($_ENV['DB_DATABASE'] ?? 'hegosentinel'),
            'username' => getenv('DB_USERNAME') ?: ($_ENV['DB_USERNAME'] ?? 'hegosentinel_app'),
            'password' => getenv('DB_PASSWORD') ?: ($_ENV['DB_PASSWORD'] ?? ''),
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => getenv('DB_SSLMODE') ?: 'prefer',
        ],

        'pgsql_admin' => [
            'driver' => 'pgsql',
            'host' => getenv('DB_HOST') ?: ($_ENV['DB_HOST'] ?? '127.0.0.1'),
            'port' => getenv('DB_PORT') ?: ($_ENV['DB_PORT'] ?? '5432'),
            'database' => getenv('DB_DATABASE') ?: ($_ENV['DB_DATABASE'] ?? 'hegosentinel'),
            'username' => getenv('DB_ADMIN_USERNAME') ?: (getenv('DB_USERNAME') ?: 'postgres'),
            'password' => getenv('DB_ADMIN_PASSWORD') ?: (getenv('DB_PASSWORD') ?: ''),
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => getenv('DB_SSLMODE') ?: 'prefer',
        ],

        'sqlite' => [
            'driver' => 'sqlite',
            'database' => getenv('DB_SQLITE_PATH') ?: (getenv('DB_DATABASE') ?: (__DIR__ . '/../database/hegosentinel.sqlite')),
            'prefix' => '',
            'foreign_key_constraints' => true,
        ],
    ],

    'migrations' => [
        'table' => 'migrations',
        'update_date_on_publish' => true,
    ],

    'redis' => [
        'client' => getenv('REDIS_CLIENT') ?: 'phpredis',
        'options' => [
            'cluster' => 'redis',
            'prefix' => 'hegosentinel_database_',
        ],
        'default' => [
            'url' => getenv('REDIS_URL') ?: null,
            'host' => getenv('REDIS_HOST') ?: '127.0.0.1',
            'username' => getenv('REDIS_USERNAME') ?: null,
            'password' => getenv('REDIS_PASSWORD') ?: null,
            'port' => getenv('REDIS_PORT') ?: '6379',
            'database' => getenv('REDIS_DB') ?: '0',
        ],
        'cache' => [
            'url' => getenv('REDIS_URL') ?: null,
            'host' => getenv('REDIS_HOST') ?: '127.0.0.1',
            'username' => getenv('REDIS_USERNAME') ?: null,
            'password' => getenv('REDIS_PASSWORD') ?: null,
            'port' => getenv('REDIS_PORT') ?: '6379',
            'database' => getenv('REDIS_CACHE_DB') ?: '1',
        ],
    ],
];
