<?php

declare(strict_types=1);

return [
    'default' => getenv('DB_CONNECTION') ?: 'sqlite',

    'connections' => [
        'pgsql' => [
            'driver' => 'pgsql',
            'host' => getenv('DB_HOST') ?: '127.0.0.1',
            'port' => getenv('DB_PORT') ?: '5432',
            'database' => getenv('DB_DATABASE') ?: 'hegosentinel',
            'username' => getenv('DB_USERNAME') ?: 'hegosentinel',
            'password' => getenv('DB_PASSWORD') ?: '',
            'charset' => 'utf8',
            'prefix' => '',
            'schema' => 'public',
            'sslmode' => 'prefer',
        ],

        'sqlite' => [
            'driver' => 'sqlite',
            'database' => getenv('DB_SQLITE_PATH') ?: getenv('DB_DATABASE') ?: (__DIR__ . '/../database/hegosentinel.sqlite'),
            'prefix' => '',
            'foreign_key_constraints' => true,
        ],
    ],
];

