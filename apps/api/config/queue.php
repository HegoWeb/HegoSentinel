<?php

declare(strict_types=1);

return [
    'default' => getenv('QUEUE_CONNECTION') ?: ($_ENV['QUEUE_CONNECTION'] ?? 'redis'),

    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],

        'redis' => [
            'driver' => 'redis',
            'connection' => 'default',
            'queue' => getenv('REDIS_QUEUE') ?: 'hegosentinel-scans',
            'retry_after' => 120,
            'block_for' => 5,
            'after_commit' => true,
        ],

        'database' => [
            'driver' => 'database',
            'connection' => getenv('DB_CONNECTION') ?: 'pgsql',
            'table' => 'scan_queue_jobs',
            'queue' => 'hegosentinel-scans',
            'retry_after' => 120,
            'after_commit' => true,
        ],
    ],

    'queues' => [
        'scans' => 'hegosentinel-scans',
        'rechecks' => 'hegosentinel-rechecks',
        'notifications' => 'hegosentinel-notifications',
    ],

    'failed' => [
        'driver' => 'database-uuids',
        'database' => getenv('DB_CONNECTION') ?: 'pgsql',
        'table' => 'failed_jobs',
    ],

    'horizon' => [
        'environments' => [
            'production' => [
                'supervisor-scans' => [
                    'connection' => 'redis',
                    'queue' => [
                        'hegosentinel-scans',
                        'hegosentinel-rechecks',
                        'hegosentinel-notifications',
                    ],
                    'balance' => 'auto',
                    'maxProcesses' => 4,
                    'memory' => 256,
                    'tries' => 1,
                    'timeout' => 90,
                ],
            ],
            'local' => [
                'supervisor-scans' => [
                    'connection' => 'redis',
                    'queue' => [
                        'hegosentinel-scans',
                        'hegosentinel-rechecks',
                        'hegosentinel-notifications',
                    ],
                    'balance' => 'simple',
                    'maxProcesses' => 2,
                    'memory' => 256,
                    'tries' => 1,
                    'timeout' => 90,
                ],
            ],
        ],
    ],
];
