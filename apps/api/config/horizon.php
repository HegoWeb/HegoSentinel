<?php

declare(strict_types=1);

return [
    'domain' => null,
    'path' => 'horizon',
    'use' => 'default',
    'prefix' => 'hegosentinel_horizon:',
    'middleware' => ['web', 'auth:sanctum'],
    'waits' => [
        'redis:hegosentinel-scans' => 60,
        'redis:hegosentinel-rechecks' => 60,
        'redis:hegosentinel-notifications' => 30,
    ],
    'trim' => [
        'recent' => 60,
        'pending' => 60,
        'completed' => 60,
        'recent_failed' => 10080,
        'failed' => 10080,
        'monitored' => 10080,
    ],
    'silenced' => [],
    'fast_termination' => true,
    'memory_limit' => 256,
    'defaults' => [
        'supervisor-scans' => [
            'connection' => 'redis',
            'queue' => [
                'hegosentinel-scans',
                'hegosentinel-rechecks',
                'hegosentinel-notifications',
            ],
            'balance' => 'auto',
            'autoScalingStrategy' => 'time',
            'maxProcesses' => 4,
            'maxTime' => 0,
            'maxJobs' => 0,
            'memory' => 256,
            'tries' => 1,
            'timeout' => 90,
            'nice' => 0,
        ],
    ],
    'environments' => [
        'production' => [
            'supervisor-scans' => [
                'maxProcesses' => 4,
                'balanceMaxShift' => 1,
                'balanceCooldown' => 3,
            ],
        ],
        'local' => [
            'supervisor-scans' => [
                'maxProcesses' => 2,
            ],
        ],
    ],
];
