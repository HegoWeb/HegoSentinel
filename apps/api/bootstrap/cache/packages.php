<?php

declare(strict_types=1);

return [
    'laravel/horizon' => [
        'providers' => [
            'Laravel\\Horizon\\HorizonServiceProvider',
        ],
        'aliases' => [
            'Horizon' => 'Laravel\\Horizon\\Horizon',
        ],
    ],
    'laravel/sanctum' => [
        'providers' => [
            'Laravel\\Sanctum\\SanctumServiceProvider',
        ],
    ],
    'nesbot/carbon' => [
        'providers' => [
            'Carbon\\Laravel\\ServiceProvider',
        ],
    ],
    'nunomaduro/termwind' => [
        'providers' => [
            'Termwind\\Laravel\\TermwindServiceProvider',
        ],
    ],
];

