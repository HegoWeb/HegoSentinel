<?php

declare(strict_types=1);

use App\Http\Controllers\Api\V1\PlatformApiController;

/**
 * HegoSentinel Laravel API Route Manifest (`/api/v1/*`)
 *
 * Compatible with both standard Laravel Routing (`Illuminate\Support\Facades\Route`)
 * and zero-dependency native PHP 8.2 execution via `public/index.php`.
 */
return [
    ['method' => 'GET',   'uri' => '/api/v1/health',                       'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/login',                   'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/register',                'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/password-reset',          'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/logout',                  'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/auth/me',                      'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/dashboard',                    'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/organization',                 'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/organization/members',         'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/projects',                     'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/projects',                     'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/projects/{id}/grants',         'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/scans',                        'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/scans',                        'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/scans/{id}',                   'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/scans/{id}/export',            'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/findings',                     'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/findings/{id}/suppress',       'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/remediation-tasks',            'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'PATCH', 'uri' => '/api/v1/remediation-tasks/{id}',       'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/rechecks',                     'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/rechecks',                     'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/notifications',                'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/notifications',                'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/emergency-stop',               'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'POST',  'uri' => '/api/v1/emergency-stop',               'action' => [PlatformApiController::class, 'handle']],
    ['method' => 'GET',   'uri' => '/api/v1/audit-logs',                   'action' => [PlatformApiController::class, 'handle']],
];

