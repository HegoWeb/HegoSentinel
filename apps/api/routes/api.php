<?php

declare(strict_types=1);

use App\Http\Controllers\Api\V1\PlatformApiController;
use Illuminate\Support\Facades\Route;

/**
 * HegoSentinel Laravel 11 API Routes (`/api/v1/*`)
 *
 * Registers real Laravel 11 routes via `Illuminate\Support\Facades\Route` when booted inside
 * the Laravel HTTP Kernel, and returns the canonical route manifest array for inspection/tooling.
 */
$manifest = [
    ['method' => 'GET',   'uri' => '/health',                               'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/readiness',                            'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/health',                        'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/readiness',                     'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/login',                    'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/register',                 'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/password-reset',           'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/auth/logout',                   'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/auth/me',                       'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/dashboard',                     'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/organization',                  'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/organization/members',          'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/projects',                      'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/projects',                      'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/projects/{id}/grants',          'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/scans',                         'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/scans',                         'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/scans/{id}',                    'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/scans/{id}/export',             'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/findings',                      'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/findings/{id}/suppress',        'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/remediation-tasks',             'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'PATCH', 'uri' => '/api/v1/remediation-tasks/{id}',        'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/remediation-tasks/{id}',        'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/rechecks',                      'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/rechecks',                      'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/notifications',                 'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/notifications',                 'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/emergency-stop',                'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'POST',  'uri' => '/api/v1/emergency-stop',                'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/audit-logs',                    'action' => [PlatformApiController::class, 'handleLaravelRequest']],
    ['method' => 'GET',   'uri' => '/api/v1/queues/status',                 'action' => [PlatformApiController::class, 'handleLaravelRequest']],
];

if (class_exists(Route::class) && Route::getFacadeRoot() !== null) {
    foreach ($manifest as $entry) {
        Route::match([$entry['method']], $entry['uri'], $entry['action']);
    }
    Route::fallback([PlatformApiController::class, 'handleLaravelRequest']);
}

return $manifest;
