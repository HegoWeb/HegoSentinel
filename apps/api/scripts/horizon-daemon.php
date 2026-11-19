<?php

declare(strict_types=1);

/**
 * HegoSentinel Sprint 11 — Laravel Horizon Supervisor Entrypoint (`apps/api/scripts/horizon-daemon.php`)
 *
 * Delegates directly to `php artisan horizon` so the `horizon` service boots the real Laravel 11
 * Console Kernel, spawns supervised `horizon:work` queue worker processes across
 * `hegosentinel-scans`, `hegosentinel-rechecks`, and `hegosentinel-notifications`,
 * monitors child worker PIDs with automatic crash recovery (`supervisor_restarts`),
 * and processes Redis queue jobs under `TenantRlsContext`.
 */

$_SERVER['argv'] = array_merge(['artisan', 'horizon'], array_slice($argv ?? [], 1));
$_SERVER['argc'] = count($_SERVER['argv']);
$argv = $_SERVER['argv'];
$argc = $_SERVER['argc'];

require __DIR__ . '/../artisan';
