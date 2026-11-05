<?php

declare(strict_types=1);

namespace App\Support;

use RuntimeException;

/**
 * Central, server-side-only runtime policy.
 *
 * - Demo mode (known demo users / demo password / seeded demo tenants) can ONLY be enabled by the
 *   operator through the process environment (`HEGOSENTINEL_DEMO_MODE=1`) and is hard-disabled
 *   whenever `APP_ENV` is `production`/`prod`. It is never derived from any HTTP header, query or body.
 * - Repository paths supplied by users are confined to a workspace root (default: `<repo>/examples`).
 */
final class RuntimeMode
{
    public static function isProduction(): bool
    {
        $env = getenv('APP_ENV');
        if ($env === false || $env === '') {
            $env = (string) ($_ENV['APP_ENV'] ?? 'local');
        }
        return in_array(strtolower((string) $env), ['production', 'prod'], true);
    }

    public static function demoModeEnabled(): bool
    {
        if (self::isProduction()) {
            return false;
        }
        return getenv('HEGOSENTINEL_DEMO_MODE') === '1';
    }

    public static function repoRoot(): string
    {
        return realpath(__DIR__ . '/../../../..') ?: (string) getcwd();
    }

    public static function workspaceRoot(): string
    {
        $configured = getenv('HEGOSENTINEL_WORKSPACE_ROOT');
        $candidate = ($configured !== false && $configured !== '')
            ? $configured
            : self::repoRoot() . DIRECTORY_SEPARATOR . 'examples';
        $real = realpath($candidate);
        if ($real === false) {
            throw new RuntimeException('Configured workspace root does not exist', 500);
        }
        return $real;
    }

    /**
     * Resolves a user-supplied repository path to an absolute real path that is guaranteed to be
     * inside the workspace root. Rejects absolute paths, drive letters, UNC paths, NUL bytes and `..`.
     *
     * @throws RuntimeException (422) when the path escapes or does not exist
     */
    public static function resolveRepositoryPath(string $path): string
    {
        $path = trim($path);
        $normalized = str_replace('\\', '/', $path);
        if (
            $normalized === ''
            || str_contains($normalized, "\0")
            || str_starts_with($normalized, '/')
            || str_starts_with($normalized, '//')
            || preg_match('#^[A-Za-z]:#', $normalized) === 1
            || in_array('..', explode('/', $normalized), true)
        ) {
            throw new RuntimeException('repository_path must be a relative path inside the authorized workspace (path traversal rejected)', 422);
        }

        $root = self::workspaceRoot();
        $full = realpath(self::repoRoot() . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $normalized));
        if ($full === false || !is_dir($full)) {
            throw new RuntimeException('repository_path does not exist inside the authorized workspace', 422);
        }
        if (!self::isInside($full, $root)) {
            throw new RuntimeException('repository_path resolves outside the authorized workspace (symlink/path traversal rejected)', 422);
        }
        return $full;
    }

    public static function isInside(string $candidate, string $root): bool
    {
        $c = rtrim(str_replace('\\', '/', $candidate), '/') . '/';
        $r = rtrim(str_replace('\\', '/', $root), '/') . '/';
        if (DIRECTORY_SEPARATOR === '\\') {
            $c = strtolower($c);
            $r = strtolower($r);
        }
        return str_starts_with($c, $r);
    }

    /** Returns the repo-relative, forward-slash form of an absolute workspace path. */
    public static function toRepoRelative(string $absolute): string
    {
        $root = rtrim(str_replace('\\', '/', self::repoRoot()), '/') . '/';
        $abs = str_replace('\\', '/', $absolute);
        if (str_starts_with(strtolower($abs), strtolower($root))) {
            return substr($abs, strlen($root));
        }
        return $abs;
    }
}

