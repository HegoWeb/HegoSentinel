<?php

declare(strict_types=1);

namespace App\Support;

use Database\Migrations\CreateHegosentinelPlatformTables;
use PDO;

require_once __DIR__ . '/../../database/migrations/2026_11_05_000001_create_hegosentinel_platform_tables.php';

final class DatabaseManager
{
    private static ?PDO $pdo = null;
    private static string $driver = 'sqlite';

    public static function connection(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $config = require __DIR__ . '/../../config/database.php';
        $defaultDriver = (string) ($config['default'] ?? 'sqlite');

        if ($defaultDriver === 'pgsql' && extension_loaded('pdo_pgsql')) {
            $pg = $config['connections']['pgsql'];
            $dsn = sprintf(
                'pgsql:host=%s;port=%s;dbname=%s',
                $pg['host'],
                $pg['port'],
                $pg['database']
            );
            self::$pdo = new PDO($dsn, (string) $pg['username'], (string) $pg['password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            self::$driver = 'pgsql';
        } else {
            $sqlitePath = (string) $config['connections']['sqlite']['database'];
            if ($sqlitePath !== ':memory:') {
                $dir = dirname($sqlitePath);
                if (!is_dir($dir)) {
                    mkdir($dir, 0775, true);
                }
            }
            self::$pdo = new PDO('sqlite:' . $sqlitePath, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            self::$pdo->exec('PRAGMA foreign_keys = ON;');
            if ($sqlitePath !== ':memory:') {
                self::$pdo->exec('PRAGMA journal_mode = WAL;');
            }
            self::$driver = 'sqlite';
        }

        CreateHegosentinelPlatformTables::migrate(self::$pdo, self::$driver);
        return self::$pdo;
    }

    public static function connect(): PDO
    {
        return self::connection();
    }

    public static function migrate(PDO $pdo, string $driver = 'sqlite'): void
    {
        CreateHegosentinelPlatformTables::migrate($pdo, $driver);
    }

    public static function resetConnection(?PDO $customPdo = null, string $driver = 'sqlite'): void
    {
        self::$pdo = $customPdo;
        self::$driver = $driver;
        if (self::$pdo !== null) {
            CreateHegosentinelPlatformTables::migrate(self::$pdo, self::$driver);
        }
    }

    public static function driver(): string
    {
        return self::$driver;
    }
}
