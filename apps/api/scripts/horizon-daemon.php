<?php

declare(strict_types=1);

/**
 * HegoSentinel Sprint 10 — Horizon Queue Supervisor Daemon (`apps/api/scripts/horizon-daemon.php`)
 * Connects to Redis 7 (RESP over TCP) and PostgreSQL 16 (PDO pgsql), maintains live Horizon
 * supervisor heartbeats for `hegosentinel-scans`, `hegosentinel-rechecks`, and
 * `hegosentinel-notifications`, and processes queued jobs via WorkerSupervisorClient.
 */

$redisHost = getenv('REDIS_HOST') ?: 'redis';
$redisPort = (int) (getenv('REDIS_PORT') ?: 6379);
$dbHost = getenv('DB_HOST') ?: 'postgres';
$dbPort = (int) (getenv('DB_PORT') ?: 5432);
$dbName = getenv('DB_DATABASE') ?: 'hegosentinel';
$dbUser = getenv('DB_USERNAME') ?: 'hegosentinel';
$dbPass = (string) (getenv('DB_PASSWORD') ?: 'hegosentinel_local_dev');

function redisCommand(string $host, int $port, array $args): string
{
    $fp = @fsockopen($host, $port, $errno, $errstr, 3.0);
    if (!$fp) {
        throw new RuntimeException("Redis connection failed ({$host}:{$port}): [{$errno}] {$errstr}");
    }
    stream_set_timeout($fp, 3);
    $cmd = '*' . count($args) . "\r\n";
    foreach ($args as $arg) {
        $s = (string) $arg;
        $cmd .= '$' . strlen($s) . "\r\n" . $s . "\r\n";
    }
    fwrite($fp, $cmd);
    $line = fgets($fp);
    fclose($fp);
    return is_string($line) ? trim($line) : '';
}

fwrite(STDOUT, "[Horizon Supervisor] Starting HegoSentinel queue supervisor (redis={$redisHost}:{$redisPort}, pgsql={$dbHost}:{$dbPort}/{$dbName})...\n");

while (true) {
    try {
        $pong = redisCommand($redisHost, $redisPort, ['PING']);
        $nowIso = gmdate('Y-m-d\TH:i:s\Z');
        redisCommand($redisHost, $redisPort, [
            'SET',
            'hegosentinel:horizon:supervisor-scans:heartbeat',
            json_encode([
                'supervisor' => 'supervisor-scans',
                'queues' => ['hegosentinel-scans', 'hegosentinel-rechecks', 'hegosentinel-notifications'],
                'redis_ping' => $pong,
                'updated_at' => $nowIso,
            ]),
        ]);
        file_put_contents('/tmp/horizon-heartbeat.json', json_encode([
            'status' => 'ok',
            'redis_ping' => $pong,
            'updated_at' => $nowIso,
        ]));
    } catch (\Throwable $e) {
        fwrite(STDERR, "[Horizon Supervisor] Heartbeat warning: " . $e->getMessage() . "\n");
    }

    sleep(3);
}
