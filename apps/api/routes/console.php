<?php

declare(strict_types=1);

use App\Queue\HorizonRedisQueueEngine;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use Illuminate\Support\Facades\Artisan;

require_once __DIR__ . '/../app/Queue/HorizonRedisQueueEngine.php';
require_once __DIR__ . '/../app/Support/DatabaseManager.php';

Artisan::command('hegosentinel:verify-audit', function (): void {
    $service = app(SecurityPlatformService::class);
    $result = $service->verifyAuditChainIntegrity();
    $this->info((string) json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
})->purpose('Verify the SHA-256 hash chain integrity of audit_logs');

Artisan::command('horizon:status', function (): void {
    $engine = new HorizonRedisQueueEngine();
    $telemetry = $engine->getLiveHorizonTelemetry();
    $this->line((string) json_encode($telemetry, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
})->purpose('Display live Laravel Horizon supervisor, worker PIDs, and Redis queue telemetry');

Artisan::command('horizon:work {--queue=hegosentinel-scans,hegosentinel-rechecks,hegosentinel-notifications} {--supervisor=supervisor-scans} {--worker-id=worker-1} {--once} {--max-jobs=0} {--max-loops=0} {--crash-immediately}', function (): int {
    if ((bool) $this->option('crash-immediately')) {
        exit(1);
    }

    $queueOpt = (string) $this->option('queue');
    $queues = array_values(array_filter(array_map('trim', explode(',', $queueOpt))));
    $supervisorName = (string) $this->option('supervisor');
    $workerId = (string) $this->option('worker-id') . '-' . getmypid();
    $runOnce = (bool) $this->option('once');
    $maxJobs = (int) $this->option('max-jobs');
    $maxLoops = (int) $this->option('max-loops');

    $pdo = null;
    $engine = new HorizonRedisQueueEngine();
    $processed = 0;
    $loops = 0;

    while (true) {
        $loops++;
        try {
            $hasPending = false;
            foreach ($queues as $qName) {
                if ((int) $engine->command(['LLEN', "queues:{$qName}"]) > 0) {
                    $hasPending = true;
                    break;
                }
            }
            if ($hasPending) {
                $pdo ??= DatabaseManager::connect();
                $out = $engine->popAndProcessNext($pdo, $queues, $workerId, $supervisorName);
                if ($out !== null) {
                    $processed++;
                    $this->info('[Horizon Worker ' . $workerId . '] Processed job: ' . json_encode([
                        'job_id' => $out['job_id'] ?? null,
                        'scan_id' => $out['scan_id'] ?? null,
                        'organization_id' => $out['organization_id'] ?? null,
                        'status' => $out['status'] ?? null,
                    ]));
                }
            }
        } catch (\Throwable $e) {
            fwrite(STDERR, '[Horizon Worker ' . $workerId . '] Error: ' . $e->getMessage() . "\n");
        }

        if ($runOnce || ($maxJobs > 0 && $processed >= $maxJobs) || ($maxLoops > 0 && $loops >= $maxLoops)) {
            break;
        }

        usleep(100_000); // 100ms queue poll interval
    }

    return 0;
})->purpose('Run a supervised Laravel Horizon Redis queue worker process');

Artisan::command('horizon {--workers=2} {--max-cycles=0} {--simulate-worker-crash}', function (): int {
    $workerCount = max(1, min(8, (int) $this->option('workers')));
    $maxCycles = (int) $this->option('max-cycles');
    $simulateCrash = (bool) $this->option('simulate-worker-crash');
    $engine = new HorizonRedisQueueEngine();
    $artisanPath = realpath(__DIR__ . '/../artisan') ?: (__DIR__ . '/../artisan');
    $phpBin = PHP_BINARY ?: 'php';
    $nullSink = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';

    /** @var array<int, array{process: resource, pid: int, started_at: string, restarts: int}> $pool */
    $pool = [];
    $totalRestarts = 0;

    $spawnWorker = static function (int $slot, int $restarts, bool $crashThisSpawn = false) use ($phpBin, $artisanPath, $maxCycles): array {
        $cmd = [
            $phpBin,
            $artisanPath,
            'horizon:work',
            '--queue=hegosentinel-scans,hegosentinel-rechecks,hegosentinel-notifications',
            '--supervisor=supervisor-scans',
            '--worker-id=slot-' . $slot,
        ];
        if ($maxCycles > 0) {
            $cmd[] = '--once';
        }
        if ($crashThisSpawn) {
            $cmd[] = '--crash-immediately';
        }
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $proc = proc_open($cmd, $descriptors, $pipes, dirname($artisanPath), null, ['bypass_shell' => true]);
        if (!is_resource($proc)) {
            throw new \RuntimeException("Failed to spawn Horizon worker process for slot {$slot}");
        }
        @fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $status = proc_get_status($proc);
        return [
            'process' => $proc,
            'pipes' => $pipes,
            'pid' => (int) ($status['pid'] ?? 0),
            'started_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'restarts' => $restarts,
        ];
    };

    for ($slot = 1; $slot <= $workerCount; $slot++) {
        $pool[$slot] = $spawnWorker($slot, 0, $simulateCrash && $slot === 1);
    }

    $this->info(sprintf(
        '[Laravel Horizon] Master supervisor-scans booted (master_pid=%d, workers=%d)',
        (int) getmypid(),
        $workerCount
    ));

    $cycle = 0;
    while (true) {
        $cycle++;
        if ($simulateCrash && $cycle === 1 && isset($pool[1])) {
            for ($waitTick = 0; $waitTick < 25; $waitTick++) {
                $crashCheck = proc_get_status($pool[1]['process']);
                if (!$crashCheck['running']) {
                    break;
                }
                usleep(100_000);
            }
        }
        $activePids = [];

        foreach ($pool as $slot => &$workerMeta) {
            $st = proc_get_status($workerMeta['process']);
            if (!$st['running']) {
                if (isset($workerMeta['pipes'][1]) && is_resource($workerMeta['pipes'][1])) {
                    @fclose($workerMeta['pipes'][1]);
                }
                if (isset($workerMeta['pipes'][2]) && is_resource($workerMeta['pipes'][2])) {
                    @fclose($workerMeta['pipes'][2]);
                }
                @proc_close($workerMeta['process']);
                $totalRestarts++;
                $newRestarts = $workerMeta['restarts'] + 1;
                try {
                    $engine->command(['INCR', 'hegosentinel:horizon:metrics:supervisor_restarts']);
                } catch (\Throwable) {
                }
                $workerMeta = $spawnWorker($slot, $newRestarts, false);
                $this->warn(sprintf(
                    '[Laravel Horizon] Respawned crashed/exited worker in slot %d (new_pid=%d, total_restarts=%d)',
                    $slot,
                    $workerMeta['pid'],
                    $totalRestarts
                ));
            }
            $activePids[] = $workerMeta['pid'];
        }
        unset($workerMeta);

        try {
            $pong = (string) $engine->command(['PING']);
            $nowIso = gmdate('Y-m-d\TH:i:s\Z');
            $hbPayload = json_encode([
                'supervisor' => 'supervisor-scans',
                'master_pid' => (int) getmypid(),
                'worker_pids' => $activePids,
                'worker_count' => count($activePids),
                'supervisor_restarts' => $totalRestarts,
                'queues' => ['hegosentinel-scans', 'hegosentinel-rechecks', 'hegosentinel-notifications'],
                'redis_ping' => $pong,
                'status' => 'running',
                'updated_at' => $nowIso,
            ], JSON_UNESCAPED_SLASHES);

            $engine->command(['SET', 'hegosentinel:horizon:supervisor-scans:heartbeat', (string) $hbPayload, 'EX', 30]);
            @file_put_contents(sys_get_temp_dir() . '/horizon-heartbeat.json', (string) $hbPayload);
            if (is_dir('/tmp')) {
                @file_put_contents('/tmp/horizon-heartbeat.json', (string) $hbPayload);
            }
        } catch (\Throwable $e) {
            fwrite(STDERR, '[Laravel Horizon] Redis heartbeat warning: ' . $e->getMessage() . "\n");
        }

        if ($maxCycles > 0 && $cycle >= $maxCycles) {
            break;
        }

        usleep(250_000); // 250ms supervisor monitor interval
    }

    // Graceful shutdown of child workers when max-cycles completes
    foreach ($pool as $workerMeta) {
        if (isset($workerMeta['pipes'][1]) && is_resource($workerMeta['pipes'][1])) {
            @fclose($workerMeta['pipes'][1]);
        }
        if (isset($workerMeta['pipes'][2]) && is_resource($workerMeta['pipes'][2])) {
            @fclose($workerMeta['pipes'][2]);
        }
        @proc_terminate($workerMeta['process']);
        @proc_close($workerMeta['process']);
    }

    return 0;
})->purpose('Start the Laravel Horizon master supervisor and multi-worker pool');
