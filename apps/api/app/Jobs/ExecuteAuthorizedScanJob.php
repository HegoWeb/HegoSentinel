<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Services\WorkerSupervisorClient;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

require_once __DIR__ . '/../Services/WorkerSupervisorClient.php';

/**
 * Isolated Queue Worker Job (Sprint 10 — S10-03 & S10-04).
 *
 * Queued on `hegosentinel-scans` under Laravel Horizon.
 * Delegates container/subprocess execution to `WorkerSupervisorClient` so the Web API process
 * never mounts `/var/run/docker.sock` or executes untrusted repository code directly.
 */
final class ExecuteAuthorizedScanJob implements ShouldQueue, ShouldBeUnique
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 1;
    public int $timeout = 90;
    public int $uniqueFor = 120;

    /**
     * @param array<string, mixed> $grant
     */
    public function __construct(
        public readonly array $grant,
        public readonly string $scanId,
        public readonly string $mode,
        public readonly ?string $repositoryPath = null,
        public readonly string $fixtureVariant = 'baseline',
        public readonly bool $isCancelled = false
    ) {
        $this->onQueue('hegosentinel-scans');
    }

    public function uniqueId(): string
    {
        return $this->scanId;
    }

    /**
     * @return array<string, mixed>
     */
    public function handle(): array
    {
        return self::dispatchSyncOrQueue(
            $this->grant,
            $this->scanId,
            $this->mode,
            $this->repositoryPath,
            $this->fixtureVariant,
            $this->isCancelled
        );
    }

    /**
     * @param array<string, mixed> $grant
     * @return array<string, mixed>
     */
    public static function dispatchSyncOrQueue(
        array $grant,
        string $scanId,
        string $mode,
        ?string $repositoryPath,
        string $fixtureVariant = 'baseline',
        bool $isCancelled = false
    ): array {
        return WorkerSupervisorClient::executeScan(
            $grant,
            $scanId,
            $mode,
            $repositoryPath,
            $fixtureVariant,
            $isCancelled
        );
    }
}
