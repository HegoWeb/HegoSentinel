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
 * Isolated Re-Test & Side-by-Side Comparison Queue Job (Sprint 10 — S10-03).
 *
 * Queued on `hegosentinel-rechecks` under Laravel Horizon.
 */
final class ExecuteRecheckComparisonJob implements ShouldQueue, ShouldBeUnique
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 1;
    public int $timeout = 60;

    /**
     * @param array<string, mixed> $baselineReport
     * @param array<string, mixed> $currentReport
     * @param list<array<string, mixed>> $suppressions
     */
    public function __construct(
        public readonly string $recheckKey,
        public readonly array $baselineReport,
        public readonly array $currentReport,
        public readonly array $suppressions = []
    ) {
        $this->onQueue('hegosentinel-rechecks');
    }

    public function uniqueId(): string
    {
        return $this->recheckKey;
    }

    /**
     * @return array<string, mixed>
     */
    public function handle(): array
    {
        return WorkerSupervisorClient::executeAuxAction([
            'action' => 'compare',
            'baseline_report' => $this->baselineReport,
            'current_report' => $this->currentReport,
            'suppressions' => $this->suppressions,
        ]);
    }
}

