<?php

declare(strict_types=1);

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

/**
 * Approved Developer Notification Queue Job (Sprint 10 — S10-03 & SEC-013).
 *
 * Queued on `hegosentinel-notifications` under Laravel Horizon after passing
 * SEC-013 public sink, verified domain, and secret redaction checks.
 */
final class DispatchApprovedNotificationJob implements ShouldQueue, ShouldBeUnique
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 2;
    public int $timeout = 30;

    public function __construct(
        public readonly string $notificationId,
        public readonly string $organizationId,
        public readonly string $projectId,
        public readonly string $channel,
        public readonly string $recipient,
        public readonly string $sanitizedSummary
    ) {
        $this->onQueue('hegosentinel-notifications');
    }

    public function uniqueId(): string
    {
        return $this->notificationId;
    }

    /**
     * @return array<string, mixed>
     */
    public function handle(): array
    {
        return [
            'notification_id' => $this->notificationId,
            'queue' => 'hegosentinel-notifications',
            'status' => 'dispatched',
            'dispatched_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
    }
}
