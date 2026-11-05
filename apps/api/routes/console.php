<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;

Artisan::command('hegosentinel:verify-audit', function (): void {
    $service = app(\App\Services\SecurityPlatformService::class);
    $result = $service->verifyAuditChainIntegrity();
    $this->info(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
})->purpose('Verify the SHA-256 hash chain integrity of audit_logs');
