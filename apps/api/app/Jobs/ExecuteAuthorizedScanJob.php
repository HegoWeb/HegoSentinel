<?php

declare(strict_types=1);

namespace App\Jobs;

use RuntimeException;

/**
 * Isolated Queue Worker Job (Stage 2 / Sprint 8 — S2-02 & Section 5).
 * Never executes untrusted repository hooks or package managers inside the API process.
 * Spawns the hardened TypeScript worker bridge with shell=false, enforces EmergencyStop
 * cancellation (SIGTERM -> SIGKILL), and runs real Semgrep CE (1.183.0) & Trivy (0.76.1)
 * on authorized local repositories or Trusted Egress Broker-verified fixtures.
 */
final class ExecuteAuthorizedScanJob
{
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
        if ($isCancelled) {
            return [
                'allowed' => false,
                'cancelled' => true,
                'reason' => 'scan_cancelled',
                'detail' => 'Scan cancelled by EmergencyStopRegistry before worker execution (SEC-012)',
            ];
        }

        if ($mode === 'restricted-remote') {
            return [
                'allowed' => false,
                'cancelled' => false,
                'reason' => 'remote_egress_isolation_unverified',
                'detail' => 'restricted-remote mode is fail-closed until Linux netns & TrustedEgressBroker runtime verification is active in deployment (SEC-005 / SEC-014)',
            ];
        }

        $repoRoot = realpath(__DIR__ . '/../../../..');
        if ($repoRoot === false) {
            throw new RuntimeException('Unable to resolve monorepo root for scanner worker execution');
        }

        $bridgeScript = $repoRoot . DIRECTORY_SEPARATOR . 'scripts' . DIRECTORY_SEPARATOR . 'api-worker-bridge.ts';
        $inputPayload = json_encode([
            'scan_id' => $scanId,
            'mode' => $mode,
            'grant' => $grant,
            'repository_path' => $repositoryPath,
            'fixture_variant' => $fixtureVariant,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $nodeBin = is_file('C:\\Program Files\\nodejs\\node.exe')
            ? 'C:\\Program Files\\nodejs\\node.exe'
            : 'node';
        $cmd = [$nodeBin, '--experimental-strip-types', $bridgeScript];
        $process = proc_open($cmd, $descriptors, $pipes, $repoRoot, null, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Failed to spawn isolated scanner worker subprocess');
        }

        fwrite($pipes[0], (string) $inputPayload);
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);
        if ($exitCode !== 0 || !is_string($stdout) || trim($stdout) === '') {
            return [
                'allowed' => false,
                'cancelled' => false,
                'reason' => 'worker_subprocess_failed',
                'detail' => 'Worker subprocess exited with code ' . $exitCode . ': ' . trim((string) $stderr),
            ];
        }

        $decoded = json_decode($stdout, true);
        if (!is_array($decoded)) {
            return [
                'allowed' => false,
                'cancelled' => false,
                'reason' => 'worker_invalid_json',
                'detail' => 'Worker subprocess returned non-JSON output',
            ];
        }

        return $decoded;
    }
}
