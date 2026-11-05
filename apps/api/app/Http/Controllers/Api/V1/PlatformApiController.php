<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api\V1;

use App\Services\SecurityPlatformService;
use RuntimeException;
use Throwable;

/**
 * HegoSentinel Laravel API V1 Controller
 *
 * Exposes all 14 multi-tenant security platform modules over REST JSON endpoints
 * with strict RBAC, ScopeAuthorizationGrant validation, and tamper-evident audit logging.
 */
final class PlatformApiController
{
    public function __construct(
        private readonly SecurityPlatformService $service
    ) {
    }

    /**
     * Dispatches an incoming HTTP request (`METHOD`, `URI`, headers, query, JSON body)
     * and returns `['status' => int, 'headers' => array, 'body' => array|string]`.
     *
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, mixed> $body
     * @return array{status: int, headers: array<string, string>, body: mixed}
     */
    public function handle(string $method, string $path, array $headers = [], array $query = [], array $body = []): array
    {
        $method = strtoupper($method);
        $cleanPath = '/' . trim((string) parse_url($path, PHP_URL_PATH), '/');

        try {
            // Public health check
            if ($method === 'GET' && ($cleanPath === '/api/v1/health' || $cleanPath === '/health')) {
                $audit = $this->service->verifyAuditChainIntegrity();
                return $this->json(200, [
                    'ok' => true,
                    'service' => 'hegosentinel-laravel-api',
                    'version' => '0.1.0-alpha.4',
                    'php_version' => PHP_VERSION,
                    'restricted_remote_mode' => 'BLOCKED',
                    'pinned_scanners' => [
                        'semgrep' => '1.183.0',
                        'trivy' => '0.76.1',
                    ],
                    'audit_chain_integrity' => $audit,
                ]);
            }

            // Module 1: Authentication endpoints (unauthenticated entrypoints)
            if ($method === 'POST' && $cleanPath === '/api/v1/auth/login') {
                $res = $this->service->login(
                    (string) ($body['email'] ?? ''),
                    (string) ($body['password'] ?? ''),
                    // Trusted source address injected by public/index.php from REMOTE_ADDR (never from client headers).
                    (string) ($headers['x-hegosentinel-remote-addr'] ?? '127.0.0.1'),
                    (string) ($headers['user-agent'] ?? 'HegoSentinel-Web')
                );
                return $this->json(200, ['ok' => true, 'data' => $res]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/auth/register') {
                $res = $this->service->register($body);
                return $this->json(201, ['ok' => true, 'data' => $res]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/auth/password-reset') {
                $res = $this->service->requestPasswordReset((string) ($body['email'] ?? ''));
                return $this->json(200, ['ok' => true, 'data' => $res]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/auth/logout') {
                $bearer = $headers['authorization'] ?? $headers['Authorization'] ?? '';
                $rawToken = preg_replace('/^Bearer\s+/i', '', trim((string) $bearer)) ?? '';
                if ($rawToken !== '') {
                    $this->service->logout($rawToken);
                }
                return $this->json(200, ['ok' => true, 'logged_out' => true]);
            }

            // Authenticate principal for all protected endpoints.
            // SECURITY (B1): identity comes ONLY from a server-issued Bearer session token. No other
            // client-controllable header (e.g. the removed X-Demo-Principal) can establish identity.
            // Every route below this point requires $principal; unknown routes still require auth first,
            // so route existence is not disclosed to anonymous callers.
            $bearer = $headers['authorization'] ?? $headers['Authorization'] ?? null;
            $principal = $this->service->authenticateRequest(is_string($bearer) ? $bearer : null);

            if ($method === 'GET' && $cleanPath === '/api/v1/auth/me') {
                return $this->json(200, ['ok' => true, 'data' => $principal]);
            }

            // Dashboard Telemetry
            if ($method === 'GET' && $cleanPath === '/api/v1/dashboard') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->getDashboardSummary($principal),
                ]);
            }

            // Module 2 & 3: Organization & Team RBAC
            if ($method === 'GET' && $cleanPath === '/api/v1/organization') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->getOrganizationOverview($principal),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/organization/members') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->inviteOrUpdateMember($principal, $body),
                ]);
            }

            // Module 4: Projects & Target Assets
            if ($method === 'GET' && $cleanPath === '/api/v1/projects') {
                $includeDemo = !isset($query['include_demo']) || $query['include_demo'] !== 'false';
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listProjects($principal, $includeDemo),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/projects') {
                $proj = $this->service->createProject($principal, $body);
                return $this->json(201, ['ok' => true, 'data' => $proj]);
            }

            // Module 5: Scope Authorization Grants (`/api/v1/projects/{id}/grants`)
            if ($method === 'POST' && preg_match('#^/api/v1/projects/([a-zA-Z0-9\-_]+)/grants$#', $cleanPath, $m)) {
                $grant = $this->service->createScopeAuthorizationGrant($principal, $m[1], $body);
                return $this->json(201, ['ok' => true, 'data' => $grant]);
            }

            // Module 6 & 7: Scans & Coverage Matrix
            if ($method === 'GET' && $cleanPath === '/api/v1/scans') {
                $projectId = isset($query['project_id']) ? (string) $query['project_id'] : null;
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listScans($principal, $projectId),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/scans') {
                $scan = $this->service->createAndExecuteScan($principal, $body);
                $statusCode = ($scan['status'] ?? '') === 'denied' ? 403 : 201;
                return $this->json($statusCode, [
                    'ok' => $statusCode === 201,
                    'data' => $scan,
                ]);
            }

            if ($method === 'GET' && preg_match('#^/api/v1/scans/([a-zA-Z0-9\-_]+)$#', $cleanPath, $m)) {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->getScanById($principal, $m[1]),
                ]);
            }

            // Module 11: Safe Report Export (`/api/v1/scans/{id}/export`)
            if ($method === 'GET' && preg_match('#^/api/v1/scans/([a-zA-Z0-9\-_]+)/export$#', $cleanPath, $m)) {
                $format = (string) ($query['format'] ?? 'json');
                $exported = $this->service->exportScanReport($principal, $m[1], $format);
                if (!empty($query['raw']) && $query['raw'] === '1') {
                    return [
                        'status' => 200,
                        'headers' => [
                            'Content-Type' => $exported['content_type'],
                            'Content-Disposition' => 'attachment; filename="' . $exported['filename'] . '"',
                        ],
                        'body' => $exported['content'],
                    ];
                }
                return $this->json(200, ['ok' => true, 'data' => $exported]);
            }

            // Module 8: Security Findings & Scoped Suppressions
            if ($method === 'GET' && $cleanPath === '/api/v1/findings') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listFindings($principal, $query),
                ]);
            }

            if ($method === 'POST' && preg_match('#^/api/v1/findings/([a-zA-Z0-9\-_]+)/suppress$#', $cleanPath, $m)) {
                $sup = $this->service->suppressFindingFalsePositive($principal, $m[1], $body);
                return $this->json(201, ['ok' => true, 'data' => $sup]);
            }

            // Module 9: Remediation Tasks
            if ($method === 'GET' && $cleanPath === '/api/v1/remediation-tasks') {
                $projectId = isset($query['project_id']) ? (string) $query['project_id'] : null;
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listRemediationTasks($principal, $projectId),
                ]);
            }

            if (($method === 'PATCH' || $method === 'POST') && preg_match('#^/api/v1/remediation-tasks/([a-zA-Z0-9\-_]+)$#', $cleanPath, $m)) {
                $task = $this->service->updateRemediationTask($principal, $m[1], $body);
                return $this->json(200, ['ok' => true, 'data' => $task]);
            }

            // Module 10: Re-Test & Comparison
            if ($method === 'GET' && $cleanPath === '/api/v1/rechecks') {
                $projectId = isset($query['project_id']) ? (string) $query['project_id'] : null;
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listRecheckComparisons($principal, $projectId),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/rechecks') {
                $comp = $this->service->runRecheckComparison($principal, $body);
                return $this->json(201, ['ok' => true, 'data' => $comp]);
            }

            // Module 12: Approved Developer Notifications
            if ($method === 'GET' && $cleanPath === '/api/v1/notifications') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listNotifications($principal),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/notifications') {
                $notif = $this->service->sendApprovedNotification($principal, $body);
                return $this->json(201, ['ok' => true, 'data' => $notif]);
            }

            // Module 14: Emergency Stop
            if ($method === 'GET' && $cleanPath === '/api/v1/emergency-stop') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listEmergencyStopEvents($principal),
                ]);
            }

            if ($method === 'POST' && $cleanPath === '/api/v1/emergency-stop') {
                $stop = $this->service->triggerEmergencyStop($principal, $body);
                return $this->json(201, ['ok' => true, 'data' => $stop]);
            }

            // Module 13: Tamper-Evident Audit Logs
            if ($method === 'GET' && $cleanPath === '/api/v1/audit-logs') {
                return $this->json(200, [
                    'ok' => true,
                    'data' => $this->service->listAndVerifyAuditLogs($principal),
                ]);
            }

            return $this->json(404, [
                'ok' => false,
                'error' => 'route_not_found',
                'message' => sprintf('Endpoint %s %s not found', $method, $cleanPath),
            ]);
        } catch (RuntimeException $e) {
            $code = (int) $e->getCode();
            if ($code < 400 || $code > 599) {
                $code = 400;
            }
            return $this->json($code, [
                'ok' => false,
                'error' => match (true) {
                    $code === 401 => 'unauthenticated',
                    $code === 403 => 'forbidden',
                    $code === 429 => 'too_many_requests',
                    default => 'validation_or_policy_error',
                },
                'message' => $e->getMessage(),
            ]);
        } catch (Throwable $e) {
            // Never reflect internal exception details to clients; keep them in the server log.
            error_log('[HegoSentinel API] ' . get_class($e) . ': ' . $e->getMessage());
            return $this->json(500, [
                'ok' => false,
                'error' => 'internal_server_error',
                'message' => getenv('APP_DEBUG') === 'true' ? $e->getMessage() : 'Internal server error',
            ]);
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @return array{status: int, headers: array<string, string>, body: array<string, mixed>}
     */
    private function json(int $status, array $payload): array
    {
        return [
            'status' => $status,
            'headers' => [
                'Content-Type' => 'application/json; charset=utf-8',
            ],
            'body' => $payload,
        ];
    }
}

