<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;
use App\Support\TenantRlsContext;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel Authentication & PostgreSQL RLS Tenant Context Middleware (S10-01 & S10-02).
 *
 * Authenticates Bearer / Sanctum session tokens and binds `TenantRlsContext`
 * (`SET LOCAL app.current_organization_id`) for the duration of the HTTP request,
 * resetting the connection context in `finally` to prevent connection-pool leakage.
 */
final class AuthenticateSessionOrSanctumMiddleware
{
    public function __construct(
        private readonly SecurityPlatformService $service
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->header('Authorization');
        try {
            $principal = $this->service->authenticateRequest(is_string($bearer) ? $bearer : null);
        } catch (RuntimeException $e) {
            return new JsonResponse([
                'ok' => false,
                'error' => 'unauthenticated',
                'message' => $e->getMessage(),
            ], 401);
        }

        $pdo = DatabaseManager::connection();
        $orgId = (string) ($principal['organization_id'] ?? '');
        $request->attributes->set('hegosentinel_principal', $principal);

        return TenantRlsContext::runInTenantTransaction(
            $pdo,
            $orgId,
            static function () use ($next, $request): Response {
                /** @var Response $res */
                $res = $next($request);
                return $res;
            },
            $principal,
            false
        );
    }
}
