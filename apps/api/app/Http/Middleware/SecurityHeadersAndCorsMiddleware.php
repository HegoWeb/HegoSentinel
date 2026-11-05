<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Hardened HTTP Security, CORS & Untrusted Header Sanitization Middleware (S10-01 & Sprint 9 B1).
 *
 * - Strips any client-supplied `X-Demo-Principal` or `X-Hegosentinel-Remote-Addr` headers so they
 *   can never influence downstream logic.
 * - Sets `X-Hegosentinel-Remote-Addr` strictly from the socket peer `REMOTE_ADDR`.
 * - Applies strict CORS allowlist and security response headers (`nosniff`, `DENY`, `no-referrer`, sandbox CSP).
 */
final class SecurityHeadersAndCorsMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        // Strip untrusted client-controllable identity/ip headers (B1 defense-in-depth)
        $request->headers->remove('x-demo-principal');
        $request->headers->remove('x-hegosentinel-remote-addr');
        $remoteAddr = (string) ($request->server('REMOTE_ADDR') ?: $request->ip() ?: '127.0.0.1');
        $request->headers->set('x-hegosentinel-remote-addr', $remoteAddr);

        $origin = (string) ($request->headers->get('Origin') ?? '*');
        $allowedOrigins = [
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://localhost:4173',
            'http://127.0.0.1:4173',
        ];
        $corsOrigin = in_array($origin, $allowedOrigins, true) ? $origin : 'http://localhost:3000';

        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            $response = new Response('', 204);
        } else {
            /** @var Response $response */
            $response = $next($request);
        }

        $response->headers->set('Access-Control-Allow-Origin', $corsOrigin);
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
        $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, X-Requested-With, X-XSRF-TOKEN');
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; sandbox");

        return $response;
    }
}
