<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap/autoload.php';

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;

// Hardened HTTP Security & CORS Headers
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
$allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
];
$corsOrigin = in_array($origin, $allowedOrigins, true) ? $origin : 'http://localhost:3000';

header('Access-Control-Allow-Origin: ' . $corsOrigin);
header('Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, Accept');
header('Access-Control-Allow-Credentials: true');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox");

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$requestUri = $_SERVER['REQUEST_URI'] ?? '/api/v1/health';
$rawBody = file_get_contents('php://input');
$decodedBody = is_string($rawBody) && trim($rawBody) !== ''
    ? (json_decode($rawBody, true) ?: [])
    : [];

$headers = [];
if (function_exists('getallheaders')) {
    foreach ((array) getallheaders() as $k => $v) {
        $headers[strtolower((string) $k)] = (string) $v;
    }
}
foreach ($_SERVER as $k => $v) {
    if (str_starts_with($k, 'HTTP_')) {
        $headerName = strtolower(str_replace('_', '-', substr($k, 5)));
        $headers[$headerName] = (string) $v;
    }
}
if (!isset($headers['authorization']) && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
    $headers['authorization'] = (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
}
// Trusted network peer only: discard any client-supplied value of this internal header name.
unset($headers['x-hegosentinel-remote-addr']);
$headers['x-hegosentinel-remote-addr'] = (string) ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');

$pdo = DatabaseManager::connect();
$service = new SecurityPlatformService($pdo);
$controller = new PlatformApiController($service);

$response = $controller->handle(
    $method,
    (string) $requestUri,
    $headers,
    $_GET,
    is_array($decodedBody) ? $decodedBody : []
);

http_response_code($response['status']);
foreach ($response['headers'] as $hk => $hv) {
    header($hk . ': ' . $hv);
}

if (is_string($response['body'])) {
    echo $response['body'];
} else {
    echo json_encode($response['body'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

