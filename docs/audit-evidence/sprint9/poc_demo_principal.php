<?php
// PoC (read-only, in-memory SQLite): is X-Demo-Principal an unauthenticated impersonation path?
declare(strict_types=1);
require_once __DIR__ . '/../../../apps/api/bootstrap/autoload.php';

use App\Http\Controllers\Api\V1\PlatformApiController;
use App\Services\SecurityPlatformService;
use App\Support\DatabaseManager;

putenv('DB_CONNECTION=sqlite'); putenv('DB_SQLITE_PATH=:memory:'); putenv('DB_DATABASE=:memory:');
$_ENV['DB_CONNECTION'] = 'sqlite'; $_ENV['DB_SQLITE_PATH'] = ':memory:'; $_ENV['DB_DATABASE'] = ':memory:';
putenv('APP_ENV=production'); $_ENV['APP_ENV'] = 'production';   // prove it is NOT env-gated

$pdo = DatabaseManager::connect();
$controller = new PlatformApiController(new SecurityPlatformService($pdo));

function show(string $label, array $r): void {
    $b = $r['body'] ?? [];
    $d = $b['data'] ?? $b;
    echo sprintf("%-62s => HTTP %d | %s\n", $label, $r['status'], json_encode(is_array($d) ? array_intersect_key($d, array_flip(['user_id','id','email','name','role','organization_id','error','message'])) : $d, JSON_UNESCAPED_UNICODE));
}
echo "APP_ENV=production (set before boot)\n";
show('1) no credentials at all', $controller->handle('GET', '/api/v1/auth/me'));
show('2) X-Demo-Principal: usr-owner-01 (no password/token)', $controller->handle('GET', '/api/v1/auth/me', ['X-Demo-Principal' => 'usr-owner-01']));
show('3) X-Demo-Principal: usr-beta-owner (other tenant owner)', $controller->handle('GET', '/api/v1/auth/me', ['X-Demo-Principal' => 'usr-beta-owner']));
$p = $controller->handle('GET', '/api/v1/projects', ['X-Demo-Principal' => 'usr-owner-01']);
echo sprintf("%-62s => HTTP %d | projects visible: %d\n", '4) impersonated owner lists projects', $p['status'], is_array($p['body']['data'] ?? null) ? count($p['body']['data']) : -1);
$a = $controller->handle('GET', '/api/v1/audit-logs', ['X-Demo-Principal' => 'usr-owner-01']);
echo sprintf("%-62s => HTTP %d | audit entries readable: %d\n", '5) impersonated owner reads audit log', $a['status'], is_array($a['body']['data']['entries'] ?? null) ? count($a['body']['data']['entries']) : (is_array($a['body']['data'] ?? null) ? count($a['body']['data']) : -1));
