# Secret & hygiene scan  (2026-11-05T03:10:12)
## git HEAD: 1cda48d85d00b91032b36b5abb80feab00d8ced8
## commits in history: 3

## Working tree (git-tracked files) pattern hits
- pattern `AKIA[0-9A-Z]{16}` : 1 hit(s)
    tests/security/security-matrix.test.ts:291:    const plantedAwsKey = 'AKIAIOSFODNN7EXAMPLE';
- pattern `ASIA[0-9A-Z]{16}` : 0 hit(s)
- pattern `AIza[0-9A-Za-z_\-]{35}` : 0 hit(s)
- pattern `ghp_[0-9A-Za-z]{36}` : 0 hit(s)
- pattern `github_pat_[0-9A-Za-z_]{22,}` : 0 hit(s)
- pattern `gh[ousr]_[0-9A-Za-z]{36}` : 0 hit(s)
- pattern `xox[baprs]-[0-9A-Za-z\-]{10,}` : 0 hit(s)
- pattern `sk-[A-Za-z0-9]{32,}` : 0 hit(s)
- pattern `sk_live_[0-9A-Za-z]{16,}` : 0 hit(s)
- pattern `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` : 1 hit(s)
    tests/security/worker-containment-and-sprint2.test.ts:1528:      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
- pattern `eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}` : 3 hit(s)
    examples/safe-demo/fixture-baseline.json:13:          "hegosentinel_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c; Path=/",
    examples/safe-demo/fixture-patched.json:14:          "hegosentinel_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c; Path=/",
    tests/security/security-matrix.test.ts:289:      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3JldCJ9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
- pattern `(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][A-Za-z0-9/+_\-]{16,}['"]` : 0 hit(s)
- pattern `(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}` : 0 hit(s)

## Git history (all commits, added lines) pattern hits
- pattern `AKIA[0-9A-Z]{16}` : 0 added-line hit(s)
- pattern `ASIA[0-9A-Z]{16}` : 0 added-line hit(s)
- pattern `AIza[0-9A-Za-z_\-]{35}` : 0 added-line hit(s)
- pattern `ghp_[0-9A-Za-z]{36}` : 0 added-line hit(s)
- pattern `github_pat_[0-9A-Za-z_]{22,}` : 0 added-line hit(s)
- pattern `gh[ousr]_[0-9A-Za-z]{36}` : 0 added-line hit(s)
- pattern `xox[baprs]-[0-9A-Za-z\-]{10,}` : 0 added-line hit(s)
- pattern `sk-[A-Za-z0-9]{32,}` : 0 added-line hit(s)
- pattern `sk_live_[0-9A-Za-z]{16,}` : 0 added-line hit(s)
- pattern `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` : 1 added-line hit(s)
    +      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
- pattern `eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}` : 0 added-line hit(s)
- pattern `(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][A-Za-z0-9/+_\-]{16,}['"]` : 0 added-line hit(s)
- pattern `(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}` : 0 added-line hit(s)

## Tracked files that should never be committed
- TRACKED: apps/api/.env.example

## Files ever present in history matching sensitive names
- IN HISTORY: apps/api/.env.example

## Ignored (untracked) local artefacts present in working dir
- ?? docs/audit-evidence/
- !! .tools/
- !! HegoSentinel/
- !! apps/api/database/hegosentinel.sqlite
- !! apps/api/database/hegosentinel.sqlite-shm
- !! apps/api/database/hegosentinel.sqlite-wal
- !! docs/audit-evidence/01-lint.log
- !! docs/audit-evidence/02-typecheck.log
- !! docs/audit-evidence/03-test-unit.log
- !! node_modules/
- !! reports/

## Size of ignored dirs (MB)
- .tools : 2545.6 MB
- node_modules : 22.5 MB
- reports : 0.5 MB
- HegoSentinel : 0.6 MB

## Hard-coded demo credentials / tokens in tracked source (informational, not secrets)
    apps/api/app/Http/Controllers/Api/V1/PlatformApiController.php:88:            $demoPrincipal = $headers['x-demo-principal'] ?? $headers['X-Demo-Principal'] ?? null;
    apps/api/app/Services/SecurityPlatformService.php:86:            ['usr-owner-01', 'admin@hegoweb.local', '[PERSONAL_NAME_REDACTED] (Owner)', 'HegoSentinel!2026', 'tr', 1],
    apps/api/app/Services/SecurityPlatformService.php:87:            ['usr-seclead-01', 'sec-lead@hegoweb.local', '[DEMO_PERSONA_REDACTED] (Security Lead)', 'HegoSentinel!2026', 'tr', 1],
    apps/api/app/Services/SecurityPlatformService.php:88:            ['usr-dev-01', 'dev@hegoweb.local', '[DEMO_PERSONA_REDACTED] (Developer)', 'HegoSentinel!2026', 'tr', 0],
    apps/api/app/Services/SecurityPlatformService.php:89:            ['usr-viewer-01', 'auditor@hegoweb.local', '[DEMO_PERSONA_REDACTED] (Viewer)', 'HegoSentinel!2026', 'en', 0],
    apps/api/app/Services/SecurityPlatformService.php:90:            ['usr-beta-owner', 'owner@betafintech.example.test', 'Beta Tenant Owner', 'HegoSentinel!2026', 'en', 1],
    apps/api/app/Services/SecurityPlatformService.php:503:     * Resolves an authenticated principal from a Bearer token or X-Demo-Principal header.
    apps/api/app/Services/SecurityPlatformService.php:739:                ':hash' => password_hash((string) ($payload['password'] ?? 'HegoSentinel!2026'), PASSWORD_BCRYPT),
    apps/api/public/index.php:23:header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Demo-Principal, Accept');
    apps/api/tests/run-api-tests.php:67:    'password' => 'HegoSentinel!2026',
    apps/api/tests/run-api-tests.php:75:    'password' => 'HegoSentinel!2026',
    apps/api/tests/run-api-tests.php:81:    'password' => 'HegoSentinel!2026',
    apps/api/tests/run-api-tests.php:87:    'password' => 'HegoSentinel!2026',
    apps/api/tests/run-api-tests.php:93:    'password' => 'HegoSentinel!2026',
    apps/web/src/lib/api-client.ts:51:      headers['X-Demo-Principal'] = this.demoPrincipalId;
    apps/web/src/server.ts:746:                <input id="login-password" class="hs-input" type="password" required value="HegoSentinel!2026" />
    apps/web/src/server.ts:776:                  <input id="reg-password" class="hs-input" type="password" required placeholder="HegoSentinel!2026" />
    apps/web/src/server.ts:827:          headers['X-Demo-Principal'] = demoPrincipal;
    apps/web/src/server.ts:1193:          password: 'HegoSentinel!2026'
    apps/web/src/server.ts:1467:      forwardHeaders['X-Demo-Principal'] = rawHeaders['x-demo-principal'];
