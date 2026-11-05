# Pre-commit secret scan - working tree incl. untracked (non-ignored) files  (2026-11-05T03:57:31)
HEAD: 1cda48d85d00b91032b36b5abb80feab00d8ced8
Scanned files: 192 (tracked + untracked-not-ignored)

- `AKIA[0-9A-Z]{16}` : 3 hit(s)
    PROJECT_STATUS.md:77:| Gerçek sır (çalışma ağacı, 13 desen) | **Bulunamadı.** Eşleşenlerin hepsi test/örnek verisi: `AKIAIOSFODNN7EXAMPLE` (AWS dokümantasyon örneği), sahte PEM başlığı, jwt.io örnek J
    docs/audit-evidence/secret-scan.md:7:    tests/security/security-matrix.test.ts:291:    const plantedAwsKey = 'AKIAIOSFODNN7EXAMPLE';
    tests/security/security-matrix.test.ts:291:    const plantedAwsKey = 'AKIAIOSFODNN7EXAMPLE';
- `ASIA[0-9A-Z]{16}` : 0 hit(s)
- `AIza[0-9A-Za-z_\-]{35}` : 0 hit(s)
- `ghp_[0-9A-Za-z]{36}` : 4 hit(s)
    tests/security/broker-b2-regression.test.ts:100:  'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    tests/security/broker-b2-regression.test.ts:124:    assert.equal(sanitizeUrlForAudit('https://demo.example.test/ghp_abcdefghijklmnopqrstuvwxyz0123456789').includes('ghp_abcdefghijklmnopqrstuvwxyz01234
    tests/security/broker-b2-regression.test.ts:135:      'https://demo.example.test/?token=top-secret-audit-value&code=abcdef123456&password=p@ssw0rd-value&api_key=sk_live_REALLYSECRET&x=ghp_abcdefghijkl
    tests/security/broker-b2-regression.test.ts:233:      { 'X-Custom-Trace': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
- `github_pat_[0-9A-Za-z_]{22,}` : 0 hit(s)
- `gh[ousr]_[0-9A-Za-z]{36}` : 0 hit(s)
- `xox[baprs]-[0-9A-Za-z\-]{10,}` : 0 hit(s)
- `sk_live_[0-9A-Za-z]{16,}` : 0 hit(s)
- `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` : 3 hit(s)
    docs/audit-evidence/secret-scan.md:17:    tests/security/worker-containment-and-sprint2.test.ts:1528:      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
    docs/audit-evidence/secret-scan.md:36:    +      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
    tests/security/worker-containment-and-sprint2.test.ts:1528:      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
- `(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][A-Za-z0-9/+_\-]{20,}['"]` : 0 hit(s)

## Files that must never be committed but would be picked up (must be empty)
- none

## Largest files that would be committed (KB)
- apps/api/app/Services/SecurityPlatformService.php : 113 KB
- apps/web/src/server.ts : 81.6 KB
- tests/security/worker-containment-and-sprint2.test.ts : 58.2 KB
- apps/worker/src/index.ts : 51.2 KB
- scripts/verify-all-security-gates.ts : 50.6 KB
- packages/scanner-core/src/server.ts : 48.1 KB

## Local user path / personal-name occurrences in files that would be committed
- PROJECT_STATUS.md:81:| Yerel yollar / kullanıcı adı | `C:\Users\<user>` izlenen dosyalarda **yok**. |
- VERSION_AUDIT.md:4:> **Kanonik kaynak:** `<repo>` · branch `main` · HEAD `1cda48d85d00b91032b36b5abb80feab0
- docs/audit-evidence/sprint9/T06-demo.log:20:  - <repo>\reports\demo-baseline.json
- docs/audit-evidence/sprint9/T06-demo.log:21:  - <repo>\reports\demo-baseline.md
- docs/audit-evidence/sprint9/T06-demo.log:22:  - <repo>\reports\demo-patched.json
- docs/audit-evidence/sprint9/T06-demo.log:23:  - <repo>\reports\demo-recheck.json
- docs/audit-evidence/sprint9/T06-demo.log:24:  - <repo>\reports\demo-recheck.md
- docs/audit-evidence/sprint9/T06-demo.log:25:  - <repo>\reports\demo-recheck.html
Personal-name ('Ya.ar') occurrences: 0 file(s)
