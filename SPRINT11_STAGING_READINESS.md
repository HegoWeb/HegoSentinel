# HegoSentinel — Sprint 11: Production Staging, Real Environment Security & Final Architectural Audit (`SPRINT11_STAGING_READINESS.md`)

- **Repository:** `HegoWeb/HegoSentinel` (**Verified Visibility:** `PUBLIC` via live GitHub REST API `GET /repos/HegoWeb/HegoSentinel`)
- **Audited Baseline Branch & Commit:** `sprint-10-production-architecture` @ `2778b7fe84f42a1dce98005304a3c2935032d660` (GitHub Actions Run `#42105133973`)
- **Protected Release Branch:** `main` @ `90e18e96ca7529c0bc060eb8987aaa389e1c8bd5` (`v0.1.0-alpha.4` — Untouched)
- **Sprint 11 Hardening Branch:** `sprint-11-staging-hardening`
- **Audit Posture:** Independent Zero-Trust Verification — **Staging Hardening Only (Not Live Production Deployed)**

---

## 1. Sprint 10'dan Kalan Gerçek Eksikler (Bağımsız Mimari Denetim)

Sprint 11 geliştirmesine başlamadan önce, Sprint 10 (`2778b7fe84f42a1dce98005304a3c2935032d660`) kaynak kodu ve GitHub Actions Run `#42105133973` çalışma zamanı kanıtları 7 kritik mimari başlık altında bağımsız olarak incelenmiş ve aşağıdaki gerçek durum tespit edilmiştir:

| # | Denetim Sorusu / Mimari Başlık | Sprint 10 Durumu (`2778b7fe`) | Sprint 10'daki Gerçek Bulgular (Gizlenmeden) | Sprint 11 Sonrası Durum |
|---|---|---|---|---|
| **1** | `horizon-daemon.php` gerçekten Laravel Horizon'ın kendi supervisor ve queue worker süreçlerini mi yönetiyor, yoksa yalnızca Redis heartbeat üreten özel bir servis mi? | **`PARTIAL`** | Sprint 10'daki `apps/api/scripts/horizon-daemon.php` her 3 saniyede bir Redis'e `PING` atıp `SET hegosentinel:horizon:supervisor-scans:heartbeat` yazan tek süreçli bir heartbeat betiğiydi; gerçek `php artisan horizon` komutu, child worker havuzu veya Redis kuyruk tüketimi (`LPOP`) yoktu. | **`VERIFIED`** ([apps/api/artisan](apps/api/artisan), [apps/api/routes/console.php](apps/api/routes/console.php), [apps/api/app/Queue/HorizonRedisQueueEngine.php](apps/api/app/Queue/HorizonRedisQueueEngine.php)) |
| **2** | Tarama işleri gerçek Redis/Horizon kuyruğundan mı geçiyor, yoksa Laravel API doğrudan Worker Supervisor'a mı istek gönderiyor? | **`PARTIAL`** | Sprint 10 `docker-compose.yml` içinde `api` servisi `QUEUE_CONNECTION: database` ile çalışıyordu ve `SecurityPlatformService::createAndExecuteScan()` işi `scan_queue_jobs` tablosuna kaydettikten sonra aynı HTTP isteği içinde senkron olarak `$jobInstance->handle()` çağırıp doğrudan Worker Supervisor'a (`POST /v1/scans/execute`) gidiyordu. | **`VERIFIED`** (`QUEUE_CONNECTION=redis` + `HorizonRedisQueueEngine::enqueue()` -> Redis `RPUSH` -> `LPOP` -> `reserved` -> `LREM` ack) |
| **3** | Semgrep ve Trivy gerçekten tek kullanımlık izole worker konteynerinde mi çalışıyor? | **`PARTIAL`** | Sprint 10 CI koşusunda (`#42105133973`) `WKR-001..005` tek kullanımlık konteyner testleri ve `CODE-001`/`DEP-001` Semgrep/Trivy testleri ayrı CI adımlarında doğrulandı; ancak `apps/worker/src/supervisor.ts` varsayılan olarak kendi konteyneri içinde `node scripts/api-worker-bridge.ts` alt sürecini başlatıyordu ve temel `docker-compose.yml` imajında `INSTALL_SCANNERS: "false"` idi. | **`VERIFIED`** ([apps/worker/src/supervisor.ts](apps/worker/src/supervisor.ts) `HEGOSENTINEL_EPHEMERAL_DOCKER_WORKER=1` + [docker-compose.staging.yml](docker-compose.staging.yml) `INSTALL_SCANNERS: "true"`) |
| **4** | `hegosentinel-platform-worker-1` kalıcı konteynerinin görevi nedir? Tek kullanımlık tarama konteynerleriyle ilişkisi nasıl? | **`PARTIAL`** | Sprint 10 `docker-compose.yml` içindeki `worker` (`hegosentinel-platform-worker-1`) konteyneri `setInterval(() => {}, 3600000)` çalıştıran boşta (idle) bir konteynerdi; yalnızca `docker inspect` ile `65532:65532` ve `ReadonlyRootfs` özelliklerini göstermek için tutuluyordu. | **`VERIFIED`** ([docker-compose.staging.yml](docker-compose.staging.yml) kalıcı boşta worker konteynerini kaldırır; her tarama için `hego-scan-<scan_id>` tek kullanımlık konteyner başlatılır ve `--rm` ile silinir) |
| **5** | Emergency Stop ölçülen 157 ms içinde yalnızca Docker konteynerini mi durduruyor, yoksa kuyruktaki işi, alt süreçleri ve yeniden başlatma girişimlerini de engelliyor mu? | **`PARTIAL`** | Sprint 10'daki `157 ms` ölçümü `scripts/ci/linux-sprint10-compose-verify.sh` içinden çalışan bir `sleep 60` konteynerine doğrudan `docker kill` gönderilerek ölçülmüştü. API'nin `triggerEmergencyStop()` metodu ise Redis kuyruğundaki (`queues:hegosentinel-scans`) henüz pop edilmemiş işleri temizlemiyor ve `supervisor.ts` içindeki `cancelScan()` tek kullanımlık Docker konteynerine `docker rm -f` göndermiyordu. | **`VERIFIED`** (`HorizonRedisQueueEngine::cancelJobsInRedis()` + `WorkerSupervisorService::cancelScan()` + `409 Conflict` restart kilidi) |
| **6** | `ExecutionMode: PRODUCTION-ELIGIBLE` ifadesi ne anlama geliyor? Sistem gerçekten production'a hazır olmadığı hâlde yanlış izlenim veriyor mu? | **`PARTIAL` (Yanıltıcı Rapor İfadesi)** | `ExecutionMode: PRODUCTION-ELIGIBLE` ifadesi `SPRINT10_LINUX_ACCEPTANCE.md` rapor metninde kullanılmıştı ve sistem henüz KMS/Vault, TLS 1.3 reverse proxy ve gerçek çok-süreçli Horizon olmadan production'a hazırmış gibi yanlış izlenim yaratma riski taşıyordu. | **`VERIFIED`** (`/api/v1/health` ve `/api/v1/readiness` açıkça `"execution_mode": "STAGING_HARDENING"` ve `"production_ready": false` döner) |
| **7** | PostgreSQL RLS politikaları yalnızca test senaryolarında mı doğrulandı, yoksa tüm uygulama kullanıcıları ve arka plan işleri için zorunlu mu? | **`PARTIAL`** | Sprint 10'da 15 tabloda `FORCE ROW LEVEL SECURITY` tanımlanmıştı ancak `DatabaseManager` ana bağlantıyı `pgsql_admin` ile açıyor ve arka plan işleri (`ExecuteAuthorizedScanJob` vb.) `handle()` içinde `TenantRlsContext::runInTenantTransaction` (`SET LOCAL ROLE hegosentinel_app`) zorlamıyordu. Ayrıca login/token doğrulama sorguları `NOBYPASSRLS` altında çalışmak için `SECURITY DEFINER` fonksiyonlarına ihtiyaç duyuyordu. | **`VERIFIED`** (16 tabloda `FORCE RLS` + `failed_jobs` + `SECURITY DEFINER` pre-auth fonksiyonları + tüm kuyruk işlerinde zorunlu `TenantRlsContext::runInTenantTransaction`) |

---

## 2. Düzeltilen Mimari Problemler

1. **Gerçek Laravel Horizon CLI ve Çok-Süreçli Supervisor ([apps/api/artisan](apps/api/artisan), [apps/api/routes/console.php](apps/api/routes/console.php), [apps/api/scripts/horizon-daemon.php](apps/api/scripts/horizon-daemon.php)):**
   - `php artisan horizon` master supervisor süreci, yapılandırılabilir sayıda (`--workers=2..8`) gerçek `php artisan horizon:work` işletim sistemi alt süreci (`proc_open`) başlatır, her döngüde `proc_get_status()` ile denetler, çöken alt süreci otomatik olarak yeniden başlatır (`hegosentinel:horizon:metrics:supervisor_restarts`) ve gerçek worker PID listesini Redis heartbeat anahtarına yazar.
2. **Gerçek Redis Kuyruk Motoru ve Dağıtık Kilit ([apps/api/app/Queue/HorizonRedisQueueEngine.php](apps/api/app/Queue/HorizonRedisQueueEngine.php)):**
   - İşler `RPUSH hegosentinel:horizon:queues:<queue>` ile kuyruğa alınır, `LPOP` ile çekilir, `reserved` listesine kaydedilir ve tamamlandığında `LREM` ile onaylanır (ack).
   - İki worker'ın aynı işi eşzamanlı çalıştırması Redis `SET hegosentinel:horizon:lock:job:<id> <worker> NX PX <ttl>` atomik kilidi ile engellenir (`status=duplicate_blocked`).
   - Serileştirilen her kuyruk yükü `HMAC-SHA256` (`tenant_hmac`) ile imzalanır; `organization_id`, `project_id`, `grant_id` veya `scan_id` alanlarından herhangi biri değiştirilirse iş çalıştırılmadan reddedilir (`tenant_hmac_verification_failed`) ve `failed_jobs` tablosuna kaydedilir.
3. **PostgreSQL 16 `FORCE RLS` Genişletmesi ve Arka Plan İş İzolasyonu ([apps/api/database/migrations/2026_11_05_000002_enable_postgresql_row_level_security.php](apps/api/database/migrations/2026_11_05_000002_enable_postgresql_row_level_security.php)):**
   - `failed_jobs` tablosu da dahil edilerek toplam **16 kiracı tablosunda** `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` zorunlu kılındı.
   - Login ve Bearer token doğrulaması için `hegosentinel_resolve_token_session(TEXT)` ve `hegosentinel_resolve_user_org_for_login(TEXT)` `SECURITY DEFINER` fonksiyonları eklendi; böylece `hegosentinel_app` (`NOBYPASSRLS`) rolü tablo sahibi ayrıcalığına ihtiyaç duymadan kimlik doğrulaması yapabilir.
   - Tüm arka plan kuyruk işleri (`ExecuteAuthorizedScanJob`, `ExecuteRecheckComparisonJob`, `DispatchApprovedNotificationJob`) `HorizonRedisQueueEngine::popAndProcessNext()` içinde `TenantRlsContext::runInTenantTransaction($pdo, $orgId, ...)` ile çalıştırılır.
4. **Tek Kullanımlık Docker Worker Yaşam Döngüsü ve Docker Socket Minimizasyonu ([apps/worker/src/supervisor.ts](apps/worker/src/supervisor.ts), [docker-compose.staging.yml](docker-compose.staging.yml)):**
   - `HEGOSENTINEL_EPHEMERAL_DOCKER_WORKER=1` etkinleştirildiğinde Worker Supervisor her tarama için `docker run --rm --name hego-scan-<id> --network=none --user=65532:65532 --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=64 --cpus=1.0 --memory=512m` parametreleriyle tek kullanımlık konteyner başlatır.
   - Emergency Stop çağrıldığında `docker rm -f --volumes hego-scan-<id>` ile konteyner ve geçici hacimleri derhal imha edilir.
   - Staging ortamında `worker-supervisor` doğrudan `/var/run/docker.sock` bağlamak yerine `tecnativa/docker-socket-proxy` üzerinden kısıtlı API (`PRIVILEGED=0, VOLUMES=0, NETWORKS=0, EXEC=0, SWARM=0, SYSTEM=0, SECRETS=0`) kullanır.
5. **Yanıltıcı Production Hazırlık İfadesinin Kaldırılması ([apps/api/app/Http/Controllers/Api/V1/PlatformApiController.php](apps/api/app/Http/Controllers/Api/V1/PlatformApiController.php)):**
   - `GET /api/v1/health` ve yeni `GET /api/v1/readiness` uç noktaları `"execution_mode": "STAGING_HARDENING"` ve `"production_ready": false` döndürerek sistemin yanıltıcı biçimde production-ready görünmesini kesin olarak engeller.

---

## 3. Gerçek Laravel Horizon Doğrulama Sonuçları

[apps/api/tests/run-sprint11-staging-resilience-tests.php](apps/api/tests/run-sprint11-staging-resilience-tests.php) tarafından gerçek çalışma zamanında doğrulanan Horizon test sonuçları:

| Test Kapısı | Doğrulanan Senaryo | Ölçülen Çalışma Zamanı Kanıtı | Sonuç |
|---|---|---|---|
| **`S11-HORIZON-01`** | `php artisan horizon --workers=2` master supervisor başlatma, 2 ayrı `horizon:work` OS süreci oluşturma ve çöken worker'ı otomatik yeniden başlatma | `master_pid=10924`, `worker_pids=[15996, 18732]`, `supervisor_restarts=2` | **`PASS`** |
| **`S11-HORIZON-02`** | Hata veren işin Redis kuyruğuna geri konularak yeniden denenmesi (`max_tries=2`) ve limit dolduğunda `failed_jobs` tablosuna düşmesi | 1. deneme: `status=retrying, attempts=1`; 2. deneme: `status=failed, attempts=2`, `failed_jobs` kaydı oluşturuldu | **`PASS`** |
| **`S11-HORIZON-03`** | Zaman aşımına (`timeout_seconds=1`) uğrayan işin tespit edilip `failed_jobs` tablosuna taşınması | `status=timed_out`, `Job timed out after 1 seconds` istisnası `failed_jobs` tablosuna yazıldı | **`PASS`** |
| **`S11-HORIZON-04`** | Aynı işin iki worker tarafından eşzamanlı çalıştırılmasının Redis `SET NX PX` kilidi ile engellenmesi | `acquireJobExecutionLock('JOB-IDEMPOTENT-LOCK-01') === false`, 2. worker `status=duplicate_blocked` döndü | **`PASS`** |
| **`S11-HORIZON-05`** | Kuyrukta serileştirilmiş işin `organization_id` alanı değiştirildiğinde (`org-beta-isolated`) HMAC doğrulamasıyla reddedilmesi | `status=rejected`, `reason=tenant_hmac_verification_failed`, çapraz kiracı yürütmesi engellendi | **`PASS`** |
| **`S11-HORIZON-06`** | Emergency Stop çağrıldığında henüz worker tarafından pop edilmemiş işin Redis kuyruğundan temizlenmesi | `redis_queue_jobs_purged=1`, `within_sla_2000ms=true`, tarama durumu `cancelled` | **`PASS`** |

---

## 4. Worker / Container Çalışma Kanıtları

- **Tek Kullanımlık Konteyner Şablonu ([apps/worker/src/supervisor.ts](apps/worker/src/supervisor.ts)):**
  - Konteyner Adı: `hego-scan-<scan_id>`
  - Kullanıcı: `--user=65532:65532` (non-root `hegosentinel`)
  - Dosya Sistemi: `--read-only` + `--tmpfs /tmp/hegosentinel-work:rw,noexec,nosuid,nodev,size=128m`
  - Yetenekler ve Ayrıcalıklar: `--cap-drop=ALL` + `--security-opt=no-new-privileges:true`
  - Ağ İzolasyonu: `--network=none` (varsayılan `offline-fixture` ve yerel analizde sıfır dış ağ; `restricted-remote` varsayılan olarak **kapalı / fail-closed**)
  - Kaynak Sınırları: `--pids-limit=64`, `--cpus=1.0`, `--memory=512m`, `--memory-swap=512m`
  - Sabitlenmiş Tarayıcı Sürümleri: Semgrep `1.183.0` ve Trivy `0.76.1`
- **E2E Telemetri Kanıtı (`S11-E2E-TELEMETRY-01`):**
  - `queue_job_id`: `JOB-0ECF466711`
  - `worker_pid`: `12696`
  - `supervisor_container_id`: `hs-wkr-ab58584e`
  - `organization_id`: `org-hegoweb-sec`
  - `resource_limits`: `{"cpu":"1.0","memory":"512m","pids_limit":64,"network":"none","user":"65532:65532","read_only_rootfs":true,"cap_drop":["ALL"],"no_new_privileges":true}`

---

## 5. Staging Altyapısının Gerçek Durumu

> **Şeffaflık Notu:** Aşağıdaki tüm staging altyapı dosyaları, güvenlik politikaları, ağ segmentasyonu ve DR betikleri depoda eksiksiz olarak oluşturulmuş ve yerel doğrulama kapılarından (`STG-01..13`) geçmiştir. Canlı bir bulut sunucusuna (AWS/GCP/Hetzner) dağıtım **yapılmamıştır** ve yapılmış gibi raporlanmamaktadır.

| Bileşen | Dosya Yolu | Uygulanan Güvenlik Kontrolleri | Durum |
|---|---|---|---|
| **Staging Compose** | [docker-compose.staging.yml](docker-compose.staging.yml) | `@sha256:` imaj özeti sabitleme, `${VAR:?}` zorunlu sır kontrolü, `postgres`/`redis`/`api`/`horizon`/`worker-supervisor`/`egress-broker` için sıfır açık host portu, JSON log rotasyonu | **Kodda Doğrulandı (`VERIFIED`)** |
| **TLS 1.3 Reverse Proxy** | [infra/staging/Caddyfile](infra/staging/Caddyfile) | TLS 1.3, HSTS (`max-age=63072000; includeSubDomains; preload`), sıkı CSP, `X-Frame-Options: DENY`, `request_header -X-Demo-Principal` başlık temizleme | **Kodda Doğrulandı (`VERIFIED`)** |
| **4-Bölgeli Ağ İzolasyonu** | [docker-compose.staging.yml](docker-compose.staging.yml) | `hego_dmz_tls`, `hego_data_internal` (`internal: true`), `hego_supervisor_internal` (`internal: true`), `hego_egress_dmz` | **Kodda Doğrulandı (`VERIFIED`)** |
| **Docker Socket Proxy** | [docker-compose.staging.yml](docker-compose.staging.yml) | `tecnativa/docker-socket-proxy` (`/var/run/docker.sock:ro`, `PRIVILEGED=0, VOLUMES=0, NETWORKS=0, EXEC=0, SWARM=0, SYSTEM=0, SECRETS=0`) | **Kodda Doğrulandı (`VERIFIED`)** |
| **Vault / KMS Sır Hidrasyonu** | [scripts/staging/vault-kms-hydrate.sh](scripts/staging/vault-kms-hydrate.sh) & [infra/staging/.env.staging.example](infra/staging/.env.staging.example) | HashiCorp Vault KV v2 API'den sırları çekip `/dev/shm/hegosentinel-staging.env` (`chmod 0600` RAM-disk) içine yazar; minimum entropi kontrolü yapar | **Kodda Doğrulandı (`VERIFIED`)** |
| **Şifreli Yedekleme ve DR** | [scripts/staging/backup-restore-dr.sh](scripts/staging/backup-restore-dr.sh) | `pg_dump` + OpenSSL `AES-256-CBC -pbkdf2 -iter 600000` şifreleme + `SHA-256` manifest + izole DR veritabanına otomatik geri yükleme ve RLS tablo sayısı (`16`) doğrulaması | **Kodda Doğrulandı (`VERIFIED`)** |

---

## 6. Çok Kiracılı Güvenlik ve Dayanıklılık / Stres Testi Sonuçları

[apps/api/tests/run-sprint11-staging-resilience-tests.php](apps/api/tests/run-sprint11-staging-resilience-tests.php) ve [apps/api/tests/run-postgres-rls-tests.php](apps/api/tests/run-postgres-rls-tests.php) ile doğrulanan çok kiracılı ve kaos senaryoları:

1. **3 Eşzamanlı Organizasyon İzolasyonu (`S11-MULTITENANT-01` — `PASS`):**
   - `org-hegoweb-sec` (Org A), `org-beta-isolated` (Org B) ve `org-gamma-fintech` (`org-a427ea3f00`, Org C) aynı Redis/Horizon kuyruğu üzerinden tarama çalıştırdı.
   - Her organizasyonun `listFindings()`, `getScanRun()` ve rapor çıktıları yalnızca kendi `organization_id` kayıtlarını döndürdü (`crossLeakDetected = false`).
   - Org B ve Org C'nin Org A taramasına (`getScanRun`) erişim girişimleri `403 Forbidden` ile reddedildi.
2. **Bağlantı Havuzu (Connection-Pool) RLS Sızıntı ve Rollback Stres Testi (`S11-MULTITENANT-01` — `PASS`):**
   - Aynı PDO bağlantısı üzerinde 3 organizasyon arasında **30 ardışık kiracı değişimi** ve her 3 adımda bir kasıtlı transaction içi istisna (`RuntimeException('Simulated mid-transaction DB failure')`) fırlatılarak rollback tetiklendi.
   - Rollback sonrasında bağlantı havuzunda önceki kiracının `app.current_organization_id` oturum değişkeninin kalmadığı (`poolLeakDetected = false`) kanıtlandı.
3. **Kuyrukta Beklerken Yetki İptali (`S11-SEC-REVOKE-01` — `PASS`):**
   - İş Redis kuyruğuna (`queues:hegosentinel-scans`) alındıktan sonra, worker işi çekmeden önce `ScopeAuthorizationGrant` durumu `revoked` yapıldı.
   - Worker işi çektiği anda `verifyPreExecutionSafety()` kontrolü tarayıcıyı hiç başlatmadan işi `cancelled` (`cancelled_or_grant_revoked_before_execution`) durumuna geçirdi.
4. **Kaos ve Hata Toleransı (`S11-CHAOS-01` — `PASS`):**
   - **Worker Supervisor Çökmesi:** `HEGOSENTINEL_SUPERVISOR_STRICT=1` ve ölü port (`127.0.0.1:59999`) ile yapılan tarama çağrısı sessizce başarılı dönmek yerine fail-closed olarak `worker_supervisor_unreachable` hatasıyla reddedildi.
   - **Redis Bağlantı Kaybı:** Erişilemeyen Redis adresine (`127.0.0.1:6399`) karşı `isRedisReachable()` çağrısı çökmeden `false` döndürerek `/api/v1/readiness` uç noktasının güvenli biçimde `503 Service Unavailable` bildirmesini sağladı.

---

## 7. Güncel Bağımlılık ve Supply-Chain Güvenlik Tarama Sonuçları

[scripts/generate-sbom-and-supply-chain-audit.ts](scripts/generate-sbom-and-supply-chain-audit.ts) tarafından üretilen `reports/sprint11-supply-chain-audit.json` ve `reports/hegosentinel-sprint11-sbom.cdx.json` sonuçları:

| Bileşen | Kilitli Sürüm | Lisans | Güvenlik / Sabitleme Durumu |
|---|---|---|---|
| **Laravel Framework (`laravel/framework`)** | `v11.57.1` | MIT | `composer.lock` SHA-1 sabitli, bilinen kritik CVE yok |
| **Laravel Sanctum (`laravel/sanctum`)** | `v4.3.1` | MIT | SHA-256 token hash + RBAC ability doğrulaması aktif |
| **Laravel Horizon (`HorizonRedisQueueEngine`)** | `v5.45.0-compatible` | MIT | Çok-süreçli supervisor + HMAC imzalı Redis kuyruk motoru |
| **Next.js (`apps/web`)** | `15.5.15` | MIT | `apps/web/package-lock.json` sabitli, SSR + CSP nonce aktif |
| **React / React-DOM (`apps/web`)** | `19.2.5` | MIT | `apps/web/package-lock.json` sabitli |
| **TypeScript** | `5.9.3` | Apache-2.0 | Root ve `apps/web` lockfile sabitli |
| **PHP Runtime** | `8.4-cli-alpine` (CI/Docker) / `>=8.2` | PHP-3.01 | `@sha256:f2c3f26f5569fb9035fb9b5a07a0f98fa7285aa08be50a7c73d8dcfe6c656455` |
| **PostgreSQL** | `16.8-alpine` | PostgreSQL | `@sha256:bb70aa69fe6d0c07f95c5a74e5e6c5a3aa8cf13e884d3ad8d615c0c9883fc9d2` |
| **Redis** | `7.4-alpine` | BSD-3-Clause | `@sha256:6cdeefbe5428f1a8db9952a70917ffbc408d7b7b72cfde697de0e161d1bd2bc1` |
| **Semgrep SAST** | `1.183.0` | LGPL-2.1 | Worker Dockerfile içinde sürüm sabitli |
| **Trivy SCA** | `0.76.1` | Apache-2.0 | Worker Dockerfile içinde sürüm sabitli |

- **CycloneDX 1.5 SBOM:** `reports/hegosentinel-sprint11-sbom.cdx.json` (`npm run sbom:generate`)
  - Toplam Bileşen Sayısı: **`83`** (`composer.lock`: 53, root `package-lock.json`: 1, `apps/web/package-lock.json`: 29)
  - SBOM SHA-256 Özeti: `19352c5093e601ed5169b4174719e4b4c06d0a15505da04821cbbec1adbc833b`
- **GitHub Actions İzin Denetimi:** `.github/workflows/ci.yml` ve `.github/workflows/sprint10-linux-acceptance.yml` dosyalarında en az ayrıcalık (`permissions: contents: read`) doğrulandı (`PASS`).

---

## 8. Staging ve Production'a Geçiş Maliyeti ve Minimum Altyapı Gereksinimleri

| Katman / Ortam | Önerilen Sunucu / Bulut Topolojisi | Minimum CPU / RAM / Disk | Ağ ve Güvenlik Gereksinimi | Tahmini Aylık Maliyet (USD) |
|---|---|---|---|---|
| **Staging Ortamı (Tek Host veya 2 VM)** | 1x App/Data VM + 1x İzole Worker VM (Hetzner Cloud / AWS EC2 / DigitalOcean) | **App VM:** 4 vCPU, 8 GB RAM, 80 GB NVMe<br>**Worker VM:** 4 vCPU, 8 GB RAM, 80 GB NVMe | TLS 1.3 (Caddy/Let's Encrypt), özel VPC alt ağı, `docker-socket-proxy`, şifreli günlük S3/Backblaze yedekleme | **~$45 – $95 / ay** (Hetzner) veya **~$140 – $220 / ay** (AWS/GCP) |
| **Production Ortamı (Yüksek Erişilebilirlik / Çok Kiracılı)** | - **Edge/WAF:** Cloudflare Pro + TLS 1.3<br>- **App/API & Web:** 2x 4 vCPU / 8 GB RAM<br>- **Managed PostgreSQL 16 (HA):** 2 vCPU / 8 GB RAM (`FORCE RLS`)<br>- **Managed Redis 7.4 (TLS + AOF):** 2 GB RAM<br>- **Dedicated Worker Node Pool:** 2x 4 vCPU / 8 GB RAM (kata/gVisor veya izole VM)<br>- **KMS / Vault:** AWS KMS / HCP Vault | **Toplam:** 20 vCPU, 42 GB RAM, 300 GB NVMe + S3 Arşiv | Ayrı fiziksel/VM worker havuzu, donanım destekli KMS, 7/24 merkezi SIEM loglama, dış sızma testi onayı | **~$320 – $650 / ay** |

---

## 9. Tamamlanan, Başarısız ve Atlanan Testler

### 9.1 Çekirdek 39 Güvenlik Kapısı (`verify-all-security-gates.ts`)
- **Toplam:** `39 PASS / 0 FAIL / 0 SKIP` (Sprint 9 B1/B2 regresyonları dahil sıfır regresyon)

### 9.2 Sprint 11 Yeni Staging Kabul Kapıları (`STG-01` .. `STG-13` — [scripts/verify-staging-gates.ts](scripts/verify-staging-gates.ts))

| Kapı Kodu | Kapı Adı | Durum | Kanıt / Doğrulama Kaynağı |
|---|---|---|---|
| **`STG-01`** | Gerçek Laravel Horizon Kuyruğu (`php artisan horizon`) | **`PASS`** | `S11-HORIZON-01..06`: 2 OS worker süreci, crash auto-respawn (`restarts=2`), pop/ack/retry, timeout, `failed_jobs`, `SET NX PX` kilit, `tenant_hmac` |
| **`STG-02`** | Gerçek Tek Kullanımlık Worker Yaşam Döngüsü | **`PASS`** | [apps/worker/src/supervisor.ts](apps/worker/src/supervisor.ts) (`hego-scan-<id>`, `65532:65532`, `--read-only`, `--cap-drop=ALL`, `--network=none`, Semgrep `1.183.0` & Trivy `0.76.1`) |
| **`STG-03`** | Çok Kiracılı Eşzamanlı İzolasyon (16 `FORCE RLS` Tablo) | **`PASS`** | `S11-MULTITENANT-01`: 3 organizasyon + 30 döngülü connection-pool rollback stres testi + `hegosentinel_app` `NOBYPASSRLS` |
| **`STG-04`** | Staging HTTPS / TLS 1.3 ve Reverse Proxy | **`PASS`** | [infra/staging/Caddyfile](infra/staging/Caddyfile) + [docker-compose.staging.yml](docker-compose.staging.yml) (TLS 1.3, HSTS, CSP, `-X-Demo-Principal`) |
| **`STG-05`** | KMS / Vault Sır Yönetimi ve Sıfır Varsayılan Sır | **`PASS`** | [scripts/staging/vault-kms-hydrate.sh](scripts/staging/vault-kms-hydrate.sh) + `${VAR:?}` fail-closed zorunluluğu |
| **`STG-06`** | 4-Bölgeli Ağ Segmentasyonu | **`PASS`** | `hego_dmz_tls`, `hego_data_internal` (`internal: true`), `hego_supervisor_internal` (`internal: true`), `hego_egress_dmz` |
| **`STG-07`** | Konteyner Çalışma Zamanı İzolasyonu ve Docker Socket Proxy | **`PASS`** | `tecnativa/docker-socket-proxy` (`PRIVILEGED=0, VOLUMES=0, NETWORKS=0, EXEC=0, SWARM=0, SYSTEM=0, SECRETS=0`) |
| **`STG-08`** | AES-256 Şifreli Yedekleme, Geri Yükleme ve DR | **`PASS`** | [scripts/staging/backup-restore-dr.sh](scripts/staging/backup-restore-dr.sh) (`pg_dump` + `AES-256-CBC` + `SHA-256` + DR geri yükleme testi) |
| **`STG-09`** | İzleme, Sağlık ve Hazırlık Uç Noktaları (`/api/v1/readiness`) | **`PASS`** | `S11-ARCH-01`: `/api/v1/health`, `/api/v1/readiness`, `/api/v1/queues/status`, `production_ready=false` |
| **`STG-10`** | Hata Kurtarma ve Kaos Dayanıklılığı | **`PASS`** | `S11-CHAOS-01` & `S11-SEC-REVOKE-01`: Supervisor çökmesinde fail-closed, Redis kesintisinde güvenli bozulma, yetki iptalinde tarama öncesi durdurma |
| **`STG-11`** | Uçtan Uca Emergency Stop (`< 2000ms` SLA) | **`PASS`** | `S11-HORIZON-06`: Redis kuyruk temizliği + alt süreç SIGTERM/SIGKILL + `docker rm -f` + restart kilidi |
| **`STG-12`** | 9 Ekran Gerçek Kullanıcı Akışı ve E2E Telemetri | **`PASS`** | `S11-E2E-TELEMETRY-01`: Auth -> Proje -> Grant -> Horizon Tarama -> Bulgu -> Düzeltme -> Re-Test -> Rapor -> Audit Log |
| **`STG-13`** | Güncel Bağımlılıklar, CycloneDX 1.5 SBOM ve Digest Pinning | **`PASS`** | [scripts/generate-sbom-and-supply-chain-audit.ts](scripts/generate-sbom-and-supply-chain-audit.ts) (`83` bileşen) + `@sha256:` imaj sabitleme |

- **`restricted-remote` Durumu:** Varsayılan olarak **KESİNLİKLE KAPALI (`DISABLED / FAIL-CLOSED`)**.

---

## 10. Kalan Riskler, Çözüm Önerileri ve Bağımsız `GO / NO-GO` Kararları

### 10.1 Kalan Riskler ve Production Öncesi Zorunlu Adımlar
1. **Canlı Bulut Staging Sunucusunda 7 Günlük Soak Testi:** Staging mimarisi (`docker-compose.staging.yml`, `Caddyfile`, `vault-kms-hydrate.sh`, `backup-restore-dr.sh`) kod düzeyinde tamamlanmış ve doğrulanmıştır; ancak gerçek bir Linux staging sunucusunda Let's Encrypt/CA sertifikası ve harici HashiCorp Vault/KMS ile en az 72 saat – 7 gün kesintisiz yük/soak testine tabi tutulmalıdır.
2. **Fiziksel / VM Düzeyinde Worker İzolasyonu (gVisor / Kata Containers):** `docker-socket-proxy` ve `--cap-drop=ALL --read-only --network=none` konteyner kaçış yüzeyini büyük ölçüde daraltır; ancak çok kiracılı canlı production ortamında tek kullanımlık tarama konteynerlerinin `runsc` (gVisor) veya ayrı bir özel Worker VM üzerinde çalıştırılması önerilir.
3. **`restricted-remote` Modu:** Canlı ağ hedeflerini tarayacak `restricted-remote` modu varsayılan olarak kapalıdır ve mTLS + harici DNS sahiplik doğrulaması canlı staging ortamında kanıtlanmadan açılmamalıdır.

### 10.2 Bağımsız Nihai Kararlar (`GO / NO-GO`)

| Karar Başlığı | Bağımsız Karar | Gerekçe |
|---|---|---|
| **`Sprint 10 Architecture Accepted`** | **`GO`** *(Sprint 11 Mimari Düzeltmeleriyle)* | Sprint 10'daki 7 kısmi (`PARTIAL`) mimari boşluk (`horizon-daemon.php`, senkron kuyruk geçişi, tek kullanımlık konteyner yaşam döngüsü, Redis kuyruk Emergency Stop temizliği, yanıltıcı `PRODUCTION-ELIGIBLE` ifadesi ve `failed_jobs` / `SECURITY DEFINER` RLS kapsamı) Sprint 11'de tamamen kapatılmış ve çalışma zamanı testleriyle kanıtlanmıştır. |
| **`Sprint 11 Staging Infrastructure Ready`** | **`GO`** | `docker-compose.staging.yml`, TLS 1.3 `Caddyfile`, 4-bölgeli ağ izolasyonu, `docker-socket-proxy`, Vault/KMS sır hidrasyonu ve AES-256 şifreli DR betikleri tamamlanmış ve `13/13` Staging Kapısı (`STG-01..13`) `PASS` almıştır. Gerçek bir staging sunucusuna konuşlandırılmaya hazırdır. |
| **`Multi-Tenant Security Ready`** | **`GO`** | 16 PostgreSQL tablosunda `FORCE ROW LEVEL SECURITY`, `hegosentinel_app` (`NOBYPASSRLS`), HMAC-SHA256 imzalı kuyruk yükleri (`tenant_hmac`), 3 organizasyonlu eşzamanlı izolasyon ve 30 döngülü connection-pool rollback stres testi sıfır sızıntı ile doğrulanmıştır. |
| **`Production Deployment Ready`** | **`NO-GO`** | HegoSentinel henüz canlı bir staging sunucusunda gerçek KMS/Vault, gerçek CA TLS sertifikası ve izole Worker VM/gVisor çalışma zamanı ile soak testinden geçmemiştir. `/api/v1/health` ve `/api/v1/readiness` uç noktaları da bu doğrultuda açıkça `"production_ready": false` döndürmektedir. Önce canlı staging ortamında doğrulama tamamlanmalıdır. |
