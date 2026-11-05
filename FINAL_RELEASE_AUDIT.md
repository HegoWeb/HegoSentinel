# HEGOSENTINEL — FINAL PUBLIC ALPHA RELEASE AUDIT (`v0.1.0-alpha.4`)

- **Denetim Tarihi:** `2026-11-05`
- **Denetlenen Kanonik Dal / Commit:** `main @ 1cda48d` + Sprint 9 Güvenlik ve Yayın Hazırlığı Çalışma Ağacı
- **Denetim Ortamı:** Windows 10.0.26200 (x64) · Node.js `v24.12.0` · PHP `8.4.6` (`pdo_sqlite`) · Semgrep CE `1.183.0` · Trivy `0.76.1` · Docker Engine: **Kurulu Değil (`ENOENT`)**
- **Kanıt Dizini:** [`docs/audit-evidence/final-release-audit/`](docs/audit-evidence/final-release-audit/) ve [`docs/audit-evidence/sprint9/`](docs/audit-evidence/sprint9/)

> **Denetim İlkesi:** Bu rapor projeyi koşulsuz onaylamak için değil; gerçek çalışma zamanı testleri, kaynak kod incelemesi ve depo hijyeni kontrolleriyle GitHub üzerinde açık kaynak alfa (`v0.1.0-alpha.4`) olarak yayımlanmaya hazır olup olmadığını kanıtlamak için hazırlanmıştır.

---

## 1. Kritik Güvenlik Kontrolleri (Çalışma Zamanı Doğrulaması)

### 1.1 Önceki Denetimlerde Bulunan İki P0 Açığın Kapanış Kanıtı

| Bulgu | Önceki Durum (`HEAD 1cda48d`) | Güncel Durum (Çalışma Zamanı Testi) | Doğrulama Kanıtı |
| :--- | :--- | :--- | :--- |
| **`B1` — `X-Demo-Principal` Kimlik Doğrulama Atlatması** | `X-Demo-Principal: owner` başlığıyla `/api/v1/projects`, `/api/v1/scans`, `/api/v1/audit-logs` uç noktaları token olmadan `200 OK` dönüyordu ([`S9-before-fix-php-battery.log`](docs/audit-evidence/sprint9/S9-before-fix-php-battery.log)). | **KAPATILDI (`PASS`)**: `APP_ENV=production`, `testing` ve `local` modlarında `X-Demo-Principal` (tüm büyük/küçük harf varyasyonları dahil) tamamen yok sayılır ve oturumsuz istekler `401 AUTHENTICATION_REQUIRED` ile reddedilir. `APP_ENV=production` iken `HEGOSENTINEL_DEMO_MODE=1` verilse dahi demo kullanıcıları oluşturulmaz (`A1..A7`, `B1..B2`, `C1..C2`). | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log), [`S9-after-fix-php-battery.log`](docs/audit-evidence/sprint9/S9-after-fix-php-battery.log), [`run-security-regression-tests.php`](apps/api/tests/run-security-regression-tests.php) |
| **`B2` — Trusted Egress Broker Audit Log URL/Başlık Sızıntısı** | Hedef URL içindeki `?token=...&password=...&secret=...&code=...&api_key=...` parametreleri ilk denetim kaydına düz metin yazılıyordu; worker başlıkları (`x-api-key`, `x-forwarded-for`) hedefe iletiliyor ve `/v1/egress/fetch` gövdesindeki `now` alanı süresi dolmuş grant'i yeniden geçerli kılıyordu ([`B2-before-fix-http.log`](docs/audit-evidence/sprint9/B2-before-fix-http.log)). | **KAPATILDI (`PASS`)**: İlk audit kaydı ve SHA-256 zinciri hesaplanmadan önce [`sanitizeUrlForAudit()`](apps/egress-broker/src/index.ts) ve [`sanitizeAuditText()`](apps/egress-broker/src/index.ts) çalışır; tüm gizli sorgu parametreleri, URL `userinfo` ve `#fragment` verileri `[REDACTED]` olarak maskelenir. Yalnızca `BROKER_OUTBOUND_HEADER_ALLOWLIST` (`accept-language`, `x-custom-trace`) iletilir; redirect takip edilmez (`followRedirects: false`) ve `Location` başlığı maskelenir; worker `now`/`env`/`signal` alanları [`buildTrustedProxyRequestFromWorkerPayload()`](apps/egress-broker/src/index.ts) tarafından atılır. | [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log), [`B2-after-fix-http.log`](docs/audit-evidence/sprint9/B2-after-fix-http.log), [`broker-b2-regression.test.ts`](tests/security/broker-b2-regression.test.ts) |

### 1.2 Yedi Güvenlik Alanının Yeniden Doğrulaması

| Güvenlik Alanı | Durum | Çalışma Zamanı Doğrulama Özeti ve Kalan Sınırlar | Kanıt / Test Referansı |
| :--- | :---: | :--- | :--- |
| **1. Tenant Isolation (`SEC-011`)** | **PASS** | `org-beta-isolated` kiracısı `org-hegoweb-sec` kiracısına ait proje, kapsam yetkisi, tarama, bulgu, görev, rapor, yeniden test ve bildirim nesnelerinin tamamında `403`/`404` alır (`C5`, `C6`). `/api/v1/auth/register` istemcinin gönderdiği `organization_id` ve `role` alanlarını yok sayarak her zaman yeni ve izole bir organizasyon açar (`C15..C17`). Cross-tenant ret kayıtlarında yabancı proje ID'si yerine yalnızca SHA-256 `foreign_ref` özeti tutulur. | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) (`SEC-011`, `C5..C6`, `C15..C17`) |
| **2. RBAC & Proje Yetkisi (`SEC-011`)** | **PASS** | `viewer` rolü proje/grant/tarama/re-test/acil durdurma/üye daveti başlatamaz (`C7`). `viewer` ve `developer` rolleri `/api/v1/audit-logs` uç noktasını okuyamaz (`C8`, `C9`). Hiçbir rol (Owner dahil) Re-Test çalışmadan bir görevi elle `verified_closed` yapamaz (`C12`, `C13`). `allowed_project_ids` kısıtlaması hem tekil okumalarda hem bildirim/acil durdurma listelerinde uygulanır (`C14`, `C14e`, `C20`). | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) (`C7..C14e`, `C18..C20`) |
| **3. SSRF & DNS Rebinding (`SEC-002..004`, `EGR-003`)** | **PASS** | IPv4/IPv6 özel, loopback, link-local, CGNAT, bulut metadata (`169.254.169.254`, `fd00:ec2::254`, `::ffff:169.254.169.254`) adresleri, kapsam dışı yönlendirmeler (`SEC-003`) ve doğrulama ile soket bağlantısı arasındaki DNS rebinding (`SEC-004`, `EGR-003`) deterministik olarak reddedilir. Canlı uzak ağ taraması (`restricted-remote`) `SEC-005` kapısıyla kapalıdır (**fail-closed**). | [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log), [`17-security-gates-verification.md`](docs/audit-evidence/final-release-audit/17-security-gates-verification.md) |
| **4. Worker Isolation & Path Confinement (`SEC-006`, `WKR-001..006`)** | **PARTIAL (`PASS` Host / `SKIP` Docker)** | **Doğrulanan (`PASS`):** `realpathSync` + `lstatSync` sembolik bağ kaçışı (`HS-AUDIT-002`, `NEW-01`), `shell: false`, `AbortSignal` (`SIGTERM` -> `SIGKILL`) alt süreç sonlandırma (`WKR-005/006`) ve PHP API [`RuntimeMode::resolveRepositoryPath()`](apps/api/app/Support/RuntimeMode.php) ile `repository_path` değerinin yalnızca çalışma alanı içindeki `examples/` dizinlerine ve projenin kayıtlı varlıklarına sınırlandırılması (`C21..C26`).<br>**Kalan Sınır (`SKIP`):** Bu Windows makinede Docker Engine bulunmadığından `WKR-001..005` konteyner çalışma zamanı testleri `SKIP (not verified)` olarak raporlanır ve [`ExecuteAuthorizedScanJob`](apps/api/app/Jobs/ExecuteAuthorizedScanJob.php) taramayı konteyner yerine kısıtlı yerel alt süreç (`proc_open` -> `scripts/api-worker-bridge.ts`) olarak çalıştırır. | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) (`C21..C26`), [`09-full-ts-tests-real-binaries.log`](docs/audit-evidence/final-release-audit/09-full-ts-tests-real-binaries.log) |
| **5. Secret Redaction (`SEC-007`)** | **PASS** | Çerez değerleri ayrıştırma anında atılır; 9 aşamalı maskeleme motoru (`Set-Cookie`, `Authorization: Bearer`, URL parolaları, AWS anahtarları, GitHub PAT, JWT, PEM özel anahtarları, DB bağlantı dizgeleri, `APP_KEY`, `NEXTAUTH_SECRET`) JSON, Markdown, HTML ve SARIF raporlarında sıfır sızıntı ile doğrulanmıştır. | [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log) (`SEC-007`), [`14-demo.log`](docs/audit-evidence/final-release-audit/14-demo.log) |
| **6. Emergency Stop (`SEC-012`)** | **PASS** | Hem çekirdek `EmergencyStopRegistry` (`SEC-012`) hem PHP API proje genelinde acil durdurma (`POST /api/v1/emergency-stop`) doğrulanmıştır. Proje bazlı acil durdurma tetiklendiğinde, istemci bayrağına bakılmaksızın 900 saniye boyunca aynı projede yeni tarama başlatılması `409 EMERGENCY_STOP_ACTIVE` ile engellenir (`C27..C30`). | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) (`C27..C30`), [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log) |
| **7. Notification Authorization (`SEC-013`)** | **PASS** | Genel webhook hedefleri (`hooks.slack.com`, `discord.com`, `webhook.site`, `ngrok.io` vb.), doğrulanmamış alıcı alan adları, maskelenmemiş sırlar ve yetkisiz roller (`developer`/`viewer`) reddedilir; bildirim listesi kullanıcının yetkili olduğu projelere göre süzülür (`C14`). | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) (`Module 12`, `C14`) |

---

## 2. Tam Sistem Doğrulaması (Güncel Test Sonuçları ve Kanıt Dosyaları)

Tüm testler `2026-11-05` tarihinde mevcut çalışma ağacı üzerinde yeniden koşturulmuş ve çıktıları [`docs/audit-evidence/final-release-audit/`](docs/audit-evidence/final-release-audit/) dizinine kaydedilmiştir:

| Kontrol / Test Paketi | Komut | Exit Code | `PASS` | `FAIL` | `SKIP` | Kanıt Dosyası |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **1. Statik Politika ve Kaynak Lint** | `npm run lint` | `0` | **1** | `0` | `0` | [`01-lint.log`](docs/audit-evidence/final-release-audit/01-lint.log) |
| **2. Gerçek TypeScript Derleyicisi (`tsc --noEmit`) & Şema** | `npm run typecheck` | `0` | **1** | `0` | `0` | [`02-typecheck.log`](docs/audit-evidence/final-release-audit/02-typecheck.log) |
| **3. Dokümantasyon Bağlantı Kontrolü** | `npm run docs:links` | `0` | **115** | `0` | `0` | [`03-docs-links.log`](docs/audit-evidence/final-release-audit/03-docs-links.log) |
| **4. PHP API Fonksiyonel + Güvenlik Regresyon Testleri** | `npm run test:api` | `0` | **86** *(36 + 50)* | `0` | `0` | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log) |
| **5. Birim (Unit) Testleri** | `npm run test:unit` | `0` | **3** | `0` | `0` | [`05-unit-tests.log`](docs/audit-evidence/final-release-audit/05-unit-tests.log) |
| **6. Entegrasyon Testleri (Semgrep/Trivy/SARIF)** | `npm run test:integration` | `0` | **1** | `0` | `0` | [`06-integration-tests-sandbox.log`](docs/audit-evidence/final-release-audit/06-integration-tests-sandbox.log) |
| **7. Güvenlik Matrisi & B2 Regresyon (`test:security`)** | `npm run test:security` | `0` | **65** *(66 gerçek ikili ile)* | `0` | **6** *(5 gerçek ikili ile)* | [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log) |
| **8. Uçtan Uca (E2E) CLI & Web/API Testleri** | `npm run test:e2e` | `0` | **9** | `0` | `0` | [`08-e2e-tests.log`](docs/audit-evidence/final-release-audit/08-e2e-tests.log) |
| **9. Tam TypeScript Test Paketi (Gerçek Semgrep `1.183.0` + Trivy `0.76.1` ile)** | `npm test` | `0` | **79** | `0` | **5** | [`09-full-ts-tests-real-binaries.log`](docs/audit-evidence/final-release-audit/09-full-ts-tests-real-binaries.log) |
| **10. Gerçek Semgrep CE & Trivy İkili Sürüm Doğrulaması** | `semgrep --version && trivy --version` | `0` | **2** (`1.183.0` / `0.76.1`) | `0` | `0` | [`10-real-semgrep-trivy-versions.log`](docs/audit-evidence/final-release-audit/10-real-semgrep-trivy-versions.log) |
| **11. Birleşik Güvenlik Kapıları (`SEC-001..014`, `WKR`, `EGR`, Gerçek Tarayıcılar)** | `npm run verify:gates` | `0` | **27** | `0` | **5** | [`11-verify-gates-real-binaries.log`](docs/audit-evidence/final-release-audit/11-verify-gates-real-binaries.log), [`17-security-gates-verification.md`](docs/audit-evidence/final-release-audit/17-security-gates-verification.md) |
| **12. Üretim Yayın Kapısı (`verify:release-gate`)** | `npm run verify:release-gate` | `0` *(Bilgilendirme: `BLOCKED`)* / `--enforce-production-release` ile **`1`** | **27** | `0` | **5** *(Üretim Engelleyici)* | [`12-verify-release-gate-real-binaries.log`](docs/audit-evidence/final-release-audit/12-verify-release-gate-real-binaries.log) |
| **13. Çevrimdışı Sentetik Demo Döngüsü** | `npm run demo` | `0` | **1** | `0` | `0` | [`14-demo.log`](docs/audit-evidence/final-release-audit/14-demo.log) |
| **14. Yerel Docker Engine & Git Remote Kontrolü** | `git remote -v ; docker --version` | `1` (`docker` yok) | — | — | **SKIP (Yerel)** | [`13-docker-and-github-actions-check.log`](docs/audit-evidence/final-release-audit/13-docker-and-github-actions-check.log) |
| **15. GitHub Actions `ubuntu-24.04` Tam CI & Konteyner/Netns Doğrulaması (`Run #4 [42076698840]`)** | `6/6` CI İşi (`WKR-001..005`, `EGR-LINUX-NETNS-RUNTIME`, Semgrep `1.183.0`, Trivy `0.76.1`, PHP API `86/86`, Gitleaks, `verify:release-gate`) | `0` | **32/32 Kapı (`7/7` İş)** | `0` | `0` | [`20-github-actions-ubuntu2404-run-42076698840.log`](docs/audit-evidence/final-release-audit/20-github-actions-ubuntu2404-run-42076698840.log) |

> **Özet Skor:**
> - **TypeScript Test Paketi (`npm test`):** Toplam **84 test** -> **`79 PASS`, `0 FAIL`, `5 SKIP (not verified)`** (Yalnızca Docker/Linux gerektiren `WKR-001..005` runtime konteyner testleri `SKIP`).
> - **PHP API Test Paketi (`npm run test:api`):** Toplam **86 iddia (assertion)** -> **`86 PASS`, `0 FAIL`**.
> - **Birleşik Güvenlik Kapıları (`npm run verify:gates`):** Toplam **32 kapı** -> **`27 PASS` (gerçek Semgrep `1.183.0` ile 6 SAST bulgusu ve gerçek Trivy `0.76.1` ile 61 SCA/yapılandırma bulgusu dahil), `0 FAIL`, `5 SKIP (not verified)`** (`WKR-001-RUNTIME`, `WKR-002-RUNTIME`, `WKR-003-RUNTIME`, `WKR-005-RUNTIME`, `EGR-LINUX-NETNS-RUNTIME`).

---

## 3. Frontend ve Backend Mimari Doğrulaması

`apps/api`, `apps/web`, `apps/worker` ve `apps/egress-broker` dizinleri satır satır incelenerek gerçek mimari yapı aşağıda belgelenmiştir:

### 3.1 Gerçek Teknoloji Yığını vs. Planlanan Çerçeveler

| Dizin | İddia Edilen / Hedeflenen Mimari | Gerçekte Çalışan Kod (Doğrulanmış Durum) | Sınıflandırma |
| :--- | :--- | :--- | :--- |
| **[`apps/api`](apps/api/)** | Laravel 11 + PostgreSQL + Redis + Laravel Horizon + Sanctum ([`composer.json`](apps/api/composer.json)) | **Özel (Custom) Sıfır Bağımlılıklı PHP 8.4 + SQLite PDO REST API.** `vendor/` dizini yoktur; [`bootstrap/autoload.php`](apps/api/bootstrap/autoload.php) kendi PSR-4 yükleyicisini kullanır. [`apps/api/artisan`](apps/api/artisan) içindeki `horizon` ve `queue:work` komutları yalnızca konsola mesaj yazıp çıkan birer **stub**'dır. Tarama işleri ([`ExecuteAuthorizedScanJob.php`](apps/api/app/Jobs/ExecuteAuthorizedScanJob.php)) Redis kuyruğu yerine `proc_open` ile senkron olarak [`scripts/api-worker-bridge.ts`](scripts/api-worker-bridge.ts) alt sürecini çalıştırır. | **`PROTOTYPE IMPLEMENTED & TESTED`** *(Tam Laravel/PostgreSQL/Horizon: `PLANNED`)* |
| **[`apps/web`](apps/web/)** | Next.js 15 App Router + React 19 ([`apps/web/package.json`](apps/web/package.json)) | **Özel (Custom) Node.js `node:http` SSR + Vanilla JS Tek Sayfa Uygulaması ([`apps/web/src/server.ts`](apps/web/src/server.ts)).** `npm run dev` ve `npm start` doğrudan `src/server.ts` dosyasını çalıştırır. [`apps/web/src/app/page.tsx`](apps/web/src/app/page.tsx) yalnızca 152 satırlık tek panelli bir React özet bileşenidir; 9 ekranlı gerçek arayüz `src/server.ts` içindedir. | **`PROTOTYPE IMPLEMENTED & TESTED`** *(Tam Next.js App Router: `PLANNED`)* |
| **[`apps/worker`](apps/worker/)** | Kısıtlı Docker Worker (`--network=none`, `--read-only`, `65532:65532`) | [`apps/worker/src/index.ts`](apps/worker/src/index.ts) konteyner güvenlik politikası doğrulayıcısını, `docker run` argüman üreticisini (`WKR-001..005`), `analyzeDockerRunOutcome()` çıkış kodu denetimini ve `AbortSignal` (`SIGTERM` -> `SIGKILL`) alt süreç yönetimini içerir. Linux/Docker olmayan bu makinede çalışma zamanı konteyner testleri dürüstçe `SKIP` üretir. | **`IMPLEMENTED (Policy & Subprocess) / SKIP (Docker Runtime)`** |
| **[`apps/egress-broker`](apps/egress-broker/)** | Worker dışı Trusted Egress Broker (`EGR-001..006`) | [`apps/egress-broker/src/index.ts`](apps/egress-broker/src/index.ts) üzerinde tam çalışan HTTP sunucusu (`createTrustedEgressBrokerServer`), HMAC imzalı `SignedRemoteExecutionGrant` doğrulayıcısı, tek kullanımlık nonce kaydı, SSRF/DNS rebinding engeli, `BROKER_OUTBOUND_HEADER_ALLOWLIST` ve gizli parametre maskelemeli SHA-256 denetim zinciri mevcuttur. | **`IMPLEMENTED & TESTED (User-Space / HTTP) / SKIP (Linux netns)`** |

### 3.2 `apps/web` Ekranlarının Backend İşlemleriyle Bağlantı ve Demo Verisi Denetimi

[`apps/web/src/server.ts`](apps/web/src/server.ts) içindeki 9 ekranın tamamı incelenmiştir:

| Ekran | Bağlı Olduğu Gerçek API Uç Noktaları | Gerçek Backend İşlemi mi? | Statik / Simüle / Demo Veri İçeren Unsurlar |
| :--- | :--- | :---: | :--- |
| **01. Genel Bakış (`#screen-dashboard`)** | `GET /api/v1/dashboard`, `GET /api/v1/scans`, `GET /api/v1/audit-logs` | **Evet** (Oturum açıldığında SQLite metriklerini okur) | Oturum açılmadan önceki ilk HTML şablonunda varsayılan KPI sayıları (`3` proje, `1` tarama) yer alır; ancak varsayılan modda (`DEMO_MODE=false`) uygulama doğrudan `09. Oturum & Rol` ekranına yönlenir. |
| **02. Projeler & Kapsam (`#screen-projects`)** | `GET /api/v1/projects`, `POST /api/v1/projects`, `POST /api/v1/projects/:id/grants` | **Evet** (Gerçek SQLite kaydı ve `SEC-001`/`SEC-002` doğrulaması yapar) | Form alanlarında kullanıcıya örnek olması için ön tanımlı `value` değerleri (`HegoPay Core API`, `demo.example.test`, `AUTH-DOC-2026-HEGOPAY-09`) bulunur; değiştirilerek gönderilebilir. |
| **03. Güvenlik Tarayıcı (`#screen-scanner`)** | `POST /api/v1/scans`, `GET /api/v1/scans`, `POST /api/v1/emergency-stop` | **Evet** (`proc_open` ile `api-worker-bridge.ts` üzerinden gerçek Semgrep/Trivy ve çevrimdışı web kontrollerini çalıştırır) | **Simüle Etiket:** Tablo başlığındaki `Horizon / Queue: hegosentinel-scans` rozeti statiktir; gerçekte Redis/Horizon kuyruğu yoktur, tarama senkron alt süreç olarak çalışır. Ayrıca web kontrolleri (`WEB-*`) çevrimdışı fikstür (`offline-fixture`) üzerinde çalışır; `restricted-remote` modu fail-closed olarak engellenir. |
| **04. Zafiyet Bulguları (`#screen-vulnerabilities`)** | `GET /api/v1/findings`, `POST /api/v1/findings/:id/suppress` | **Evet** (Gerçek bulgu listeleme, filtreleme ve `SEC-010` kapsam bazlı `false_positive` bastırma) | `HEGOSENTINEL_DEMO_MODE=1` açıkken ilk tohumlanan tarama verileri görüntülenir; her bulguda `real_scan` / `demo_seed` rozeti açıkça gösterilir. |
| **05. Çözüm Merkezi (`#screen-remediation`)** | `GET /api/v1/remediation-tasks`, `PATCH /api/v1/remediation-tasks/:id` | **Evet** (`in_progress` ve `ready_for_retest` durum güncellemeleri SQLite üzerinde kalıcıdır) | `verified_closed` durumu elle seçilemez; yalnızca Ekran 06'daki gerçek Re-Test karşılaştırması ile otomatik kapanır (`S9-08`). |
| **06. Yeniden Test & Fark (`#screen-rechecks`)** | `GET /api/v1/rechecks`, `POST /api/v1/rechecks` | **Evet** (`packages/recheck-engine` ile gerçek parmak izi ve kapsam versiyonu karşılaştırması yapar) | Yok — gerçek tarama çiftlerini karşılaştırır. |
| **07. Raporlar & Bildirim (`#screen-reports`)** | `GET /api/v1/scans/:id/export?format=...`, `GET /api/v1/notifications`, `POST /api/v1/notifications` | **Rapor: Evet / Bildirim: Simüle** | **Simüle Gönderim:** `POST /api/v1/notifications` tüm `SEC-013` güvenlik kontrollerini (alıcı alan adı, genel webhook engeli, sır taraması, RBAC) gerçekte uygular ve kaydı `dispatched` olarak SQLite'a yazar; ancak gerçek bir harici SMTP veya HTTP webhook isteği göndermez. |
| **08. Ayarlar & Denetim (`#screen-settings`)** | `GET /api/v1/organization`, `POST /api/v1/organization/members`, `GET /api/v1/audit-logs` | **Evet** (Gerçek bcrypt parola ile üye ekleme, RBAC rol güncelleme ve SHA-256 zincir doğrulaması) | Üye ekleme formunda örnek `Demo SecOps` / `secops@hegoweb.local` varsayılan değerleri bulunur. |
| **09. Oturum & Rol (`#screen-auth`)** | `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `POST /api/v1/auth/register` | **Evet** (Gerçek Bearer token oturumu, brute-force koruması ve yeni organizasyon kaydı) | Üst çubuktaki hızlı rol seçici (`#quick-role-select`) ve ön-doldurulmuş demo giriş bilgileri **yalnızca** operatör `HEGOSENTINEL_DEMO_MODE=1` (ve `APP_ENV!=production`) ayarladığında aktif olur; varsayılan/üretim modunda DOM'dan kaldırılır. |

---

## 4. GitHub Yayın Temizliği ve Tekrar Üretilebilirlik Denetimi

### 4.1 Sır, Kişisel Veri ve Müşteri Kodu Taraması

Kanıt dosyası: [`16-repo-hygiene-and-secret-scan.log`](docs/audit-evidence/final-release-audit/16-repo-hygiene-and-secret-scan.log)

1. **Aktif Çalışma Ağacı (`apps/`, `packages/`, `integrations/`, `scripts/`, `tests/`):**
   - Gerçek API anahtarı, özel anahtar (`.pem`/`.key`), `.env` dosyası veya müşteri kaynak kodu: **`0` eşleşme.**
   - Kişisel görünüm taşıyan tüm örnek isimler (`[PERSONAL_NAME_REDACTED]`, `[DEMO_PERSONA_REDACTED]`, `[DEMO_PERSONA_REDACTED]`, `[DEMO_PERSONA_REDACTED]`, `[DEMO_PERSONA_REDACTED]`) aktif kaynak koddan temizlenmiş; yerlerine `Demo Owner`, `Demo Security Lead`, `Demo Developer`, `Demo SecOps`, `Demo Operator` atanmıştır (**`0` eşleşme**).
2. **Git Geçmişi (`git log --all -p`):**
   - Gerçek sır / token sızıntısı: **`0` eşleşme.** (Geçmişteki tek `AKIA...` eşleşmesi, `SEC-007` maskeleme testinde kullanılan sentetik AWS dokümantasyon örneği `AKIAIOSFODNN7EXAMPLE` dizgesidir.)
   - **Önemli Git Geçmişi Notu:** `26ec85b` numaralı önceki commit içinde `[PERSONAL_NAME_REDACTED]` ismi 4 kez geçmektedir (güncel çalışma ağacında silinmiştir). Eğer GitHub'a gönderilecek açık kaynak depoda geçmiş commit farklarında (`git log -p`) bu ismin hiç görünmemesi isteniyorsa, Bölüm 5.2'deki tek-commit (orphan/squash) yayın komutu kullanılmalıdır.

### 4.2 `.gitignore` ve Dışlanan Dosyalar Kontrolü

[`.gitignore`](.gitignore) dosyası doğrulanmış olup aşağıdaki dizin ve dosyaların **hiçbiri** GitHub yayın listesinde yer almamaktadır (`Forbidden files included: 0`):
- `.tools/` (yerel Python, Semgrep `1.183.0` ve Trivy `0.76.1` ikilileri)
- `node_modules/` ve `vendor/`
- `apps/api/database/*.sqlite`, `*.sqlite-shm`, `*.sqlite-wal`
- `reports/*.json`, `reports/*.md`, `reports/*.html`, `reports/*.sarif.json` (yalnızca `reports/README.md` takip edilir)
- `.env*`, `*.zip`, `*.tar`, `*.7z`, `*.pem`, `*.key`

### 4.3 Temiz Bilgisayarda Kurulumun Tekrar Üretilebilirliği

1. **Sıfır Harici Çalışma Zamanı NPM Bağımlılığı:** Kök [`package.json`](package.json) yalnızca `devDependencies: { "typescript": "^5.9.3" }` içerir; tüm çekirdek paketler, `apps/web/src/server.ts`, `apps/worker` ve `apps/egress-broker` Node.js `>=22.6.0` yerleşik modülleriyle (`--experimental-strip-types`) çalışır.
2. **PHP API Sıfır Composer Bağımlılığı ile Çalışma:** `apps/api` standart PHP `>=8.2` (`ext-pdo`, `pdo_sqlite`, `ext-json`, `ext-openssl`) ile `composer install` gerektirmeden [`bootstrap/autoload.php`](apps/api/bootstrap/autoload.php) üzerinden doğrudan çalışır ve SQLite şemasını otomatik oluşturur.
3. **Semgrep CE ve Trivy Kurulumu:**
   - Windows üzerinde [`scripts/install-local-scanners.ps1`](scripts/install-local-scanners.ps1),
   - Linux / GitHub Actions `ubuntu-24.04` üzerinde [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (`semgrep==1.183.0`, `trivy_0.76.1_Linux-64bit.tar.gz`) ile sabit sürümler tekrar üretilebilir biçimde kurulur.

### 4.4 GitHub'a Gönderilecek Dosyaların Son Listesi

GitHub'a gönderilecek toplam **197** dosyanın tam listesi [`docs/audit-evidence/final-release-audit/15-github-publish-file-list.txt`](docs/audit-evidence/final-release-audit/15-github-publish-file-list.txt) dosyasında kayıtlıdır (`FINAL_RELEASE_AUDIT.md` ve `docs/audit-evidence/final-release-audit/*` kanıtlarıyla birlikte **215** dosya):

- **Kök Yapılandırma & Belgeler (14 dosya):** `.gitattributes`, `.gitignore`, `CHANGELOG.md`, `CONTRIBUTING.md`, `FINAL_RELEASE_AUDIT.md`, `LICENSE`, `PROJECT_STATUS.md`, `README.md`, `README.tr.md`, `SECURITY.md`, `docker-compose.yml`, `package.json`, `package-lock.json`, `tsconfig.json`
- **CI İş Akışı (1 dosya):** `.github/workflows/ci.yml`
- **Uygulama Servisleri (`apps/` — 40 dosya):**
  - `apps/api/` (18 dosya: `artisan`, `composer.json`, `Dockerfile`, `.env.example`, `bootstrap/autoload.php`, `config/*.php`, `database/migrations/*`, `public/index.php`, `routes/api.php`, `app/Http/Controllers/Api/V1/PlatformApiController.php`, `app/Jobs/ExecuteAuthorizedScanJob.php`, `app/Services/SecurityPlatformService.php`, `app/Support/DatabaseManager.php`, `app/Support/RuntimeMode.php`, `tests/run-api-tests.php`, `tests/run-security-regression-tests.php`)
  - `apps/web/` (12 dosya: `src/server.ts`, `src/lib/api-client.ts`, `src/lib/i18n.ts`, `src/app/*`, `package.json`, `tsconfig.json`, `Dockerfile`, `next.config.mjs`, `components.json`)
  - `apps/worker/` (7 dosya: `src/index.ts`, `source-offline-manifest.json`, `container-policy.json`, `seccomp-profile.json`, `network-egress-policy.sh`, `Dockerfile`, `package.json`)
  - `apps/egress-broker/` (3 dosya: `src/index.ts`, `Dockerfile`, `package.json`)
- **Çekirdek Paketler & Entegrasyonlar (`packages/`, `integrations/`, `schemas/`, `types/` — 26 dosya):** `findings-schema`, `policy-engine`, `remediation-catalog`, `scanner-core`, `report-engine`, `recheck-engine`, `integrations/semgrep`, `integrations/trivy`, JSON şemaları (`finding`, `report`, `recheck`, `scope-grant`)
- **Sentetik Test Hedefleri & Betikler (`examples/`, `scripts/` — 26 dosya):** `examples/synthetic-targets/{laravel-app,nextjs-app,nodejs-service,semgrep-rules.yml}`, `scripts/verify-all-security-gates.ts`, `scripts/release-gate-check.ts`, `scripts/check-markdown-links.ts`, `scripts/linux-*.sh`, `scripts/install-local-scanners.ps1`
- **Otomatik Test Paketleri (`tests/` — 11 dosya):** `tests/unit/*`, `tests/integration/*`, `tests/security/*` (6 dosya), `tests/e2e/*` (2 dosya)
- **Mimari Belgeler, Arşiv & Denetim Kanıtları (`docs/`, `reports/README.md` — 97 dosya):** `docs/ARCHITECTURE.md`, `docs/PRODUCT_REQUIREMENTS.md`, `docs/ROADMAP.md`, `docs/RELEASE_READINESS.md`, `docs/TEST_CATALOG.md`, `docs/THREAT_MODEL.md`, `docs/security/*`, `docs/archive/*`, `docs/audit-evidence/*`

---

## 5. Nihai Bağımsız Karar

### 5.1 Üçlü Yayın Kararı

| Hedef Ortam | Karar | Somut Teknik Gerekçe ve Kanıtlar |
| :--- | :---: | :--- |
| **1. PRIVATE REPOSITORY** | **GO** | - `B1` (`X-Demo-Principal` kimlik doğrulama atlatması, self-register tenant takeover, varsayılan demo seed) ve `B2` (Trusted Egress Broker URL/başlık sızıntısı ve `now` override) açıkları kapatılmış ve 86 PHP API iddiası + 84 TypeScript testi `0 FAIL` ile doğrulanmıştır.<br>- `.gitignore` ile `.tools/`, `node_modules/`, `*.sqlite*`, `.env*` ve üretilen raporlar dışlanmıştır. |
| **2. PUBLIC ALPHA RELEASE (`v0.1.0-alpha.4`)** | **GO** | - Tüm kritik uygulama katmanı güvenlik kontrolleri (`SEC-001..014`, `EGR-001..006`, `B1`, `B2`, `S9-01..17`) gerçek çalışma zamanı regresyon testleriyle doğrulanmıştır (`0 FAIL`).<br>- [`README.md`](README.md), [`README.tr.md`](README.tr.md), [`PROJECT_STATUS.md`](PROJECT_STATUS.md), [`docs/ROADMAP.md`](docs/ROADMAP.md) ve [`CHANGELOG.md`](CHANGELOG.md) hangi bileşenlerin tam doğrulandığını (`IMPLEMENTED & TESTED`), hangilerinin özel PHP/SQLite ve Node HTTP prototipi olduğunu (`PROTOTYPE`) ve hangilerinin bu Windows ortamında doğrulanmadığını (`5 SKIP — Docker/Linux netns`) şeffaf biçimde belirtmektedir.<br>- Aktif kaynak kodda hiçbir sır, müşteri kodu veya kişisel isim bulunmamaktadır. |
| **3. PRODUCTION DEPLOYMENT** | **NO-GO** | 1. **Doğrulanmamış Konteyner ve Ağ İzolasyonu (`5 SKIP`):** [`npm run verify:release-gate`](docs/audit-evidence/final-release-audit/12-verify-release-gate-real-binaries.log) komutu `WKR-001..005` ve `EGR-LINUX-NETNS-RUNTIME` kapıları Linux + Docker Engine üzerinde doğrulanmadığı için üretimi bloklamaktadır.<br>2. **Host Alt Süreci ile Tarama:** `apps/api` içindeki `ExecuteAuthorizedScanJob` Semgrep/Trivy taramasını henüz izole Docker konteyneri içinde değil, host üzerinde `proc_open` ile çalıştırmaktadır.<br>3. **Veritabanı ve Kuyruk Altyapısı:** Çok kiracılı üretim ortamı için SQLite ve senkron HTTP yürütmesi yerine PostgreSQL RLS ve gerçek asenkron kuyruk işçileri gereklidir. |

### 5.2 GitHub'a Yayımlamak İçin Gereken Son Komutlar (Push Yapılmamıştır)

#### Seçenek A — Mevcut Dal Geçmişini Koruyarak Yayımlama
```powershell
# 1. Çalışma ağacındaki tüm Sprint 9 güvenlik, dokümantasyon ve arşiv değişikliklerini sahnele
git add -A

# 2. Sahnelenen dosyaları kontrol et (.tools, node_modules, .sqlite olmadığından emin ol)
git status --short

# 3. Sprint 9 ve Final Public Alpha Release Audit commit'ini oluştur
git commit -m "sec(sprint9): close B1/B2 auth & broker vulnerabilities, align docs, and add final release audit"

# 4. GitHub uzak deposunu ekle ve gönder (kullanıcı onayıyla)
git remote add origin https://github.com/HegoWeb/HegoSentinel.git
git push -u origin main
```

#### Seçenek B — Git Geçmişindeki Eski Commit'i (`26ec85b` İçindeki Kişisel İsmi) Tamamen Temizleyerek Tek Temiz Commit İle Yayımlama (Önerilen Public Alpha Yöntemi)
```powershell
# 1. Mevcut doğrulanmış çalışma ağacından geçmişsiz (orphan) temiz bir dal oluştur
git checkout --orphan public-alpha-main
git add -A
git commit -m "chore(release): HegoSentinel v0.1.0-alpha.4 public alpha security platform"

# 2. Ana dalı bu temiz commit ile güncelle
git branch -M public-alpha-main main

# 3. GitHub uzak deposunu ekle ve gönder (kullanıcı onayıyla)
git remote add origin https://github.com/HegoWeb/HegoSentinel.git
git push -u origin main
```

