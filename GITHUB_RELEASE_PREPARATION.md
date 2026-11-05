# HEGOSENTINEL — GITHUB PUBLIC ALPHA RELEASE PREPARATION (`v0.1.0-alpha.4`)

> **Durum:** `Experimental / Alpha / Not Production Ready` (`v0.1.0-alpha.4`)  
> **Tarih:** `2026-11-05` · **Kanonik Yerel Dal:** `main @ 1cda48d` + Sprint 9 Güvenlik ve Yayın Hazırlığı  
> **Temel Denetim Raporu:** [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) · **Güvenlik Yeniden Denetimi:** [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md)

---

## 1. Son Güvenlik İncelemesi ve Yerel Yedekleme Doğrulaması

| Kontrol Kalemi | Durum | Doğrulama Kanıtı ve Açıklama |
| :--- | :---: | :--- |
| **1. `B1` (`X-Demo-Principal` & RBAC/Tenant) Regresyon Testi** | **PASS (`50/50`)** | [`apps/api/tests/run-security-regression-tests.php`](apps/api/tests/run-security-regression-tests.php) (`production`, `testing` ve `local` modlarında `50 passed, 0 failed`). Kanıt: [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log). |
| **2. `B2` (Trusted Egress Broker URL/Başlık Maskeleme) Regresyon Testi** | **PASS (`12/12`)** | [`tests/security/broker-b2-regression.test.ts`](tests/security/broker-b2-regression.test.ts) (`12 passed, 0 failed`). İlk denetim kaydından önce `token`, `password`, `secret`, `code`, `api_key`, `userinfo` ve `#fragment` maskelenir. Kanıt: [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log). |
| **3. GitHub'a Gidecek Tüm Dosyaların (206 Dosya) Denetimi** | **PASS (`0` Sızıntı)** | [`15-github-publish-file-list.txt`](docs/audit-evidence/final-release-audit/15-github-publish-file-list.txt) içindeki **206** dosyanın tamamı taranmıştır: `.tools/`, `node_modules/`, `*.sqlite*`, `.env`, `*.zip`, `*.bundle` veya gerçek müşteri raporu bulunmamaktadır (`Forbidden files: 0`). En büyük kaynak dosyası `SecurityPlatformService.php` (`115 KB`) olup depoda hiçbir büyük ikili (binary) dosya yer almamaktadır. |
| **4. Trivy Secret Scanner & Gitleaks Kontrolü** | **PASS (Trivy) / CI Hazır (Gitleaks)** | Yerel Windows ortamında gerçek `trivy.exe fs --scanners secret` (`v0.76.1`) çalıştırılmış ve **0 sır (secret)** tespit edilmiştir ([`18-trivy-secret-scan.log`](docs/audit-evidence/final-release-audit/18-trivy-secret-scan.log)). Windows makinede `gitleaks` kurulu olmadığından Gitleaks taraması [`.github/workflows/ci.yml`](.github/workflows/ci.yml) içindeki `secret-and-dependency-security` işine (`ubuntu-24.04`) eklenmiştir. |
| **5. Kişisel Bilgi (PII) ve Yerel Kullanıcı Yolu Temizliği** | **PASS (`0` Eşleşme)** | GitHub'a gidecek 206 dosyanın tamamında kişisel isimler ve yerel Windows kullanıcı yolu (`<WORKSPACE_ROOT>` olarak maskelendi) taranmış ve **0 eşleşme** doğrulanmıştır. |
| **6. Eski Git Geçmişinin Yerel Yedeği ve Public Depo Koruması** | **PASS** | Mevcut Git geçmişi (`main @ 1cda48d`, `26ec85b`, `6e683d0`) kullanıcı onayı olmadan **silinmemiş ve yeniden yazılmamıştır**. Tam Git geçmişi yerel olarak `reports/hegosentinel-history-backup-2026-11-05.bundle` (`.gitignore` ile dışlanan yerel yedek) dosyasına yedeklenmiştir. `26ec85b` commit farkındaki kişisel ismin GitHub'a taşınmaması için Bölüm 5.4'te mevcut `main` dalını bozmayan temiz yayın dalı (`release/public-alpha-v0.1.0-alpha.4`) prosedürü hazırlanmıştır. |

---

## 2. Private GitHub Hazırlığı ve Mimari Şeffaflık Kontrolü

1. **`Experimental / Alpha / Not Production Ready` Tanımı:**
   - [README.md](README.md), [README.tr.md](README.tr.md), [CONTRIBUTING.md](CONTRIBUTING.md) ve [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) dosyalarının başında proje açıkça **`Experimental / Alpha / Not Production Ready`** olarak tanımlanmıştır.
2. **Gerçek Mimari vs. Planlanan Çerçeveler:**
   - `apps/api`: Gerçek bir Laravel 11 / PostgreSQL / Redis / Horizon kurulumu **değildir**; sıfır bağımlılıklı özel **PHP 8.2+ / SQLite PDO** servis katmanıdır (`PROTOTYPE IMPLEMENTED & TESTED`).
   - `apps/web`: Gerçek bir Next.js derlemesi **değildir**; bağımlılıksız özel **Node.js `node:http` SSR + gömülü HTML/JS** tek sayfa uygulamasıdır (`PROTOTYPE IMPLEMENTED & TESTED`).
3. **Gerçek Tarama vs. Sentetik Demo Ayrımı:**
   - Varsayılan/production modunda (`HEGOSENTINEL_DEMO_MODE` tanımlı değilken) API ve Web arayüzü **boş ve kilitli** başlar.
   - Operatör yalnızca yerel ortamda `HEGOSENTINEL_DEMO_MODE=1` verdiğinde örnek veriler yüklenir ve her kayıtta `real_scan` ile `demo_seed` / `is_demo` rozetleri açıkça ayrılır.
4. **Açık Kaynak Lisans Doğrulaması:**
   - Proje lisansı: **MIT** ([LICENSE](LICENSE)).
   - Kök çalışma zamanı bağımlılığı: **Sıfır** (`devDependencies` altında yalnızca `typescript@^5.9.3` — Apache-2.0).
   - İsteğe bağlı harici tarayıcılar: Semgrep CE (`LGPL-2.1`) ve Trivy (`Apache-2.0`) depoya gömülmemiştir; ayrı süreç olarak çağrılır.

---

## 3. GitHub Actions (`ubuntu-24.04`) Doğrulama Matrisi ve Gerçek CI Sonuçları (`Run #4 [42076698840]`)

Private GitHub deposu (`https://github.com/HegoWeb/HegoSentinel.git`, `private: true`) üzerinde `ubuntu-24.04` çalışma ortamında **Run #4 (`42076698840`)** koşturulmuş ve **7 işin tamamı (`6/6` CI işi + Node `22.16.0` & `24.x` matrisi) `SUCCESS` (`0 FAIL`, `0 SKIP`)** ile tamamlanmıştır ([`20-github-actions-ubuntu2404-run-42076698840.log`](docs/audit-evidence/final-release-audit/20-github-actions-ubuntu2404-run-42076698840.log)):

| CI İşi (`ubuntu-24.04`) | Kapsadığı Kontroller | Yerel (Windows) Durumu | GitHub Actions (`ubuntu-24.04`) Gerçek Sonucu (`Run #4 [42076698840]`) |
| :--- | :--- | :---: | :---: |
| **1. `unit-integration-security-e2e`** | `npm run lint`, `npm run typecheck`, `npm run docs:links`, **`npm run test:api`** (36 PHP modül + 50 Sprint 9 B1 regresyon), `test:unit`, `test:integration`, `test:security` (B2 dahil), `test:e2e`, `demo`, `verify:gates` | **PASS** (`86/86` PHP, `79/79` TS + `5 SKIP`) | **PASS (`SUCCESS`)** — Job `127418688244` (Node `22.16.0`) & Job `127418688575` (Node `24.x`) |
| **2. `docker-worker-containment`** | `bash ./scripts/linux-docker-verify.sh` — Gerçek Docker imajı oluşturma ve `WKR-001..005` (`--user=65532:65532`, `--read-only`, `--network=none`, `--cap-drop=ALL`, CPU/RAM/PID sınırları) konteyner testleri | **SKIP (Not Verified)** *(Windows makinede Docker yok)* | **PASS (`SUCCESS`)** — Job `127418688712`: `WKR-001` (`uid=65532 capEff=0 noNewPrivs=1 netErr=ENETUNREACH`), `WKR-002` (`dockerSock=absent metadataErr=ENETUNREACH`), `WKR-003` (`EROFS`), `WKR-004` (`EACCES`), `WKR-005` (`pidsMax=64 memMax=536870912`) |
| **3. `real-scanners-semgrep-trivy`** | `bash ./scripts/linux-scanner-verify.sh` — Sabitlenmiş Semgrep CE `1.183.0` ve Trivy `0.76.1` ile Laravel, Next.js ve Node.js sentetik hedeflerinin gerçek ikili taraması | **PASS** *(Windows üzerinde Semgrep `1.183.0` -> 6 bulgu, Trivy `0.76.1` -> 61 bulgu)* | **PASS (`SUCCESS`)** — Job `127418688754`: `laravel` (`2` Semgrep, `21` Trivy), `nextjs` (`2` Semgrep, `36` Trivy), `nodejs` (`2` Semgrep, `4` Trivy) |
| **4. `real-egress-broker-isolation`** | `bash ./scripts/linux-netns-egress-verify.sh` — Docker `--internal` ağ izolasyonu ve Trusted Egress Broker uçtan uca HTTP doğrulaması (`EGR-LINUX-NETNS-RUNTIME` & `EGR-001..006`) | **PASS (In-Process HTTP) / SKIP (Linux netns)** | **PASS (`SUCCESS`)** — Job `127418688614`: `direct_internet_bypass_blocked=true`, `cloud_metadata_bypass_blocked=true`, `broker_e2e_http_allow_verified=true`, `broker_e2e_http_ssrf_drop_verified=true`, `broker_audit_chain_valid=true` |
| **5. `secret-and-dependency-security`** | `npm audit --audit-level=high`, `gitleaks` (`v8.21.2`) ve `trivy fs --scanners secret` (`v0.76.1`) ile tam depo sır ve bağımlılık taraması | **PASS** *(Trivy secret scan: `0` sır; `npm audit`: `0` zafiyet)* | **PASS (`SUCCESS`)** — Job `127418688567`: `npm audit: 0 vulnerabilities`, `gitleaks: no leaks found`, `trivy secret: 0 findings` |
| **6. `production-release-gate`** | Tüm CI artefaktlarını birleştirerek `npm run verify:release-gate -- --enforce-production-release` (`0 FAIL` ve `0 SKIP` zorunluluğu) | **BLOCKED** *(5 adet yerel Docker/Linux `SKIP` nedeniyle)* | **PASS (`SUCCESS`)** — Job `127419233356`: **`[RELEASE GATE: READY] All 32 security gates achieved PASS (0 FAIL, 0 SKIP)`** |

---

## 4. Public Alpha Yayın Kriterleri Kontrol Listesi

| # | Kriter | Durum | Kanıt |
| :-: | :--- | :---: | :--- |
| **1** | Kritik güvenlik açıkları (`B1`, `B2`, `S9-01..17`) kapalı olmalı | **EVET (`PASS`)** | [`04-php-api-tests.log`](docs/audit-evidence/final-release-audit/04-php-api-tests.log), [`07-security-tests.log`](docs/audit-evidence/final-release-audit/07-security-tests.log) |
| **2** | Gizli bilgiler ve kişisel veriler depodan ve yayımlanacak Git geçmişinden temizlenmiş olmalı | **EVET (`PASS`)** | 207 dosyada `0` PII / `0` sır ([`18-trivy-secret-scan.log`](docs/audit-evidence/final-release-audit/18-trivy-secret-scan.log), Gitleaks `no leaks found`) + tek commit'li temiz `public-alpha` dalı |
| **3** | Açık kaynak lisansları doğrulanmalı | **EVET (`PASS`)** | MIT Lisansı ([LICENSE](LICENSE)), sıfır çalışma zamanı npm paketi |
| **4** | README gerçek özellikleri anlatmalı (`Experimental / Alpha / Not Production Ready`) | **EVET (`PASS`)** | [README.md](README.md), [README.tr.md](README.tr.md), [PROJECT_STATUS.md](PROJECT_STATUS.md) |
| **5** | Kullanıcılar gerçek tarama (`real_scan`) ile sentetik demoyu (`demo_seed` / `HEGOSENTINEL_DEMO_MODE=1`) ayırt edebilmeli | **EVET (`PASS`)** | Varsayılan kapalı demo modu + açık veri kaynağı etiketleri |
| **6** | Canlı uzak tarama (`restricted-remote`) kapalı kalmalı | **EVET (`PASS`)** | `SEC-005` ve `ExecuteAuthorizedScanJob` tarafından **fail-closed** engellenir |
| **7** | CI sonuçları dürüstçe raporlanmalı (CI üzerinde `PASS` olmayan hiçbir kontrol tamamlanmış işaretlenmemeli) | **EVET (`PASS`)** | GitHub Actions `ubuntu-24.04` **Run #4 (`42076698840`)** üzerinde **32/32 güvenlik kapısı `PASS` (`0 FAIL, 0 SKIP`)** ([`20-github-actions-ubuntu2404-run-42076698840.log`](docs/audit-evidence/final-release-audit/20-github-actions-ubuntu2404-run-42076698840.log)) |
| **8** | Kalan güvenlik riskleri ve mimari sınırlar açıkça belgelenmeli | **EVET (`PASS`)** | [README.md#known-limitations](README.md#known-limitations) ve [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) |

---

## 5. Son Karar ve GitHub Yayın Paketi

### 5.1 Karar Özeti

1. **PRIVATE GITHUB REPOSITORY (`https://github.com/HegoWeb/HegoSentinel`):** **DOĞRULANDI (`PASS`)** — Temiz tek-commit geçmişiyle gönderilmiş ve GitHub Actions `ubuntu-24.04` **Run #4 (`42076698840`)** üzerinde tüm 6 CI işi (`32/32` güvenlik kapısı, `WKR-001..005`, `EGR-LINUX-NETNS-RUNTIME`, Semgrep `1.183.0`, Trivy `0.76.1`, PHP API `86/86`, Gitleaks + Trivy Secret) `SUCCESS` ile geçmiştir.
2. **PUBLIC ALPHA RELEASE (`v0.1.0-alpha.4`):** **GO (Hazır — Depoyu Public Yapma, Tag ve Release Açma Kararı Kullanıcı Onayına Bırakılmıştır)** — Tüm güvenlik, CI, lisans, dokümantasyon ve sır/PII temizliği kriterleri eksiksiz karşılanmıştır.
3. **PRODUCTION DEPLOYMENT:** **NO-GO** — `WKR-001..005` ve `EGR-LINUX-NETNS-RUNTIME` konteyner/netns kapıları Linux CI üzerinde doğrulanmış olsa da, `apps/api` (`ExecuteAuthorizedScanJob`) henüz taramaları konteyner yerine host alt süreci (`proc_open`) ile çalıştırdığından ve tam Laravel/PostgreSQL/Redis/Horizon yerine özel PHP/SQLite ve Node HTTP prototipi kullanıldığından çok kiracılı üretim ortamında kullanılmamalıdır (`restricted-remote` kapalı kalmalıdır).

---

### 5.2 GitHub Repository "About" Açıklaması ve Topics

- **Repository:** `HegoSentinel` (`https://github.com/HegoWeb/HegoSentinel`)
- **Version:** `v0.1.0-alpha.4`
- **Description:**
  > `Open-source, authorization-first security assessment and remediation platform.`
- **Topics:**
  `cybersecurity`, `application-security`, `sast`, `security-scanner`, `semgrep`, `trivy`, `devsecops`, `typescript`, `open-source`

---

### 5.3 `v0.1.0-alpha.4` GitHub Release Taslağı (Pre-release)

- **Tag:** `v0.1.0-alpha.4`
- **Release Title:** `HegoSentinel v0.1.0-alpha.4 — First Public Alpha`
- **Release Type:** `Pre-release` (`prerelease: true`)

```markdown
# HegoSentinel v0.1.0-alpha.4 — First Public Alpha

> **⚠️ WARNING: Experimental / Alpha / Not Production Ready**
> HegoSentinel `v0.1.0-alpha.4` is an **experimental public alpha release** designed for local evaluation, offline fixture verification, and authorized local source/dependency auditing.
> - **Do NOT deploy this release as a multi-tenant or internet-exposed production service.**
> - **Live remote network scanning (`restricted-remote`) is strictly DISABLED (`fail-closed` via `SEC-005`).**
> - **Architectural Transparency:** In this alpha release, `apps/api` is a lightweight zero-dependency **PHP 8.2+ & SQLite PDO** prototype (not a full Laravel 11 / PostgreSQL / Redis / Horizon deployment), and `apps/web` is a zero-dependency **Node.js `node:http` SSR + vanilla JS** single-page application prototype (not a full Next.js App Router build).

---

## 1. Real Implemented & Verified Features (`v0.1.0-alpha.4`)

- **Authorization-First Policy & SSRF Containment (`packages/policy-engine`):**
  - Enforces explicit `ScopeAuthorizationGrant` records requiring a `written_permission_ref` distinct from `domain_control_proof` (`SEC-001`).
  - Rejects wildcard hostnames, expired grants, out-of-window scans, and 21 reserved IPv4/IPv6/loopback/link-local/CGNAT/cloud-metadata (`169.254.169.254`, `fd00:ec2::254`, `::ffff:169.254.169.254`) ranges (`SEC-002`).
  - Blocks out-of-scope redirects and HTTPS→HTTP protocol downgrades (`SEC-003`) and verifies connected socket peers against pinned DNS resolutions (`SEC-004`).
- **Evidence-to-Fix Pipeline & Deterministic Re-Test (`packages/scanner-core`, `report-engine`, `recheck-engine`):**
  - Evaluates passive web security observers (`WEB-HEADER-001`, `WEB-COOKIE-001`, `WEB-TLS-001`, `WEB-REDIRECT-001`) against deterministic offline fixtures (`HSR-04`).
  - Discards cookie values at parse time and applies a 9-pass secret redaction engine across JWTs, API keys, PEM keys, DB URIs, `APP_KEY`, `NEXTAUTH_SECRET`, `Set-Cookie`, and `Authorization` headers (`SEC-007`).
  - Exports schema-validated **JSON**, **Markdown**, **self-contained dark HTML**, and **OASIS SARIF 2.1.0** reports.
  - Verifies remediations (`verified_fixed` vs `still_reproducible` vs `not_comparable`) using strict per-asset, per-cookie fingerprint, rulepack, and scope-version equivalence (`SEC-009`, `SEC-010`).
- **Real Semgrep CE (`1.183.0`) & Trivy (`0.76.1`) Subprocess Adapters (`integrations/semgrep`, `integrations/trivy`):**
  - Executes with `shell: false`, strict binary allowlists, and `realpathSync` + `lstatSync` symlink/junction and post-scan TOCTOU escape protection (`SEC-006`, `WKR-004`).
  - Includes synthetic Laravel, Next.js, and Node.js targets (`examples/synthetic-targets/`) and local Semgrep rulepacks.
- **Out-of-Worker Trusted Egress Broker (`apps/egress-broker`):**
  - Enforces deny-by-default `PerRunNetworkPolicy` (`EGR-001`), short-lived HMAC-signed `SignedRemoteExecutionGrant` (`TTL <= 300s`, single-use nonce replay registry — `EGR-002`), outbound header allowlisting (`accept-language`, `x-custom-trace`), redirect blocking (`EGR-004`), and pre-log URL/header secret masking with a SHA-256 hash-chained audit ledger (`EGR-006`, Sprint 9 `B2`).
- **Local Platform Prototypes (`apps/api` & `apps/web`):**
  - `apps/api`: Custom PHP 8.2+ & SQLite REST API implementing Bearer session authentication, per-account login brute-force throttling (`429`), server-side tenant/project/RBAC isolation, workspace-confined `repository_path` validation, and project-wide Emergency Stop cooldowns (Sprint 9 `B1`).
  - `apps/web`: Custom Node.js `node:http` SSR UI (TR/EN) wired to `/api/v1/*`. Starts empty and locked by default; synthetic demo data is loaded only when `HEGOSENTINEL_DEMO_MODE=1` is explicitly set in non-production environments.

---

## 2. Verification & Test Results

### GitHub Actions `ubuntu-24.04` CI Verification
- **Unit, Integration, Security Matrix (`SEC-001..014`) & E2E Tests (Node `22.16.0` & `24.x`):** `PASS` (`84` TS tests + `86` PHP API assertions, `0 FAIL`)
- **Sprint 9 `B1` (`X-Demo-Principal` Auth Bypass & RBAC/Tenant) Regression Suite:** `50/50 PASS` (`0 FAIL`)
- **Sprint 9 `B2` (Trusted Egress Broker Pre-Log Secret Masking) Regression Suite:** `12/12 PASS` (`0 FAIL`)
- **Real Docker Worker Containment (`WKR-001..005`):** `PASS` (`uid=65532:65532`, `CapEff=0`, `NoNewPrivs=1`, `--network=none` internet & metadata blocked, `--read-only` rootfs & target mount `EROFS`, `pids.max=64`, `memory.max=536870912`)
- **Real Linux Isolated Network & E2E Trusted Egress Broker (`EGR-LINUX-NETNS-RUNTIME`):** `PASS` (Docker `--internal` bridge blocks direct internet/metadata bypass; E2E HTTP broker allow/SSRF-drop/hash-chain verified)
- **Real Pinned Scanners (`Semgrep CE 1.183.0` & `Trivy 0.76.1`):** `PASS` (`6` SAST findings + `61` SCA/misconfiguration findings across synthetic Laravel, Next.js, and Node.js targets)
- **Secret & Dependency Security (`Gitleaks v8.21.2` + `Trivy Secret` + `npm audit`):** `PASS` (`0` leaked secrets, `0` dependency vulnerabilities)
- **Unified Security Gates (`npm run verify:gates`):** **`32/32 PASS` (`0 FAIL`, `0 SKIP`)** on `ubuntu-24.04` (`27 PASS, 0 FAIL, 5 SKIP` on Windows hosts without Docker Engine)

---

## 3. Quick Start & Installation

### Requirements
- **Node.js** `>= 22.6.0` (tested on `22.16.0` and `24.x`)
- **PHP** `>= 8.2` with `pdo_sqlite`, `openssl`, and `json` extensions (for `apps/api`)
- *(Optional)* **Semgrep CE** `1.183.0` and **Trivy** `0.76.1` for real local source/dependency scans

```bash
# 1. Install TypeScript compiler (zero runtime npm dependencies)
npm ci --ignore-scripts

# 2. Run static policy lint, TypeScript compiler check, and test suites
npm run lint
npm run typecheck
npm run test:api
npm test

# 3. Run the offline synthetic Evidence-to-Fix demo (zero external network calls)
npm run demo
```

---

## 4. Known Limitations & Security Warnings

1. **Not Production Ready:** Do not expose `apps/api` or `apps/web` to untrusted networks or use them for multi-tenant production workloads.
2. **Prototype Web & API Stack:** `apps/api` uses a custom PHP/SQLite service layer (`artisan horizon` and `queue:work` are CLI stubs, and `ExecuteAuthorizedScanJob` runs scans via synchronous `proc_open` host subprocesses rather than Redis/Horizon + ephemeral Docker containers). `apps/web` uses a custom Node `node:http` server (`src/server.ts`) rather than Next.js App Router.
3. **Simulated External Notifications:** `POST /api/v1/notifications` enforces all `SEC-013` policy and redaction checks and records dispatch state in SQLite, but does not send live SMTP emails or external HTTP webhooks in `v0.1.0-alpha.4`.
4. **`restricted-remote` Disabled:** Live outbound HTTP/TLS scanning against remote targets remains unconditionally blocked (`SEC-005`).
```

---

### 5.4 Kullanıcı Onayıyla Çalıştırılacak Adım Adım Git / GitHub Komutları

> **Önemli:** Yerel `main` dalınız ve `reports/hegosentinel-history-backup-2026-11-05.bundle` yedeğiniz olduğu gibi korunmaktadır. Aşağıdaki komutlar yerel `main` geçmişini silmeden, önceki commit'teki kişisel bilgiyi içermeyen **temiz ve tek commit'li** bir `public-alpha` dalı hazırlar ve önce **Private** depoya gönderir:

```powershell
# ADIM 1 — Yerel main dalına dokunmadan temiz geçmişli (orphan) yayın dalı oluştur
git checkout --orphan public-alpha
git add -A
git status --short   # 206 dosyanın sahnelendiğini ve .tools / .sqlite olmadığını doğrula
git commit -m "chore(release): HegoSentinel v0.1.0-alpha.4 experimental public alpha"

# ADIM 2 — Private GitHub deposunu uzak adres olarak ekle ve gönder (KULLANICI ONAYIYLA)
git remote add origin https://github.com/HegoWeb/HegoSentinel.git
git push -u origin public-alpha:main

# ADIM 3 — GitHub Actions (ubuntu-24.04) üzerindeki 6 işin tamamlanmasını izle
# (WKR-001..005 Docker, EGR-LINUX-NETNS-RUNTIME, Semgrep/Trivy, PHP API, Gitleaks/Trivy Secret)

# ADIM 4 — CI doğrulandıktan sonra v0.1.0-alpha.4 etiketini oluştur ve gönder (KULLANICI ONAYIYLA)
git tag -a v0.1.0-alpha.4 -m "HegoSentinel v0.1.0-alpha.4 (Experimental Public Alpha — Not Production Ready)"
git push origin v0.1.0-alpha.4

# (İsteğe bağlı) Yerel inceleme için her zaman eski main dalına geri dönebilirsiniz:
# git checkout main
```

