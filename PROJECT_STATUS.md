# HegoSentinel — PROJECT_STATUS

> **Sürüm:** `0.1.0-alpha.4` + Sprint 7/8/9 (yayımlanmamış, etiket yok) · **Kanonik kaynak:** Git `main@1cda48d` + Sprint 9 çalışma ağacı değişiklikleri (**commit edilmedi**) · **Güncelleme:** 2026-11-05
> **Ortam:** Windows 10, Node v24.19.0, PHP 8.2.12 (`pdo_sqlite` var; `pdo_pgsql`/`redis` **yok**), **Docker yok**, `git remote` yok.
> Karar belgesi: [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md) · Sprint 9 bulguları: [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md) · Kanıtlar: [docs/audit-evidence/](docs/audit-evidence/) · Tarihsel: [docs/archive/](docs/archive/)

**Etiketler:** **IMPLEMENTED** kod var · **TESTED** bu makinede otomatik testle geçti · **SIMULATED** süreç içi/loopback model, gerçek OS/ağ zorlaması kanıtlanmadı · **BLOCKED** kasıtlı kapalı veya ortam eksik · **PLANNED** yok ya da yalnızca iskelet.

## 1. Test sonuçları (Sprint 9 sonu, gerçek çalıştırma)

| Komut | Sonuç | Kanıt |
|---|---|---|
| `npm run lint` | **PASS** (exit 0) | [T01](docs/audit-evidence/sprint9/T01-lint.log) |
| `npm run typecheck` (`tsc` kök + `apps/web` + modül grafiği) | **PASS** (exit 0) | [T02](docs/audit-evidence/sprint9/T02-typecheck.log) |
| `npm run docs:links` | **PASS** — tüm göreli Markdown bağlantıları çözülüyor | [T03](docs/audit-evidence/sprint9/T03-markdown-links.log) |
| **`npm test`** (TypeScript) | **84 test · 78 PASS · 0 FAIL · 6 SKIP** (sandbox içi) | [T04](docs/audit-evidence/sprint9/T04-test-full.log) |
| `npm run test:api` (PHP) | **86 test · 86 PASS · 0 FAIL** (36 modül testi + **50 güvenlik regresyonu**) | [T05](docs/audit-evidence/sprint9/T05-test-api-php.log) |
| Gerçek Semgrep/Trivy testleri (sandbox dışı) | **6/6 PASS** — Semgrep CE `1.183.0`, Trivy `0.76.1` | [U01](docs/audit-evidence/sprint9/U01-real-semgrep-trivy.log), [U02](docs/audit-evidence/sprint9/U02-scanner-versions.log) |
| `npm run demo` | **PASS** (exit 0) | [T06](docs/audit-evidence/sprint9/T06-demo.log) |
| `npm run verify:gates` (sandbox içi) | 26 PASS · 6 SKIP · **0 FAIL** | [T07](docs/audit-evidence/sprint9/T07-verify-gates.log) |
| `npm run verify:gates` (gerçek ikililer erişilebilir) | **27 PASS · 5 SKIP · 0 FAIL** | [U03](docs/audit-evidence/sprint9/U03-verify-gates-real-binaries.log) |
| `npm run verify:release-gate` | **BLOCKED** (5 SKIP — NOT VERIFIED) | [U04](docs/audit-evidence/sprint9/U04-release-gate-real-binaries.log) |

**Toplam:** 84 + 86 = **170 test; 164 PASS (sandbox içi) → Semgrep gerçek ikili testi sandbox dışında geçtiği için 165 PASS; 0 FAIL; 5 gerçek SKIP.**

> [!NOTE]
> Sandbox, Semgrep'in `socketpair` çağrısını engellediği için sandbox içi koşuda Semgrep testi "kurulu değil" diye SKIP görünür (6 SKIP); aynı test sandbox dışında **PASS** (5 gerçek SKIP). Kalan 5 SKIP gerçektir: **Docker Engine yok** (WKR-001/002/003/005 ve EGR-LINUX-NETNS-RUNTIME). **Hiçbir SKIP PASS sayılmadı.** Exit kodları: [`docs/audit-evidence/sprint9/_exit_codes.tsv`](docs/audit-evidence/sprint9/_exit_codes.tsv).

## 2. Modül durumu

| Modül | Durum | Kanıt / kapsam | Eksik / risk |
|---|---|---|---|
| **TS güvenlik çekirdeği** (`policy-engine`, `findings-schema`, `recheck-engine`, `report-engine`, `scanner-core`) | **IMPLEMENTED · TESTED** | SEC-001..014 gate'lerinin 14'ü PASS (host-deterministik). | Host-deterministik testler. |
| **Semgrep / Trivy adaptörleri** | **IMPLEMENTED · TESTED** | CODE-001/DEP-001 adapter + ikili gate'leri PASS; `shell:false`, DB tazeliği, sürüm kayması. Sürümler: Semgrep CE `1.183.0`, Trivy `0.76.1` (Windows 10, Node 24.19.0). | **Linux CI'da doğrulanmadı.** Binary'ler `PATH` yerine `.tools/` altından çözülür. |
| **Worker** (`apps/worker`) | **IMPLEMENTED · TESTED (host)** · **BLOCKED (konteyner)** | `docker run` argüman üreticisi, mount/env reddi, `analyzeDockerRunOutcome`, WKR-004 symlink, WKR-006 yaşam döngüsü PASS. | WKR-001/002/003/005 canlı konteyner testleri **SKIP**. |
| **Trusted Egress Broker** | **IMPLEMENTED · TESTED (süreç/loopback)** · **SIMULATED (ağ zorlaması)** | EGR-001..006 PASS. **Sprint 9:** başlık izin listesi, audit maskeleme (ilk kayıttan önce), broker saati (worker `now` veremez), yönlendirme sözleşmesi, süre/boyut tavanı — 12 regresyon testi. | Gerçek netns doğrulaması SKIP; worker'ın **tek çıkış yolu** olduğu kanıtlanmadı; API'ye **bağlı değil**; nonce/bütçe/audit belleğte; gerçek üst akış (upstream) taşıması yok. |
| **`restricted-remote`** | **BLOCKED (doğru)** | Fail-closed. | Gerçek izolasyon kanıtlanana kadar kapalı kalmalı. |
| **Platform API** (`apps/api`) | **IMPLEMENTED (prototip) · TESTED** | 14 modül; **Sprint 9: kimlik doğrulama atlatması, kayıt ile kiracı ele geçirme, varsayılan parola, brute force, BOLA bilgi sızıntısı, path traversal, emergency stop atlatma ve RBAC açıkları kapatıldı** (PoC 11/11 → 0/11; 50 regresyon testi). | **Laravel değildir** (framework kurulu değil, özel PHP katmanı); varsayılan DB **SQLite**; **PostgreSQL/Redis/Horizon/Sanctum PLANNED**; e-posta **SIMULATED**; taramalar worker/Docker/broker üzerinden değil **host `node` alt süreciyle**; alan adı sahipliği doğrulanmıyor; MFA zorlanmıyor; parola sıfırlama tamamlanmadı. |
| **Web arayüzü** (`apps/web`) | **IMPLEMENTED (prototip) · TESTED** | Node HTTP + gömülü HTML/JS, 9 ekran TR/EN; oturum yalnızca Bearer; production'da boş ve kilitli açılır, demo yalnızca `HEGOSENTINEL_DEMO_MODE=1`; proxy sertleştirildi. | **Next.js değildir** (`next`/`react` kurulu değil, `src/app/*.tsx` kullanılmayan iskelet); otomatik DOM-XSS testi yok (statik inceleme). |
| **Rapor dışa aktarma / Re-Test / Audit zinciri** | **IMPLEMENTED · TESTED** | JSON/MD/HTML/SARIF; `verified_fixed` yalnızca aynı varlık+grant+kapsam+pozitif kanıt; görev yalnızca doğrulanmış Re-Test ile kapanır (Sprint 9). | Broker/API audit zinciri anahtarsız SHA-256 (veritabanı yazma yetkisi zinciri yeniden hesaplayabilir). |
| **CI** (`.github/workflows/ci.yml`) | **IMPLEMENTED · UNVERIFIED** | `ubuntu-24.04`, 5 iş, sabit sürümler. | **Hiç çalışmadı.** |
| **`docker-compose.yml`, Linux betikleri** | **IMPLEMENTED · UNVERIFIED** | Dosyalar var. | Hiç çalıştırılmadı (Docker yok). |

## 3. Güvenlik durumu (Sprint 9)

* **Kapatılan P0/P1:** 17 bulgu — ayrıntı [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md).
* **Açık (kabul edilmiş/belgelenmiş) riskler:** alan adı sahipliği ve bildirim alan adı doğrulaması yok (R-01/R-02), audit zinciri eşzamanlılık/anahtar sınırı (R-03), parola sıfırlama/MFA eksik (R-05), host üzerinde tarama (R-08), Docker/netns doğrulanmadı (R-09).
* **Depo hijyeni:** gerçek sır bulunamadı (desen tabanlı; `gitleaks` çalıştırılmadı); `.gitignore` sıkılaştırıldı; 15 dahili belge `docs/archive/` ve `docs/security/` altına **silinmeden** taşındı; lisans MIT'e hizalandı; demo kimlik bilgileri ve kişisel ad kaynaktan temizlendi — [SECRET-SCAN-PRECOMMIT.md](docs/audit-evidence/sprint9/SECRET-SCAN-PRECOMMIT.md).

## 4. Gate özeti (gerçek ikililer erişilebilirken: 27 PASS / 5 SKIP / 0 FAIL)

`PASS` = **host-deterministik** test (SEC/EGR) ya da **Windows host'ta** çalışan gerçek ikili (CODE-001/DEP-001). **Gerçek Linux Docker/netns kanıtı olan PASS yoktur.**

| Gate grubu | Katman | Sonuç |
|---|---|---|
| WKR-001-MANIFEST, WKR-004-SYMLINK, WKR-006-LIFECYCLE | Host | **3 × PASS** |
| WKR-001/002/003/005-RUNTIME | Gerçek Linux Docker | **4 × SKIP** |
| CODE-001/DEP-001 ADAPTER | Host | **2 × PASS** |
| CODE-001/DEP-001 BINARY | Gerçek ikili (Windows host) | **2 × PASS** |
| SEC-001 … SEC-014 | Host | **14 × PASS** |
| EGR-001 … EGR-006 | Host (süreç/loopback) | **6 × PASS** |
| EGR-LINUX-NETNS-RUNTIME | Gerçek Linux netns | **1 × SKIP** |

Tam tablo: [docs/audit-evidence/gates_table.md](docs/audit-evidence/gates_table.md).

## 5. Tamamlanmamış özellikler

1. Gerçek Linux Docker (WKR) ve netns/broker uçtan uca (EGR) doğrulaması — GitHub Actions `ubuntu-24.04` çalıştırması gerekir.
2. API ↔ worker ↔ broker entegrasyonu (API taramaları host alt süreciyle çalışıyor; broker URL'si kullanılmıyor).
3. Gerçek Laravel + PostgreSQL + Redis/Horizon + Sanctum; gerçek Next.js uygulaması.
4. Alan adı sahipliği (DNS) doğrulaması; SMTP teslimatı; MFA ve parola sıfırlama tamamlanması.
5. Kalıcı nonce/bütçe/audit depolaması; anahtarlı/harici append-only audit.
6. `gitleaks` ile tam geçmiş sır taraması; bağımsız sızma testi; `apps/web`/`apps/api` kilit dosyaları (`package-lock.json`, `composer.lock`).
