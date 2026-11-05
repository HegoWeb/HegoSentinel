# HegoSentinel — Sprint 9 Güvenlik Yeniden Denetimi (B1 + B2 + mimari tarama)

> **Kanonik kaynak:** `main@1cda48d` + Sprint 9 çalışma ağacı değişiklikleri (commit edilmedi). **Yöntem:** önce açığı çalıştır (PoC), sonra düzelt, sonra aynı PoC'yi yeniden çalıştır, ardından regresyon testi ekle. Ham kanıtlar: [`docs/audit-evidence/sprint9/`](../audit-evidence/sprint9/).
>
> **Dürüstlük notu:** Aşağıdaki "doğrulandı" ifadeleri yalnızca gerçekten çalıştırılmış PoC/testler içindir. Kod incelemesiyle görülüp çalıştırılmayanlar ve varsayımsal riskler en altta **ayrı** listelenmiştir.

## 1. Özet

| | Düzeltme öncesi (`HEAD 1cda48d`) | Düzeltme sonrası (çalışma ağacı) |
|---|---|---|
| API PoC bataryası (11 kontrol) | **11 / 11 AÇIK** — [`S9-before-fix-php-battery.log`](../audit-evidence/sprint9/S9-before-fix-php-battery.log) | **0 / 11 açık** — [`S9-after-fix-php-battery.log`](../audit-evidence/sprint9/S9-after-fix-php-battery.log) |
| Broker PoC (3 sınıf) | **3 / 3 AÇIK** — [`B2-before-fix-http.log`](../audit-evidence/sprint9/B2-before-fix-http.log) | **0 / 3 açık** — [`B2-after-fix-http.log`](../audit-evidence/sprint9/B2-after-fix-http.log) |
| Kalıcı regresyon testleri | — | PHP `run-security-regression-tests.php` **50 test**, TS `broker-b2-regression.test.ts` **12 test**, web e2e **+5 test** |

Yeniden üretme: `git archive HEAD …` ile HEAD kopyası çıkarılıp [`poc_sprint9_php.php`](../audit-evidence/sprint9/poc_sprint9_php.php) ve [`poc_broker_b2.ts`](../audit-evidence/sprint9/poc_broker_b2.ts) kök dizin argümanıyla çalıştırılır; aynı betikler çalışma ağacına karşı "sonra" sonucunu verir.

## 2. Bulgular — doğrulanmış (PoC öncesi/sonrası var)

| ID | Önem | Bulgu | Düzeltme | Kalıcı test |
|---|---|---|---|---|
| **S9-01** (B1) | **P0** | `X-Demo-Principal: <user-id>` başlığı parola/token olmadan **herhangi bir kullanıcıyı** (başka kiracının sahibi dahil) taklit ettiriyordu; `APP_ENV=production` iken de çalışıyordu. | Başlıkla kimlik tamamen kaldırıldı: `authenticateRequest(?string $bearer)` yalnızca sunucunun verdiği oturum belirtecini kabul eder; CORS izin listesinden, web proxy'sinden, istemciden ve UI'dan silindi. | PHP C1 (23 rota × 3 sahte kimlik varyantı → 401), C2 (özgün PoC 4 senaryo → 401), A3/B2 (production/test). Web e2e: proxy başlığı iletmez. |
| **S9-02** | **P0** | **Anonim kayıt, mevcut kiracıya sahip olarak katılıyordu**: `POST /auth/register` gövdesindeki `organization_id` ve `role` alanları işleniyordu (PoC: `org-hegoweb-sec` altında `owner`, 3 proje görünür). | Kayıt **her zaman yeni** organizasyon oluşturur; istemci `organization_id`/`role`/`allowed_project_ids` yok sayılır. | C15, C16, C17 |
| **S9-03** | **P0/P1** | Boş veritabanı (production dahil) **bilinen parolalı demo kullanıcılarla** (`HegoSentinel!2026`) otomatik dolduruluyordu → varsayılan kimlik bilgisi arka kapısı. | Demo tohumu yalnızca `HEGOSENTINEL_DEMO_MODE=1` ile (operatör ortamı) ve `APP_ENV` production değilken oluşur. Web arayüzü de demo kimlik bilgilerini yalnızca demo modunda gömer. | A1, A2, B1; web: `isDemoModeEnabled`, "production-safe HTML" testleri |
| **S9-04** | P1 | Davet edilen yeni üyeye **yerleşik varsayılan parola** (`HegoSentinel!2026`) atanıyor ve `mfa_enabled=1` yazılıyordu. | Yeni üye için ≥10 karakter açık başlangıç parolası zorunlu (422); MFA iddiası kaldırıldı; `allowed_project_ids` yalnızca kendi organizasyonunun projelerine işaret edebilir. | C18, C19, C20 |
| **S9-05** | P1 | Giriş denemesi sınırı yoktu (brute force). | 5 başarısız deneme/15 dk/hesap ve 30/IP → 429; doğru parola bile kilit süresince reddedilir. İstemci `X-Forwarded-For` başlığına güvenilmez (kaynak IP `REMOTE_ADDR`). | C31, C32 |
| **S9-06** | P1 | **Salt-okunur `viewer`**, Re-Test çalıştırabiliyordu (yan etki: görevleri otomatik `verified_closed` yapar). Farklı projelerin taramaları arasında karşılaştırma da kabul ediliyordu. | Re-Test `manage_remediation` yetkisi + aynı proje şartı. | C7, C14b, C14c, C14d |
| **S9-07** | P1 | `viewer`/`developer` kuruluşun **tüm denetim izini** okuyabiliyordu; bildirim ve acil durdurma listeleri proje atamasını yok sayıyordu. | `read_audit` yetkisi yalnızca `owner`/`security_lead`; dashboard'daki audit girdileri rolle sınırlı; bildirim/acil durdurma listeleri atanmış projelerle filtrelenir. | C8–C11, C14 |
| **S9-08** | P1 | **Re-Test yanlış doğrulama:** bir geliştirici görevi elle `verified_closed` yapabiliyordu (düzeltilmemiş açık "kapalı" görünür). | `verified_closed` yalnızca doğrulanmış (comparable, `verified_fixed`) Re-Test ile verilir; elle denemeler 422 + audit kaydı. | C12, C13 |
| **S9-09** | P1 | **BOLA keşfi / bilgi sızıntısı:** kiracılar arası erişim reddi, *saldırganın kendi* audit izine **kurbanın organizasyon ve proje kimliklerini** yazıyordu. | Reddedilen erişimde yabancı kimlikler loglanmaz; yalnızca tek yönlü kısa referans (`foreign_ref`) yazılır; proje alanı boş bırakılır. | C5, C6 (PoC S9-08) |
| **S9-10** | **P1** | **Path traversal / projeler arası tarama:** `repository_path` istemciden alınıyor (`../../..` kabul, proje oluşturma 201), grant `allowed_repositories` **tüm depo kökünü** içeriyordu; herhangi bir dizin taranabiliyordu. | `RuntimeMode::resolveRepositoryPath`: mutlak/`..`/UNC/sürücü/NUL reddi, `realpath` ile çalışma alanına hapis; tarama yalnızca **projenin kayıtlı varlık yolu** ve grant sınırı içinde; grant'lar artık kök yerine varlık yoluna bağlı; doğrulama iş kuyruğu satırı oluşmadan önce yapılır. | C21–C26 |
| **S9-11** | **P1** | **Emergency Stop atlatılıyordu:** proje düzeyi durdurma yalnızca istemci `honor_project_stop` bayrağı gönderirse dikkate alınıyordu. Ayrıca var olmayan/yabancı `project_id` ile durdurma olayı yazılabiliyordu. | Proje çapında durdurma (15 dk, `HEGOSENTINEL_ESTOP_HOLD_SECONDS`) yeni taramaları istemci bayrağı olmadan engeller; proje kimliği doğrulanır (404). | C27–C30 |
| **S9-12** (B2) | **P1** | Broker audit log'una URL **sorgu parametreleri düz yazılıyordu** (`?token=…&code=…`), hata ayrıntıları ve istek kimlikleri filtrelenmiyordu. | `sanitizeUrlForAudit` / `sanitizeAuditText` / `sanitizeAuditId`: **hash zinciri hesaplanmadan ve kayıt yapılmadan önce** maskeleme; userinfo ve fragment atılır; opak/uzun değerler maskelenir; satır/`\|` enjeksiyonu etkisizleştirilir; sonuçla dönen `detail` de aynı temiz metindir. | `broker-b2-regression` (12 test) |
| **S9-13** (B2) | **P1** | **Worker'ın başlıkları hedefe iletiliyordu**: yasak-liste mantığıyla `Origin`, `Referer` (token'lı), `X-Internal-Admin` vb. keyfi başlıklar geçiyordu. | Varsayılan-reddet izin listesi (`accept-language`, `x-custom-trace`, her ikisi de değer doğrulamalı) + broker'ın sabit `User-Agent`/`Accept`; atılan başlıkların yalnızca **adları** kaydedilir. | aynı |
| **S9-14** (B2) | **P1** | **Worker kendi saatini seçebiliyordu:** `/v1/egress/fetch` gövdesindeki `now` kabul edildiği için **süresi dolmuş** imzalı grant geriye tarihli `now` ile kabul ediliyordu (PoC: HTTP 200 ALLOW). Ayrıca `env`, `timeoutMs`, `maxResponseBytes` işçiden alınıyordu. | HTTP katmanı yalnızca grant'a bağlı alanları alır (`buildTrustedProxyRequestFromWorkerPayload`); `now`/`env`/`signal` atılır; süre ve boyut tavanı sabit (15 sn / 1 MiB). | `broker-b2-regression` (HTTP grup) |
| **S9-15** (B2) | P2 | Yönlendirme (`Location`) değerlerinde sorgu parametreleri worker'a ve loglara olduğu gibi gidiyordu; taşıma katmanının yönlendirme izlemeyeceği sözleşmede yoktu. | `followRedirects: false` sözleşmesi; dönen `Location` değerlerinde hassas parametreler maskelenir (göreli/mutlak); broker yönlendirme zinciri izlemez (tek hop). | aynı |
| **S9-16** | P3 | İç hata mesajları (`Throwable::getMessage`) istemciye yansıyordu. | Genel mesaj; ayrıntı yalnızca sunucu logunda (`APP_DEBUG=true` ise yansır). | C33 |
| **S9-17** | P3 | Web proxy: `%2e%2e` ile `/api/v1/` dışına çıkabiliyordu; istek gövdesi sınırsızdı. | Hedef kökeni ve yol önekini yeniden doğrular (400); 1 MiB sınır (413). | web e2e |

Korunan kontroller: imzalı grant, nonce tekrarı, TTL ≤ 300 sn, kapsam/hedef bağlama, acil durdurma, SSRF/rebinding/yönlendirme, kiracı izolasyonu, mevcut 36 API testi ve tüm önceki TS testleri **aynen geçmeye devam eder** (hiçbir test gevşetilmedi; yalnızca iki test yeni, daha katı semantiğe göre güncellendi: yeni üye için açık parola, broker HTTP testinde gerçek saatli grant).

## 3. Çalıştırılmadan, kodla incelenen alanlar (kısmen doğrulanmış)

| Alan | İnceleme sonucu | Kanıt türü |
|---|---|---|
| Command injection | PHP `proc_open` dizi argümanıyla (`bypass_shell`); TS adaptörleri `execFile` + `shell:false` (lint kuralı **SEC-006** bunu zorlar). Kullanıcı girdisi artık yol olarak çalışma alanına hapsedilmiş. | Kod incelemesi + mevcut lint/test |
| Web XSS | `apps/web/src/server.ts` istemci betiğindeki 16 `innerHTML` kullanımının tamamında veri alanları `esc()` ile kaçışlanıyor; nitelik değerleri çift tırnaklı. | **Yalnızca statik inceleme**; otomatik DOM-XSS testi yok |
| Rapor dışa aktarma | `Content-Disposition` adı yol parametresi regex'i ile kısıtlı; HTML raporu XSS testli (mevcut test); API yanıtı `CSP: default-src 'none'; sandbox`. | Kod + mevcut test |
| SSRF/DNS rebinding | TS policy engine ve broker testleri (mevcut) geçiyor; **gerçek ağda doğrulanmadı**. | Birim/süreç içi test |
| Re-Test API'si | Karşılaştırma motoru TS tarafında kapsamlı regresyonlu; API tarafında yeni kısıtlar eklendi. | Test |

## 4. Varsayımsal / doğrulanmamış riskler (düzeltilmedi veya kanıtlanamadı)

| ID | Risk | Durum |
|---|---|---|
| R-01 | **Alan adı sahipliği doğrulanmıyor**: proje oluşturulurken varlık `domain_ownership_verified=1` ile kaydedilir; DNS TXT kontrolü yoktur. Kullanıcı herhangi bir genel alan adını "kendisinin" gösterebilir. Canlı tarama (`restricted-remote`) kapalı olduğundan şu an istismar edilemez. | **Kabul edilmiş sınırlama** (belgelendi) |
| R-02 | **Bildirim alan adı doğrulaması simüle**: kayıtta e-posta alan adı "doğrulanmış" sayılır. Teslimat kodu olmadığı için gerçek sızıntı yok; SMTP eklendiğinde kritik olur. | Kabul edilmiş sınırlama |
| R-03 | `appendAuditLog` işlem içinde değil: eşzamanlı isteklerde hash zinciri çatallanabilir (PHP-FPM + SQLite/PG). Zincir ayrıca anahtarsız SHA-256 olduğundan veritabanı yazma yetkisi olan biri tüm zinciri yeniden hesaplayabilir. | Doğrulanmadı / bilinen sınır |
| R-04 | Cross-tenant istekte `403` vs `404` farkı nesne varlığını sızdırır (mevcut testler 403'ü sabitliyor). | Düşük; değiştirilmedi |
| R-05 | Parola sıfırlama: belirteç üretilip saklanıyor, **doğrulama (confirm) uç noktası ve teslim yolu yok**; MFA alanı yalnızca saklanıyor. | Eksik özellik |
| R-06 | Oturum belirteçleri 24 saat, sunucu tarafı iptal var; cihaz/IP bağlama yok. | Kabul |
| R-07 | Broker nonce/bütçe/audit belleğte; yeniden başlatmada sıfırlanır (nonce tekrar penceresi açılabilir). | Kabul edilmiş sınırlama |
| R-08 | API taramaları worker konteyneri/broker üzerinden değil, host `node` alt süreciyle çalışır; Semgrep/Trivy repodaki güvenilmeyen içerik üzerinde host ayrıcalığıyla koşar (gerçek izolasyon kanıtı yok). | **Production engeli** |
| R-09 | Docker/netns doğrulamaları çalıştırılamadı (Docker yok). | **Production engeli** |
| R-10 | Dil seviyesinde otomatik DOM-XSS, DAST veya bağımsız sızma testi yapılmadı. | Yapılmadı |

## 5. Değişen kaynak dosyalar (Sprint 9)

`apps/api/app/Services/SecurityPlatformService.php`, `apps/api/app/Http/Controllers/Api/V1/PlatformApiController.php`, `apps/api/public/index.php`, **yeni** `apps/api/app/Support/RuntimeMode.php`, `apps/api/database/migrations/2026_11_05_000001_create_hegosentinel_platform_tables.php` (+`auth_login_attempts`), `apps/api/composer.json` (lisans MIT), `apps/api/tests/run-api-tests.php` (demo bayrağı + açık parola), **yeni** `apps/api/tests/run-security-regression-tests.php`, `apps/egress-broker/src/index.ts`, `apps/web/src/server.ts`, `apps/web/src/lib/api-client.ts`, `types/node-builtins.d.ts`, `tests/security/broker-b2-regression.test.ts` (yeni), `tests/security/worker-containment-and-sprint2.test.ts` (HTTP broker testi gerçek saatle), `tests/e2e/web-api-platform.test.ts`, **yeni** `scripts/check-markdown-links.ts`, `package.json`, `.gitignore`, dokümantasyon (README×2, ROADMAP, CHANGELOG, PROJECT_STATUS, bu belge, `docs/RELEASE_READINESS.md`).

