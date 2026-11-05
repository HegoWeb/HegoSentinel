# HegoSentinel — RELEASE_READINESS

> **ARŞİV — 2026-11-05 ilk denetim kararı (Sprint 9 öncesi).** Güncel karar: [../RELEASE_READINESS.md](../RELEASE_READINESS.md).`n>`n> **Kanonik kaynak:** Git `main@1cda48d` · **Tarih:** 2026-11-05
> Bu belge karar önerisidir. **Hiçbir push, etiket veya birleştirme yapılmadı.**
> Kanıtlar: [`PROJECT_STATUS.md`](../../PROJECT_STATUS.md) · [`VERSION_AUDIT_2026-11-05.md`](VERSION_AUDIT_2026-11-05.md) · [`docs/audit-evidence/`](../audit-evidence/)

## Karar

| Hedef | Karar | Tek cümlelik gerekçe |
|---|---|---|
| **GitHub public alpha (kaynak kod yayını)** | **NO-GO — düzeltilebilir** | Varsayılan API'de kimlik doğrulama atlatması (F-01, P0) var; broker audit log sızıntısı (F-02) ve yanlış/eskimiş README iddiaları (F-03) kapanmadan yayınlanmamalı. |
| **Production / canlı hedef tarama** | **NO-GO** | Gerçek Docker/netns izolasyonu hiç doğrulanmadı, API gerçek Laravel/PostgreSQL/Redis değil ve broker zorunlu yola bağlı değil. |
| `restricted-remote` | **KAPALI kalmalı** | Gerçek ağ izolasyonu kanıtı yok (EGR-LINUX-NETNS-RUNTIME = SKIP). Mevcut durum doğru. |

> [!IMPORTANT]
> Bu kararda yumuşatma yoktur. 27 PASS / 0 FAIL, 5 SKIP: bu durum **release gate'in `BLOCKED` kalmasının nedenidir.** SKIP, PASS değildir.

## 1. GitHub public alpha — GO için zorunlu koşullar

Aşağıdakilerin hepsi kapanınca karar **GO**'ya çevrilebilir. Hepsi küçük işlerdir (tahmini birkaç saat).

| # | Koşul | Bulgu | Kabul ölçütü |
|---|---|---|---|
| **B1** | `X-Demo-Principal` yolu varsayılan olarak **kapalı** olmalı. Yalnızca açık bir ortam bayrağı (ör. `HEGOSENTINEL_DEMO_MODE=1`) ve loopback bağlantısıyla açılmalı. `APP_ENV=production` iken hiçbir koşulda çalışmamalı. | F-01 (P0) | `15-demo-principal-auth-bypass-poc.log` senaryosu **401** döndüren bir regresyon testine dönüşmeli. Mevcut 36 PHP testi ve E2E akışı demo bayrağı ile geçmeye devam etmeli. |
| **B2** | Broker audit log'unda URL sorgu/fragment ve hata ayrıntıları redakte edilmeli; giden başlıklar **izin listesi** ile sınırlanmalı. `zip12` çözümü referans alınmalı; **elle** ve testle taşınmalı. | F-02 (L-01, L-02) | `16-broker-audit-leak-poc.log` → `secret_query_value_persisted_in_audit_log: false`. `zip12`'deki *"Independent broker evidence minimization regression"* testi kanonik pakette PASS. |
| **B3** | `README.md`, `README.tr.md`, `docs/ROADMAP.md`, `CHANGELOG.md` gerçek durumla eşleşmeli (bkz. 3). | F-03 | Her iddia `PROJECT_STATUS.md` sınıflandırmasıyla uyumlu. |
| **B4** | Hijyen: `.gitignore` (bkz. 4), kök dizin temizliği/arşivleme, demo parolasının/kişisel adın sadeleştirilmesi, lisans tutarlılığı. | F-04..F-07 | `git ls-files` içinde dahili brif/rapor, `.env`, `*.zip` yok; `LICENSE` ile `composer.json` aynı lisans. |
| **B5** | Public README'de "Docker/netns **UNVERIFIED**, Laravel/Next **iskelet/özel uygulama**" ifadeleri açıkça yer almalı. | F-03 | Okuyan biri üretime hazır olmadığını ilk ekranda anlayabilmeli. |

**Şiddetle önerilir (zorunlu değil):** İlk push'tan sonra GitHub Actions'ı çalıştırıp çıktıyı incelemek. Bu, Linux Docker/netns/Semgrep kanıtı için tek meşru yoldur. CI çalıştırılmadan hiçbir WKR/EGR Linux kontrolü PASS ilan edilemez.

## 2. Production engelleri

| # | Engel | Durum | Gerekli kanıt |
|---|---|---|---|
| P-1 | **Gerçek Docker worker izolasyonu** (WKR-001/002/003/005) | SKIP — Docker yok | `ubuntu-24.04` üzerinde `linux-docker-verify.sh` PASS + saklanan log. |
| P-2 | **Gerçek ağ izolasyonu + broker zorunlu yolu** (EGR-LINUX-NETNS-RUNTIME) | SKIP | Worker'ın broker'ı atlayarak internete/iç ağa çıkamadığını gösteren uçtan uca test. |
| P-3 | **API ↔ worker ↔ broker bağlantısı** | Yok | API taramaları host'ta `node` alt süreciyle çalışıyor; `HEGOSENTINEL_EGRESS_BROKER_URL` kodda hiç kullanılmıyor. |
| P-4 | **Gerçek Laravel + PostgreSQL + Redis/Horizon + Sanctum** | Yok (özel PHP katmanı + SQLite) | `composer install`, PostgreSQL ve Redis üzerinde entegrasyon testleri; ya da mimarinin dürüstçe yeniden adlandırılması. |
| P-5 | **Gerçek Next.js uygulaması** | Yok (Node `http` + gömülü HTML) | `next build` + bileşen tabanlı arayüz ya da yeniden adlandırma. |
| P-6 | **Kimlik doğrulama sertleştirmesi** | Eksik | F-01 kapatılmalı; hız sınırlama/kilitleme, MFA zorlaması, tohum demo verisinin üretimde yüklenmemesi. |
| P-7 | **Kalıcı durum** (nonce, tarama bütçesi, broker audit) | Bellek içi | Atomik, merkezi, ekleme-yalnız depolama. |
| P-8 | **E-posta teslimatı** | Simüle (DB kaydı) | SMTP/sağlayıcı entegrasyonu + onaylı alan adı testleri. |
| P-9 | **CI hiç çalışmadı** | Doğrulanmadı | 5 işin de yeşil çalışması, artefaktların saklanması. |
| P-10 | **Bağımsız güvenlik incelemesi** | Yapılmadı | Üçüncü taraf gözden geçirme veya özel sızma testi. |
| P-11 | **Sır tarama aracı** | Yalnız `git grep` | `gitleaks`/`trufflehog` ile tam geçmiş taraması. |
| P-12 | **Kilit dosyaları** | `apps/web`, `apps/api` yok | `package-lock.json`, `composer.lock`. |

**Production için release gate kuralı:** `npm run verify:release-gate` çıktısı `BLOCKED` olduğu sürece sürüm yayımlanamaz. Gate şu an doğru çalışıyor; ona dokunulmadı.

## 3. README / ROADMAP / CHANGELOG düzeltme listesi (uygulanmadı)

| Dosya | Mevcut iddia | Gerçek durum | Önerilen düzeltme |
|---|---|---|---|
| `README.md:23` | Gerçek `semgrep`/`trivy` çalıştırma = `unverified` | Windows host'ta gerçek ikililerle **PASS** (Semgrep 1.183.0, Trivy 0.76.1); Linux CI'da doğrulanmadı | "Windows host: verified; Linux CI: unverified" |
| `README.md:33`, `ROADMAP.md:23,109-111` | Laravel API, Next.js dashboard = `planned` | Özel PHP API (36 test) ve Node-render arayüz **var**; gerçek Laravel/Next **yok** | "Prototype: custom PHP service layer + Node-rendered UI; Laravel/PostgreSQL/Redis/Next.js migration planned" |
| `ROADMAP.md:3,95` | 64 test: 59 PASS / 5 SKIP | 67 TS + 36 PHP; 61 PASS / 6 SKIP (sandbox) | Güncel sayılar |
| `CHANGELOG.md` | Sprint 7/8 kaydı yok; `[Unreleased]` eski | Sprint 7 ve Sprint 8 yayımlanmamış ama yapılmış | `[Unreleased]` altında Sprint 7/8 |
| Commit `26ec85b` mesajı | "Laravel backend", "Next.js platform" | Yanıltıcı | Geçmişi yeniden yazmayın; README'de açıklayın |
| `package.json`'lar | `0.1.0-alpha.4` | Yeni kod alpha.4 sonrası | Blokerler kapanınca `0.1.0-alpha.5` (**etiket yok**) |

## 4. Önerilen `.gitignore` eklemeleri (uygulanmadı)

```gitignore
# secrets
.env
.env.*
!.env.example
*.pem
*.key
# bulky/duplicate archives
*.zip
# keep audit evidence logs (currently swallowed by *.log)
!docs/audit-evidence/*.log
```

Ek öneri: kök dizindeki 15 dahili belge ve `HegoSentinel_alpha4_Degisiklikler.patch` dosyasını `docs/archive/` altına taşımak (**silmeden**), iki birebir kopyayı tek tutmak.

## 5. Push öncesi kontrol listesi

- [ ] B1–B5 kapandı ve `npm test`, `npm run test:api`, `npm run typecheck`, `npm run lint` yeşil.
- [ ] `npm run verify:release-gate` hâlâ **BLOCKED** (SKIP'ler PASS'e çevrilmediyse bu doğru ve beklenir).
- [ ] `git remote add origin …` **kullanıcı tarafından** eklendi (gizli kimlik bilgisi istenmez, otomatik işlem yapılmaz).
- [ ] İlk push sonrası GitHub Actions 5 işi incelendi.
- [ ] `restricted-remote` varsayılan **kapalı**.

## 6. Bu denetimde yapılanlar / yapılmayanlar

**Yapıldı:** salt-okunur analiz; 13 ZIP için SHA-256 ve dosya bazlı karşılaştırma; gerçek test çalıştırmaları; iki PoC; sır taraması; **yeni** dosyalar: `PROJECT_STATUS.md`, `VERSION_AUDIT.md`, `RELEASE_READINESS.md`, `docs/audit-evidence/**`.

**Yapılmadı (talimat gereği):** `git push`, sürüm etiketi, otomatik birleştirme, ZIP/klasör silme, mevcut kaynak dosyayı değiştirme, `.gitignore`/README değişikliği, commit.

**Yan etki:** `reports/` (Git dışı) test çalıştırmalarıyla yeniden üretildi. Yerel, Git dışı SQLite dosyalarında (`apps/api/database/hegosentinel.sqlite*`) yalnızca paylaşımlı bellek dizini (`-shm`) zaman damgası değişti; veri (`.sqlite`, `-wal`) zaman damgaları denetim öncesiyle aynı (02:34 / 02:39). Denetim sonunda çalışan `php`/`node` süreci kalmadı.

**Kanıt kısıtları:** Docker ve GitHub Actions erişimi olmadığından Linux kontrolleri çalıştırılamadı. Sandbox, Semgrep'i engellediği için Semgrep testleri sandbox dışında ayrıca çalıştırıldı (`12-…`, `13-…`, `14-…` logları).
