# HegoSentinel — RELEASE_READINESS (Sprint 9)

> **Kanonik kaynak:** `main@1cda48d` + Sprint 9 çalışma ağacı (commit/push/tag **yapılmadı**). **Tarih:** 2026-11-05. Bu belge bir **karar önerisidir**; yayın kararı proje sahibine aittir.
> Kanıtlar: [PROJECT_STATUS.md](../PROJECT_STATUS.md) · [docs/security/SPRINT9_SECURITY_REAUDIT.md](security/SPRINT9_SECURITY_REAUDIT.md) · [docs/audit-evidence/sprint9/](audit-evidence/sprint9/)
> Önceki (Sprint 9 öncesi) karar: [archive/RELEASE_READINESS_2026-11-05_first-audit.md](archive/RELEASE_READINESS_2026-11-05_first-audit.md)

## Kararlar

| Hedef | Karar | Tek cümlelik gerekçe |
|---|---|---|
| **Private repository** | **GO** | Gerçek sır yok, tüm testler yeşil (0 FAIL), P0/P1 açıklar kapalı; ilk CI koşusu da zaten özel depoda yapılmalı. |
| **Public alpha repository** | **GO — koşullu** (aşağıdaki yayın öncesi kontrol listesi tamamlanınca) | B1 ve B2 gerçek PoC öncesi/sonrası ve kalıcı regresyon testleriyle kapandı; depo temizliği ve dokümantasyon gerçek durumla hizalandı; sınırlamalar ilk ekranda açıkça yazılı. |
| **Production deployment** | **NO-GO** | Gerçek Docker/netns izolasyonu, uçtan uca yetkilendirme (API↔worker↔broker), gerçek altyapı (Laravel/PostgreSQL/Redis) ve bağımsız doğrulama yok. |
| `restricted-remote` | **KAPALI kalmalı** | `EGR-LINUX-NETNS-RUNTIME` = SKIP. |

> [!IMPORTANT]
> **Public alpha yayınlanabilir olması production'a hazır olduğu anlamına gelmez.** `npm run verify:release-gate` hâlâ **BLOCKED** döner (5 SKIP — NOT VERIFIED) ve bu doğrudur. SKIP, PASS sayılmaz.

## 1. Public alpha — kabul ölçütleri ve kanıt

| # | Ölçüt | Sonuç | Kanıt |
|---|---|---|---|
| 1 | **B1** — header ile kimlik taklidi imkânsız (production/dev/test) | ✅ Kapandı | PoC öncesi **11/11 açık** → sonrası **0/11** ([before](audit-evidence/sprint9/S9-before-fix-php-battery.log) / [after](audit-evidence/sprint9/S9-after-fix-php-battery.log)); PHP regresyon **50/50** ([T05](audit-evidence/sprint9/T05-test-api-php.log)), özgün PoC `B1` ([before](audit-evidence/sprint9/B1-before-fix.log)) 4 senaryo → 401 |
| 2 | **B2** — audit log maskeleme, başlık izin listesi, saat/limit güveni, yönlendirme | ✅ Kapandı | Broker PoC öncesi **3/3 açık** (süresi dolmuş grant + geriye tarihli `now` → HTTP 200 ALLOW; yetkisiz başlıklar iletildi; sorgu sırrı log'da) → sonrası **0/3** ([before](audit-evidence/sprint9/B2-before-fix-http.log) / [after](audit-evidence/sprint9/B2-after-fix-http.log)); `broker-b2-regression` **12/12** |
| 3 | Mevcut testler korundu, güvenlik kontrolü gevşetilmedi | ✅ | TS **84 test: 78 PASS / 0 FAIL / 6 SKIP** (sandbox; gerçek 5 SKIP), PHP **86/86**; yalnızca 2 test daha katı semantiğe göre güncellendi |
| 4 | Gerçek Semgrep/Trivy ikilileri | ✅ (Windows 10 / Node 24.19.0) | 6/6 PASS — Semgrep CE `1.183.0`, Trivy `0.76.1` ([U01](audit-evidence/sprint9/U01-real-semgrep-trivy.log)) — Linux CI **doğrulanmadı** |
| 5 | Depo temizliği: sırlar, `.tools/`, `node_modules/`, ZIP, `.env`, müşteri raporu | ✅ | `.gitignore` sıkılaştırıldı; [ön-commit taraması](audit-evidence/sprint9/SECRET-SCAN-PRECOMMIT.md): commit edilecek sır yok, dışlanması gereken dosya yok, en büyük dosya 113 KB |
| 6 | Dokümantasyon doğruluğu (Laravel/Next.js/Postgres/Docker iddiaları) | ✅ | README×2, ROADMAP, CHANGELOG, PROJECT_STATUS gerçek duruma göre yeniden yazıldı; `npm run docs:links` **PASS** |
| 7 | Git geçmişinde sır yok | ✅ (desen tabanlı) | 3 commit taraması: yalnızca sahte test verisi; **`gitleaks` çalıştırılmadı** |
| 8 | Kişisel veri | ✅ | Kaynak/evidence'ta kişisel ad ve yerel yol kalmadı (taranıp temizlendi) |

### Yayın öncesi kontrol listesi (proje sahibi yapar — bu sprintte yapılmadı)

- [ ] Değişiklikleri gözden geçir ve **kendi onayınla** commit et (komutlar aşağıda). Hiçbir şey otomatik commit/push/tag edilmedi.
- [ ] **Önce özel depoya** push et ve GitHub Actions'ın 5 işini çalıştır; Linux Docker/netns/Semgrep sonuçlarını incele. CI hiç çalışmadığı için ilk koşuda hata çıkabilir; bu, public yayın için engel değil ama public'ten **önce** görülmelidir.
- [ ] `gitleaks detect` (veya `trufflehog`) ile geçmişi ve çalışma ağacını tara.
- [ ] README'deki **Alpha / production'a hazır değil** uyarısının ve "Known limitations" bölümünün yayında korunduğunu doğrula.
- [ ] `restricted-remote` varsayılan **kapalı**, `HEGOSENTINEL_DEMO_MODE` varsayılan **tanımsız**.

```powershell
# Önerilen (çalıştırılmadı) — yerelde:
git add -A
git status                      # gözden geçir: .tools/, node_modules/, reports/, *.sqlite yok olmalı
git commit -m "feat(security): Sprint 9 — close auth bypass (B1), harden egress broker (B2), honest docs & repo hygiene"
# Özel depo (remote'u siz ekleyin):
git remote add origin <PRIVATE-REPO-URL>
git push -u origin main         # ilk push → CI başlar. Etiket (tag) oluşturmayın; release kararı sizindir.
```

## 2. Production engelleri (güncel)

| # | Engel | Durum | Gerekli kanıt |
|---|---|---|---|
| P-1 | Gerçek Docker worker izolasyonu (WKR-001/002/003/005) | **SKIP** — Docker yok | `ubuntu-24.04` üzerinde `linux-docker-verify.sh` PASS + saklanan log |
| P-2 | Gerçek ağ izolasyonu + broker zorunlu yolu (EGR-LINUX-NETNS-RUNTIME) | **SKIP** | Worker'ın broker'ı atlayamadığını gösteren uçtan uca test |
| P-3 | **API ↔ worker ↔ broker bağlantısı** | Yok — taramalar host `node` alt süreciyle | Taramaların konteyner içinde, çıkışların broker üzerinden olduğunun kanıtı |
| P-4 | Gerçek Laravel + PostgreSQL + Redis/Horizon + Sanctum | Yok (özel PHP + SQLite) | Entegrasyon testleri veya mimarinin yeniden adlandırılması |
| P-5 | Gerçek Next.js uygulaması | Yok (Node HTTP + gömülü HTML) | `next build` + bileşen tabanlı arayüz |
| P-6 | MFA zorlaması, parola sıfırlama tamamlanması, oturum bağlama | Eksik | Testli uygulama |
| P-7 | Alan adı sahipliği (DNS) ve bildirim alan adı doğrulaması | Yok | Kriptografik doğrulama testleri |
| P-8 | Kalıcı nonce/bütçe/audit (broker), anahtarlı/harici append-only audit, hash zinciri için işlem/kilit | Bellek içi / anahtarsız | Atomik merkezi depolama |
| P-9 | SMTP/e-posta teslimatı | Simüle (DB kaydı) | Sağlayıcı entegrasyonu + testler |
| P-10 | CI hiç çalışmadı | Doğrulanmadı | 5 işin de yeşil koşusu ve saklanan artefaktlar |
| P-11 | Bağımsız güvenlik incelemesi / sızma testi / `gitleaks` | Yapılmadı | Üçüncü taraf rapor |
| P-12 | Kilit dosyaları (`apps/web`, `apps/api`) | Yok | `package-lock.json`, `composer.lock` |

**Release gate kuralı:** `npm run verify:release-gate` çıktısı BLOCKED iken production sürümü yayımlanamaz. Gate bu sprintte değiştirilmedi.

