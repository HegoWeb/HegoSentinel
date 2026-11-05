# HegoSentinel — VERSION_AUDIT

> **ARŞİV — 2026-11-05 ilk sürüm denetimi (Sprint 9 öncesi anlık görüntü).** Güncel durum için [PROJECT_STATUS.md](../../PROJECT_STATUS.md). Ham adli (forensic) çıktılar yerel kalır, depoya eklenmez.`n>`n> **Denetim tarihi:** 2026-11-05 · **Yöntem:** salt-okunur. ZIP'ler çıkarılmadı, hiçbir kaynak dosya silinmedi, ezilmedi veya birleştirilmedi.
> **Kanonik kaynak:** `<repo>` (local working copy) · branch `main` · HEAD `1cda48d85d00b91032b36b5abb80feab00d8ced8` · çalışma ağacı **temiz** (yalnız bu denetimin yeni `docs/audit-evidence/` dosyaları izlenmiyor) · `git remote` **yok**.

## 1. Gerçek güncel sürüm nedir?

| Soru | Kanıtlı cevap |
|---|---|
| Etkin proje klasörü | `<repo>` (Git deposu kökü; `git rev-parse --show-toplevel`) |
| Git geçmişi | Yalnız **3 commit**: `6e683d0` (Sprint 7) → `26ec85b` (Sprint 8) → `1cda48d` (IDE tanı düzeltmeleri). Önceki alpha.1–4 geçmişi Git'te **yok**; yalnızca ZIP'lerde yaşıyor. |
| Paket sürümü | Tüm `package.json` → `0.1.0-alpha.4` |
| `CHANGELOG.md` | En üst bölüm `[0.1.0-alpha.4]`, ardından `[Unreleased] — Independent audit hotfix (2026-11-04)`. **Sprint 7 ve Sprint 8 için kayıt yok.** |
| Gerçek durum | **`0.1.0-alpha.4` + Sprint 7 + Sprint 8, yayımlanmamış (unreleased).** Sürüm etiketi yok, oluşturulmadı. |
| Öneri (uygulanmadı) | Blokerler kapanınca `0.1.0-alpha.5` olarak etiketlenmeli. Bu denetimde etiket oluşturulmadı. |

**Sonuç:** Kanonik kaynak, Git `HEAD 1cda48d`'dir. **ZIP adı, boyutu veya tarihi güncellik kanıtı olarak kullanılmadı**; yalnızca dosya içeriği SHA-256'sı kullanıldı.

## 2. ZIP envanteri ve karşılaştırma

Yöntem (`docs/audit-evidence/tools/`):

1. Her ZIP için tüm dosyanın SHA-256 değeri hesaplandı (`Get-FileHash`).
2. ZIP içindeki girdiler akış olarak okunup dosya başına SHA-256 hesaplandı. Metin dosyalarında CRLF→LF normalleştirmesi yapıldı (`manifest.ps1`).
3. Kaynak karşılaştırmasından dışlananlar: `node_modules`, `.tools`, `.git`, `reports`, `.playwright-mcp`, `*.sqlite*`, `*.log`, `*.zip`, iç içe `HegoSentinel/` kopyası.
4. Kanonik referans = `git ls-files` ile izlenen **131 dosya**.
5. Farklı olan her dosya için satır, `export` sembolü, test adı ve `package.json` script düzeyinde "kayıp geliştirme" taraması yapıldı (`loss.mjs`).

<!-- tablo: docs/audit-evidence/zip_table.md -->
| ID | Dosya | Boyut (bayt) | Değiştirilme | SHA-256 | Kaynak dosya | Kanonikle aynı | Farklı | Yalnız ZIP | Sonuç |
|---|---|---:|---|---|---:|---:|---:|---:|---|
| zip01 | HegoSentinel_Project_Documentation.zip | 14605 | 2026-11-04T19:58:24 | `9da39d1e9174794dbcdabda685a9904d6b73b2d9abce0e76984b243aa9812162` | 10 | 6 (4.6%) | 4 | 0 | En eski belge paketi (yalnız 10 kaynak dosya) |
| zip02 | HegoSentinel_Project_Documentation (2).zip | 362627 | 2026-11-04T21:06:59 | `5da5b9125c5c8722d4d41cfae63666a4e5839058f8ed155bc6f7a3f705c9c5d5` | 51 | 27 (20.6%) | 24 | 0 | Erken alpha; kanonikte olmayan benzersiz kod yok |
| zip03 | HegoSentinel_Project_Documentation (3).zip | 4868493 | 2026-11-04T21:42:47 | `59058f95a0e06a24131deb91f018280d22689c6a655ba71a97999ab1d5f1759c` | 57 | 29 (22.1%) | 28 | 0 | alpha.1–2 dönemi; benzersiz kod yok |
| zip04 | HegoSentinel_Project_Documentation (4).zip | 4881346 | 2026-11-04T22:07:19 | `7c4dd6294b9e14abf83e9fe9d6daf213d69c362a9ccff1db051cd4a5a3cef8d2` | 59 | 33 (25.2%) | 26 | 0 | alpha.2–3 dönemi; benzersiz kod yok |
| zip05 | HegoSentinel_Project_Documentation (5).zip | 4892168 | 2026-11-04T22:32:58 | `b761bb1e814bef72518df292fce2d785f6a1dc82601f8223971e49aa6875799b` | 61 | 38 (29%) | 23 | 0 | alpha.3; benzersiz kod yok |
| zip06 | HegoSentinel_Project_Documentation (6).zip | 4995893 | 2026-11-05T00:25:29 | `88bc6c94a4690e2d06e04fa0bde3910b4a6a8722b082f2729d636c40f7720077` | 82 | 62 (47.3%) | 20 | 0 | alpha.4 öncesi; benzersiz kod yok |
| zip07 | HegoSentinel_Project_Documentation (7).zip | 414913483 | 2026-11-05T01:32:38 | `79b6f3e2704fdba67225367a5eee09273a24fcb1102ca96b5e9702936fc8133d` | 100 | 90 (68.7%) | 10 | 0 | Sprint 7 sonrası; kanonikten eski 10 dosya; benzersiz kod yok |
| zip08 | HegoSentinel_Project_Documentation (8).zip | 407480320 | 2026-11-05T02:42:32 | `1bdca41d3e68c7ae74c3a9679ff390357c5215a942a0b44dcbf1e84c39501c57` | — | — | — | — | **Kesik/bozuk ZIP** (bkz. 2.2) |
| zip09 | HegoSentinel_Project_Documentation (9).zip | 415569490 | 2026-11-05T02:45:48 | `47c0c4926f2b4fe3775f56992326362c3b3c2cd970c0bbdee93a232a877f93d2` | 131 | 131 (100%) | 0 | 0 | **Kanonikle birebir (131/131).** Güncel anlık görüntü |
| zip10 | HegoSentinel_alpha3_audit_hotfix_source.zip | 162915 | 2026-11-04T22:20:42 | `fbe20790f64a257fc578a880ca2b7da73638195c655a775573e10dda5d85483a` | 61 | 38 (29%) | 23 | 0 | alpha3 audit hotfix; benzersiz kod yok |
| zip11 | HegoSentinel_alpha4_Gelistirilmis_Kaynak_Kod.zip | 171197 | 2026-11-04T22:43:26 | `6438b7469db66309ef9ad6056370fbf43360ed1a3dc05922058d6c2d1dc89d0b` | 64 | 40 (30.5%) | 24 | 0 | alpha4 geliştirilmiş kaynak; benzersiz kod yok |
| zip12 | HegoSentinel_Runtime_Security_Hotfix_2026-11-05.zip | 187713 | 2026-11-05T00:37:59 | `3d3085a8f9da7d0f4e6561ae3d677b90d166c1c693be3285d53d4c9677ba277a` | 68 | 46 (35.1%) | 20 | 2 | **Kanonikte olmayan düzeltmeler içerir** (bkz. 3) |
| zip13 | HegoSentinel_Engineering_Review_and_Next_Sprint.zip | 7060 | 2026-11-04T23:23:26 | `fdc7b33b19349defa20b1c7aba8bb57bf0c72ba00fb0b7c53178478236740e8b` | 2 | 2 (1.5%) | 0 | 0 | Yalnız 2 doküman (kanonikle aynı) |

`Downloads` içindeki `HegoWeb_*` ZIP'leri (Marendo/Margido carousel, Onaylı Postlar, TeknikEv vb.) bu projeyle ilgisizdir ve incelenmedi.

### 2.1 Kanonik ↔ `(9).zip`
`(9).zip`, 131 kaynak dosyanın **131'inde** kanonikle SHA-256 olarak aynıdır. Yani `(9).zip`, `HEAD 1cda48d` içeriğinin bir kopyasıdır; ek bir değer taşımaz. ~415 MB olmasının nedeni `.tools` (11.523 dosya) ve `.git` içermesidir.

### 2.2 `(8).zip` kesik
.NET `ZipFile`, "Merkezi Dizinin Sonu kaydı bulunamadı" hatası verdi: dosya yarım inmiş. Yerel dosya başlıkları elle tarandı (`scan_truncated_zip.mjs`, `zip08_truncated_header_scan.json`):

- 11.805 başlık bulundu: 11.523 `.tools`, 260 `.git`, 22 kalan.
- Kanonikle eşleşen yalnızca 12 kaynak başlığı var; benzersiz kaynak kod bulunamadı.
- **Karar:** Doğrulanamayan arşiv. Kaynak olarak kullanılmayacak.

### 2.3 İç içe `HegoSentinel/` klasörü
Çalışma dizininde `.gitignore` ile (`/HegoSentinel/`) dışlanmış 68 dosyalık bir klasör var. Dosya karşılaştırması: `zip12` ile **68/68 SHA-256 aynı**. Yani bu klasör Runtime Security Hotfix paketinin açılmış hâlidir. Silinmedi; salt-okunur arşiv olarak kalmalı.

## 3. Önceki ZIP'lerde kaybolmuş geliştirme var mı?

**Evet. Tamamı `zip12` (Runtime Security Hotfix, 2026-11-05) kaynaklıdır.** `zip01–zip11` ve `zip13` içinde kanonikte bulunmayan hiçbir `export` sembolü, test adı veya `package.json` script'i bulunmadı (`zip_loss_report.json`: ZIP × farklı dosya olarak 204 çift analiz edildi).

| ID | Önem | Kayıp / eksik | Kanıt | Karar |
|---|---|---|---|---|
| **L-01** | **P1 (güvenlik gerilemesi)** | **Broker audit log URL sorgu parametrelerini ve ham hata ayrıntılarını saklıyor.** `zip12` sürümü `safeBrokerAuditUrl()` + `redactSensitiveText()` ile bunu engelliyordu. Kanonik `apps/egress-broker/src/index.ts` (satır 232–274) ham `req.url` yazıyor. | **Gerçek PoC:** `?token=top-secret-audit-value&code=abcdef` audit log'a düz yazıldı → `secret_query_value_persisted_in_audit_log: true`. Log: `docs/audit-evidence/16-broker-audit-leak-poc.log`. Kanonikteki tüm testler bu hâliyle geçiyor; yani mevcut test paketi bu davranışı yakalamıyor. | **Korunmalı / taşınmalı.** (Otomatik birleştirme yapılmadı.) |
| **L-02** | P2 | Broker'ın giden istek başlıklarında **izin listesi** (`accept-language`, `x-custom-trace`) vardı. Kanonik yalnız **yasak listesi** (`FORBIDDEN_OUTBOUND_REQUEST_HEADERS`) kullanıyor. Deny-by-default ilkesine daha zayıf uyuyor. | `zip12` `apps/egress-broker/src/index.ts#SAFE_OPTIONAL_OUTBOUND_HEADERS`; kanonikte `accept-language` için 0 eşleşme. | Korunmalı. |
| **L-03** | P2 (test) | `zip12` testleri: *"Independent broker evidence minimization regression"* ve 5 gerçek-Docker `WKR-001..005` testi. WKR testleri kanonikte farklı tasarımla var (`analyzeDockerRunOutcome`); **broker audit regresyon testi yok**. | `zip_loss_report.json` → `tests_lost` (7 test). | Broker testi taşınmalı. WKR testleri incelenip tek tasarımda birleştirilmeli. |
| L-04 | P3 | `verify:gates:release` (`--require-complete`) script'i. | `zip12` `package.json`. | **Gerekmez**: kanonikteki `verify:release-gate` + `release-gate-check.ts` aynı amacı karşılıyor (çalıştırıldı, `BLOCKED` döndü). |
| L-05 | P3 | Docker doğrulamada `HS_REAL_PROBE_EXECUTED` pozitif kontrol işareti ve `--entrypoint` geçersiz kılma. | Kanonik script her prob için beklenen işaret + 125/126/127 reddi yapıyor, imaj `ENTRYPOINT` yerine `CMD` kullanıyor. | **Gerekmez** (eşdeğer güvence); isteğe bağlı güçlendirme. |
| L-06 | Doküman | İki rapor yalnız `zip12`'de: `docs/AUDIT_2026-11-05_RUNTIME_GATE_TR.md`, `docs/ANTIGRAVITY_NEXT_VERIFICATION_BRIEF_TR.md`. | `zip_comparison_full.json` → `only_zip_list`. | Arşiv olarak saklanmalı. |

**Kayıp sayılmayanlar (kanonik daha yeni):** `Dockerfile` (kanonikte `CMD` + pinli Semgrep/Trivy kurulumu), `policy-engine` gizli veri regex'i (kanonik daha kapsamlı: PEM, DB URL, `APP_KEY=`), tüm Sprint 7/8 kodu.

> [!WARNING]
> L-01 gerçek, tekrarlanabilir bir sızıntıdır. Kanonik sürümde audit log (`getAuditLog`) kullanıcı kontrollü `?token=…` değerlerini barındırabilir. Bu düzeltilmeden broker, kamuya açık alpha'da "kanıt minimizasyonu" iddia edemez.

## 4. Kanonik kaynak kararı

| Karar | Gerekçe |
|---|---|
| **CANONICAL SOURCE = Git `main@1cda48d`** | Tüm Sprint 7/8 kodunu ve 67+36 testi içeren tek kaynak; `(9).zip` ile birebir. |
| Tüm ZIP'ler **salt-okunur arşiv** | Karşılaştırma bunu destekliyor; hiçbirinde kanonik üstü yeni kod yok. |
| `zip12` **tek istisna** | L-01..L-03, L-06 kanonike *elle ve testle* taşınmalı. Bu denetimde taşınmadı. |
| `(8).zip` | Kesik; kullanılmaz. Silinmesi kullanıcı kararı. |
| İç içe `HegoSentinel/` | `zip12` kopyası; Git dışı; silinmedi. |

Bundan sonra geliştirme yalnızca `main` üzerinde, kanonik depodan yapılmalıdır.

## 5. Yeniden üretme

```powershell
# 1) ZIP SHA-256 + manifest (ZIP'ler çalışma alanı dışında olduğu için sandbox dışı okuma gerekir)
powershell -NoProfile -File docs\audit-evidence\tools\run_zip_inventory.ps1
# 2) Kanonik ile karşılaştır, kayıp geliştirmeyi tara
node docs\audit-evidence\tools\compare.mjs ; node docs\audit-evidence\tools\loss.mjs
# 3) L-01 PoC
node --experimental-strip-types docs\audit-evidence\tools\poc_broker_audit_leak.ts
```

> Not: `tools/` altındaki betikler denetimde `…\brain\…\scratch\` yollarını kullandı. Başka makinede `$S` / `S` değişkeni güncellenmelidir.
