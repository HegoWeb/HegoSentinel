# HegoSentinel `v0.1.0-alpha.2` — Bağımsız Kaynak Kod Denetimi

**Denetim tarihi:** 4 Kasım 2026  
**İncelenen arşiv:** `HegoSentinel_Project_Documentation (3).zip`  
**Karşılaştırma:** Önceki `alpha.1` sürümü ve `HegoSentinel_Gercek_Kod_Denetimi_2026-11-04.md`  
**Ortam:** Node.js 22.16.0, npm 10.9.2, mevcut arşivdeki TypeScript derleyicisi.

## 1. Yönetici özeti

**Karar: İyileştirilmiş, çalışır bir offline alpha prototipi; henüz production veya gerçek müşteri sistemlerinde sızma testi için uygun değil.**

- `npm run lint`: PASS.
- `npm run typecheck`: PASS (gerçek `tsc --noEmit` çağrılıyor).
- `npm test`: **18/18 PASS** (5 suit).
- `npm run demo`: PASS; sentetik CSP ve cookie bulguları için karşılaştırma/rapor üretiyor.
- Kapsam, symlink ve recheck'e önceki sürüme göre regresyon testleri eklenmiş.
- Gerçek internet sitesini tarayan HTTP/TLS transport ve OS ağ çıkış izolasyonu hâlâ yok. Remote scan varsayılan olarak engelleniyor.
- Semgrep ve Trivy adaptörleri kaynak kodda mevcut; gerçek binary çalışması ve sandbox sınırları bu denetimde doğrulanmadı.

**Not:** Mevcut 18 testin tamamının geçmesi, test kümesinin kapsamadığı tehditlerin bulunmadığını kanıtlamaz. Aşağıdaki 3 ayrı negatif senaryo kaynak koda karşı uygulandı ve sorun üretildi.

## 2. Önceki denetim maddelerine göre değişiklik

| Eski bulgu | Güncel durum | Kanıt |
|---|---|---|
| HS-AUDIT-001: Başka endpoint ile yanlış fixed | Eski senaryo düzeltilmiş | `packages/recheck-engine/src/index.ts`: WEB-* için rule-only fallback kaldırılmış; regresyon testi geçiyor. |
| HS-AUDIT-002: Doğrudan symlink ile repo sınırı | Eski senaryo düzeltilmiş, **derin symlink açık** | `integrations/semgrep/src/index.ts` `realpathSync`, `inspectDirectorySymlinks`; aşağıdaki bulgu NEW-01. |
| HS-AUDIT-004: grant/scope karşılaştırması | Düzeltilmiş | `compareScanReports` grant_id ve scope_version karşılaştırıyor. |
| HS-AUDIT-005: tsc kontrolü | Düzeltilmiş | `npm run typecheck` gerçek `tsc -p tsconfig.json --noEmit` çalıştırıyor. |
| HS-AUDIT-006: Node 22.16 script çalıştırma | Düzeltilmiş | Node 22.16 altında scripts `--experimental-strip-types` ile çalışıyor. |
| HS-AUDIT-007: repo matching | Testlenmiş iyileştirme | CODE-001 ve DEP-001 farklı repo root'larında `not_comparable`. |
| HS-AUDIT-008: runtime şema kontrolü | Kısmi, **halen eksik** | El yazımı validator, JSON Schema'nın tüm required/minimum kurallarını uygulamıyor; NEW-03. |
| HS-AUDIT-003: canlı tarama / egress izolasyonu | Hâlâ yapılmamış | `scanner-core` `endpoints = options.fixture?.endpoints ?? []`; remote transport yok. |
| HS-AUDIT-009: doküman | İyileşmiş, küçük sürüm tutarsızlığı var | CLI help hâlâ `alpha.1` diyor; paket `alpha.2`. |

## 3. Yeni bağımsız negatif testler

### NEW-01 — P1 / Yüksek: Derin symlink taramasında fail-open kapsam doğrulaması

**Dosya:** `integrations/semgrep/src/index.ts`, `inspectDirectorySymlinks()` (özellikle `depth > maxDepth` ve `readdirSync` hata yakalama).  
**Kanıt:** Geçici, izinli klasörün içinde 13 alt dizin ve bu dizinlerden birinde kapsam dışına işaret eden sembolik bağlantı oluşturuldu. `validateAuthorizedRepositoryPath(allowedDir, grant)` **`allowed: true`** döndürdü. Aynı bağlantı doğrudan kökte yerleştirildiğinde **`allowed: false`** döndürdü.

**Kök neden:** Sınır derinliği aşılınca `return {safe:true}`; `readdirSync` istisnasında da `safe:true`. İncelenmeyen yol güvenli kabul edilmemeli.

**Etki:** Yetkilendirme kontrolü kapsam dışına işaret eden bir bağlantının varlığını onaylayabilir. Tarayıcının gerçekten bağlantıyı takip edip dosyayı okuduğu bu testte gösterilmedi; bu, uygulamanın güvenlik politika kapısındaki doğrulanmış bir boşluktur.

**Düzeltme:** Kapsam doğrulamasında okunamayan ağaç, maksimum derinlik/öğe sınırı, symlink belirsizliği -> `DENY` veya taranmayacak yolun OS seviyesinde kanıtlanmış dışlanması. Yarış durumları (TOCTOU) için salt-okunur izole mount ve farklı UID/namespace gerektir. Derinlik 13+, okunamayan dizin ve test esnasında değişen symlink için regresyon testleri eklenmeli.

### NEW-02 — P1 / Yüksek: Geçersiz CSP, `verified_fixed` sayılıyor

**Dosya:** `packages/scanner-core/src/index.ts`, `evaluateWebHeadersObserver()`, yaklaşık 224–285 satırlar; `packages/recheck-engine/src/index.ts` durum kararı.

**Kanıt:** Var olan patched sentetik fixture'daki `Content-Security-Policy` değeri **`totally-invalid-directive`** olarak değiştirildi. Sonuç:

```text
WEB-HEADER-001: positive_validation_passed = true
Recheck: recheck_state = verified_fixed
```

**Kök neden:** CSP değerinin yalnızca boş olmaması yeterli görülüyor. Tarayıcının uygulayabileceği geçerli ve savunma sağlayan bir CSP politikası olup olmadığı test edilmiyor.

**Düzeltme:** Ürün gerçekten CSP varlığını kontrol edecekse `verified_fixed` yerine `no_longer_observed` kullanmalı ve düzeltme kriterini sınırlı ifade etmeli. Anlamlı biçimde `verified_fixed` demek için CSP parser, geçerli enforcement kontrolü, tehlikeli direktiflerin değerlendirilmesi ve gerektiğinde insan incelemesi gerekiyor. Boş olmayan ancak geçersiz ve aşırı izinli politikalar için regresyon testleri ekle.

### NEW-03 — P1/P2 / Orta: Runtime rapor doğrulaması JSON Schema ile tutarsız

**Dosya:** `packages/findings-schema/src/index.ts`, `validateScanReportDocument`; `schemas/report.schema.json`.

**Kanıt:** Gerçek ve geçerli demo raporu kopyalanıp zorunlu `summary`, `started_at`, `scanner_version` alanları kaldırıldı; validator **`valid: true`** döndürdü. Başka bir denemede `coverage.request_count = -100` ve `coverage.max_request_budget = -1` atandı; yine **`valid: true`** döndü. `coverage.checks[0].asset_key` kaldırılınca da **`valid: true`** elde edildi. Bunların tamamı `report.schema.json` sözleşmesine göre geçersizdir.

**Düzeltme:** JSON Schema Draft 2020-12'yi gerçekten uygulayan validator kullan; `required`, `additionalProperties`, tür, `minimum`, format, iç içe nesneler ve çapraz alan tutarlılığını doğrula. Hem `valid` hem `invalid` corpus testleri ekle; SARIF için resmi SARIF 2.1.0 schema uyumluluğunu ayrıca doğrula. Güvenlik açısından müşteri raporuna yanlış güven işareti konmaması kritik.

## 4. Diğer eksikler ve operasyonel riskler

1. **P0 / Çıkış engelleyici:** Gerçek `restricted-remote` HTTP/TLS transport ve OS/konteyner seviyesinde izole egress kontrolü yok. Remote mode'u açma, önce gerçek negatif ağ politikası testleri.
2. **P1:** Semgrep/Trivy yerel binary çalışma doğrulaması, aracın sürüm/kurallar ve Trivy DB freshness kaydı, salt-okunur sandbox entegrasyonu eksik. Şimdiki fixture testleri bunu ispatlamıyor.
3. **P2:** CLI `help` sürümü `v0.1.0-alpha.1`; `package.json` sürümü `v0.1.0-alpha.2`.
4. **P2:** Kaynak dağıtım ZIP'i `node_modules/typescript` içeriyor; bunu açık kaynak kaynak dağıtımına dahil etme. `.gitignore` zaten node_modules'u dışlıyor. Ayrıca `package-lock.json` arşivde yok; sürüm kilidi ve `npm ci` için lockfile ekle.
5. **P2:** `package.json` içinde `private: true`. GitHub'da açık kaynak kod yayımlamaya engel değildir; ancak npm registry'ye yayımlamak istenirse paketleme ve `bin` çalışma şekli yeniden düzenlenmeli.

## 5. Öncelikli Antigravity görevleri / Kabul koşulları

**Görev A (P1) — Symlink fail-closed**
- Derinlik/okuma hatasında `safe:true` dönüşlerini kaldır. Karar verilemiyorsa ret.
- Yerel kaynak ağacında 13/20 seviyede symlink, okunamayan klasör, değişen symlink testleri ekle.
- Gerçek kaynağın okuyabileceği dosya kümesini OS/mount katmanında kısıtlayan worker tasarla.

**Görev B (P1) — CSP semantic recheck**
- Boş olmayan ama geçersiz CSP girdilerinde `verified_fixed` dönme.
- CSP kaynağı ve `positive_validation_passed` durumunu kontrollü fixture ile doğrula.
- Düzeltme derecesini gerçek gözlem ve politika güvenilirliğiyle uyumlu tut.

**Görev C (P1/P2) — Gerçek JSON Schema validator**
- Eksik `summary`, `started_at`, `scanner_version`; negatif request count; eksik check asset_key; ek alanları reddet.
- Rapor ve recheck dokümanlarını geçerli/bozuk corpus üzerinde test et.
- CLI'nin dışarı aktardığı raporları da çıktıdan önce doğrula.

**Görev D (P0, sonraki sürüm) — Safe remote transport / sandbox**
- İzinli hedef üzerinde OS-level egress gerçekten uygulanana kadar uzak tarama kapalı kalmalı.
- Gerçek ağ testlerini yalnızca sahip olunan/izni belgelenmiş hedef ya da izole fixture altyapısıyla yap.
- Gerçek Semgrep/Trivy binary'lerini izole, salt-okunur, kaynak limitli worker içinde çalıştır.

**Sürüm kabul kapısı:** Test kümesindeki mevcut 18 test korunacak; yeni negatif testler önce başarısız olacak, düzeltmeden sonra geçecek. `npm run lint`, `npm run typecheck`, `npm test`, `npm run demo` tamamlanacak. Test kanıtı ve eksik özellikler sürüm notunda dürüstçe belirtilecek.

## 6. Yargı

`alpha.2`, `alpha.1`'e kıyasla iyi bir mühendislik ilerlemesi. Çalışan CLI/demo ve önemli regresyon düzeltmeleri var. **Ancak bu hâliyle güvenlik ürünü olarak production'a çıkmamalı, gerçek müşteri kaynak kodları/test hedefleriyle kullanılmamalı.** Ağ izolasyonu, rapor doğruluğu ve izin kapsamı önce güvenilir hâle getirilmeli. Bu denetim gerçek üçüncü taraf internet sitelerini taramadı; bütün bağımsız negatif örnekler geçici klasörler ve yerel sentetik fixture'lar kullanılarak çalıştırıldı.
