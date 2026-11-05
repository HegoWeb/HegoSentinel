# HegoSentinel — Bağımsız Kaynak Kod ve Güvenlik Denetimi
**Denetim tarihi:** 4 Kasım 2026  
**İncelenen paket:** `HegoSentinel_Project_Documentation (2).zip`  
**İncelenen sürüm:** `0.1.0-alpha.1`  
**Kapsam:** Statik kaynak kod incelemesi, mevcut otomatik testleri yeniden çalıştırma, çevrimdışı demo, bağımsız olumsuz senaryolar. Üçüncü taraf üretim hedefi veya müşteri projesi test edilmedi.

## 1. Karar özeti

**Karar:** Gerçek ve kısmen çalışan bir alpha prototipi mevcut; müşteri ortamında kullanıma / production dağıtımına **henüz uygun değil**. 

- Kaynak kodu: **mevcut** (6 çekirdek TypeScript paketi, 2 tarayıcı adaptörü, CLI ve Node.js yerel web arayüzü).
- Tekrar yürütülen mevcut otomatik testler: **14/14 başarılı** (Node.js 22.16.0 + `NODE_OPTIONS=--experimental-strip-types` ile).
- Sentetik çevrimdışı demo: **başarılı**; CSP bulgusu `verified_fixed`, cookie bulgusu `persistent` olarak çıktı.
- Gerçek `tsc --noEmit` tip denetimi: **başarısız**, `TS6196` kullanılmayan `RuleId` import'u.
- Varsayılan `npm run lint` (Node.js 22.16): **başarısız**, `.ts` doğrudan çalıştırma desteği açık değil. `package.json` Node `>=22.6.0` diyor; CI Node 24 kuruyor.
- Gerçek hedef üzerinden HTTP/TLS alan taraması: **yok**; `executeScan` yalnızca `options.fixture?.endpoints ?? []` verisini dolaşıyor. Uzak mod, egress attestation kapısından geçse dahi gerçek HTTP/TLS isteği yapan bir transport uygulamıyor.
- Semgrep ve Trivy adaptörleri yazılmış; mevcut entegrasyon testi **sentetik çıktı** kullanıyor. Gerçek Semgrep/Trivy binary'leri bu denetim ortamında yoktu, bu nedenle gerçek tarama kalitesi doğrulanmadı.
- Laravel API / PostgreSQL / Next.js / SMTP / ZAP aktif test: **henüz yok**.

> `14/14 PASS` yalnızca mevcut testlerin geçtiğini gösterir; otomatik testlerin kapsamadığı güvenlik sınırlarını doğrulamaz.

## 2. Gerçekte geliştirilen modüller

| Bileşen | Kaynak dosya | Denetim değerlendirmesi |
| --- | --- | --- |
| Policy/izin, URL, IP, DNS ve yönlendirme doğrulaması | `packages/policy-engine/src/index.ts` | İşlevler var ve sentetik testlerden geçiyor. Ağ izolasyonu yok; attestation yapısı yalnızca boolean değerleri alıyor. |
| Web kontrol gözlemcileri | `packages/scanner-core/src/index.ts` | Dört gözlemci fonksiyonu var. Kaynakları gerçek ağdan toplamıyor. Header kontrolünde CSP esas alınmış; kapsam sınırlı. |
| Komut satırı | `packages/scanner-core/src/cli.ts` | `demo`, `scan`, `compare` komutları mevcut; bayraklı Node 22 ile çalıştı. |
| Yerel demo web arayüzü | `packages/scanner-core/src/server.ts` | Node HTTP sunucusu, localhost port 4173; gerçek ekip platformu değil. |
| Semgrep adaptörü | `integrations/semgrep/src/index.ts` | `execFile('semgrep')`, çıktı normalizasyonu var; gerçek binary ve isolation doğrulanmadı. |
| Trivy adaptörü | `integrations/trivy/src/index.ts` | `execFile('trivy')`, JSON normalizasyonu var; veritabanı güncelliği ve isolation doğrulanmadı. |
| Normalizasyon, standard eşlemesi | `packages/findings-schema/src/index.ts` | Tipler ve fingerprint fonksiyonları var; JSON Schema runtime validation bağlanmamış. |
| Çözüm rehberi | `packages/remediation-catalog/src/index.ts` | Kural-temelli Laravel/Next.js tavsiyeleri var. |
| Raporlama | `packages/report-engine/src/index.ts` | JSON, Markdown, HTML, SARIF 2.1.0 çıkışı var; SARIF'in resmi şemaya uygunluğu bağımsız doğrulanmadı. |
| Recheck | `packages/recheck-engine/src/index.ts` | Düzeltme karşılaştırma motoru var; yanlış pozitif `verified_fixed` hatası kanıtlandı. |

## 3. Kritik blokajlar / doğrulanmış problemler

### HS-AUDIT-001 — P0 — Farklı endpoint'teki başarılı test, eski endpoint'i `verified_fixed` yapıyor
**Dosya:** `packages/recheck-engine/src/index.ts:31-39`, `:167-169`, `:259-272`  
**Kanıt:** Sentetik baseline `/old` sayfasında CSP eksikliği buldu. Yeni tarama sadece `/completely-different-page` sayfasında CSP kontrolünü başarılı yaptı. Sonuç, **eski `/old` bulgusunu `verified_fixed` olarak işaretledi**. 
**Kök neden:** `findMatchingCoverageCheck()` eşleşen `rule_id + asset_key` bulamazsa yalnızca `rule_id` eşleşen farklı bir asset'in kapsamasını kabul ediyor. 
**Çözüm:** Bire bir asset eşleşmesi zorunlu olmalı; kapsam, grant/scope version, test profili, rule sürümü, check kapsamı ve endpoint ulaşılabilirliği kıyaslanmalı. Eksik endpoint otomatik `fixed` olmamalı; `not_comparable` veya `no_longer_observed` durumuna gitmeli. 
**Kabul testi:** `/old` CSP eksik + yalnızca `/new` CSP var senaryosu `verified_fixed` üretmemeli.

### HS-AUDIT-002 — P0 — İzinli repo klasörü sınırı symlink üzerinden aşılıyor
**Dosya:** `integrations/semgrep/src/index.ts:72-98` ve Trivy'nin aynı fonksiyonu kullanması (`integrations/trivy/src/index.ts:177`)  
**Kanıt:** `approved/linked → not-approved/` sembolik bağlantısı altında izin kontrol fonksiyonu `allowed:true` döndü. Test yalnızca geçici deneme klasörleri üzerinde yapıldı; gerçek müşteri dosyası okunmadı.
**Kök neden:** `path.resolve()` sözdizimsel yolu çözüyor ancak sembolik bağlantının gerçek hedefini çözmüyor. 
**Çözüm:** Allowlist ve hedef için `realpath()` ile fiziksel yol doğrulaması; taranan dosyaları ayrıca read-only mount + uygun container isolation altında sunma; symlink hareketi ve TOCTOU testleri.
**Kabul testi:** İzinli klasörün dışına işaret eden tüm symlink hedefleri reddedilmeli.

### HS-AUDIT-003 — P0 — Uzak tarama motoru fiilen yok
**Dosya:** `packages/scanner-core/src/index.ts:731-743`, `:882-936`, `:692-729`.
**Kanıt:** Default DNS resolver `93.184.216.34` değerini taklit ediyor; `endpoints` yalnızca fixture'dan geliyor. Gerçek HTTP isteği, TLS bağlantısı, timeout/transport ve gerçek soket peer doğrulaması entegre değil. 
**Çözüm:** İzinli hedefe gerçek HTTP/TLS yapan, socket peer doğrulaması gerçekleştiren ve ayrı ağ katmanında egress kısıtlaması bulunan worker. Uygun dış tarama ortamı olmadan bu kabiliyeti aktifleştirmemek doğru.
**Kabul testi:** Yalnızca geliştiriciye ait izole test sunucusunda gerçek TLS/HTTP gözlemleri; kapsam dışı ve private destination için sıfır istek/packet doğrulaması.

### HS-AUDIT-004 — P1 — Scope/grant sürümü değişse bile recheck karşılaştırılabilir kalıyor
**Dosya:** `packages/recheck-engine/src/index.ts:55-77`.
**Kanıt:** `scope_version=999` ve `grant_id=SOME-OTHER-GRANT` verilmiş current raporda `comparable:true`, durumlar `verified_fixed` ve `persistent` çıktı.
**Çözüm:** Mutlaka scope/grant sürümü, erişilen hedef kümesi, kural sürümü ve ağ/araç kapsam eşitliği; kontrollü değişikliklerde insan onayı/uyumluluk politikası.

### HS-AUDIT-005 — P1 — Gerçek TypeScript typecheck çalıştırılmıyor
**Dosya:** `package.json:26`, `scripts/lint-and-typecheck.ts:22-99`.
**Kanıt:** `npm run typecheck` custom script ile sözdizimi/some dynamic imports kontrol edip PASS verdi. Gerçek `tsc --noEmit` şu hatayla başarısız: `packages/policy-engine/src/index.ts(4,3): error TS6196: 'RuleId' is declared but never used.`
**Çözüm:** `tsc --project tsconfig.json --noEmit` gerçek typecheck komutu olmalı; ek security lint farklı script'te kalmalı. Kullanılmayan import silinmeli.

### HS-AUDIT-006 — P1 — Desteklenen Node sürümü ile varsayılan çalıştırma uyuşmuyor
**Dosya:** `package.json:8-9, 18-31`, `.github/workflows/ci.yml`.
**Kanıt:** Node 22.16.0 ile `npm run lint` ilk haliyle `ERR_UNKNOWN_FILE_EXTENSION: .ts`. Deneysel `NODE_OPTIONS=--experimental-strip-types` ile bütün testler geçti. CI Node 24 çalıştırıyor; tek sürümde test yapmak geriye dönük uyumluluk kanıtlamaz.
**Çözüm:** Minimum sürümü desteklenen gerçek Node sürümüne yükseltip CI matrisi oluşturma veya `tsx`/derlenmiş JS ile Node 22 uyumluluğu. CLI paketindeki `bin` TypeScript dosyasının yayın deneyimi ayrıca test edilmeli.

### HS-AUDIT-007 — P1 — Semgrep/Trivy read-only/sandbox iddiası kod seviyesinde doğrulanmıyor
**Dosyalar:** `integrations/semgrep/src/index.ts:249-262`, `integrations/trivy/src/index.ts:225-236`.
**Kanıt:** `execFile(shell:false)` ve zaman aşımı mevcut fakat konteyner mount izni, CPU/RAM/egress politikasını zorlayan bir runtime yok. PATH üzerinden binary seçimi, binary provenansı ve Trivy offline DB güncelliği için operasyonel kontroller gerekli.
**Çözüm:** Pinned binary/hash, sandbox worker, read-only mounts, no-new-privileges, ayrı egress sınırları, cache/db sürüm kaydı ve entegrasyon testleri.

### HS-AUDIT-008 — P2 — Şema ve çıktı doğrulaması sınırlı
**Dosyalar:** `scripts/lint-and-typecheck.ts:75-87`, `tests/integration/adapters-and-reports.test.ts`.
**Kanıt:** JSON Schema'lar yalnızca JSON parse edilerek kontrol ediliyor; gerçek raporun şemaya uygunluğu veya SARIF 2.1.0 resmi validator'ıyla eşleşmesi gösterilmiyor.
**Çözüm:** Rapor ve yetki belgelerini sürümlenmiş JSON Schema validator'ıyla runtime/CI doğrulama; SARIF validasyon testi.

### HS-AUDIT-009 — P2 — Doküman / tanıtım iddiaları düzeltilmeli
**Dosyalar:** `AGENT_IMPLEMENTATION_BRIEF.md`, `docs/ROADMAP.md`, `roadmap.md`, `README.md`, Workbench arayüzü.
**Gözlem:** Eski brief hâlâ `documentation only` diyor; yeni README çalışan alpha diyor. Yerel demo ekranındaki `GATE G0 + G1 PASS`, gerçek canlı remote tarama izolasyonu kanıtı olarak anlaşılmamalı. 
**Çözüm:** Tek `docs/ROADMAP.md`, sürüm bazlı CHANGELOG, `implemented / mocked / planned` matrisi ve kapsam dipnotları.

## 4. Test bulgularının anlamı

- **Başarılı:** `14/14` mevcut Node testleri, CLI fixture demo, JSON/Markdown/HTML örnekleri, synthetic recheck akışı, olumsuz fixture testleri.
- **Başarılı olmayan:** Kullanıcının vaat edilen minimum Node aralığında varsayılan komutlar; gerçek `tsc` kontrolü.
- **Doğrulanmamış:** Gerçek DNS, IP pinning soket katmanı, production SSRF izolasyonu, gerçek Semgrep/Trivy ikili çalıştırma, sertifikalı pentest, gerçek web hedef analizi, kaynak kodunun üçüncü taraf sandbox isolation.

## 5. Yapılacaklar (sıralı)

1. P0: `findMatchingCoverageCheck` kural+asset birebir eşleşmesini zorunlu yap; baseline/current endpoint farkı testini ekle.
2. P0: Kaynak kodu yol kontrolünü `realpath` + symlink negatif testiyle düzelt; tarayıcı sandbox politikalarını ekle.
3. P1: `scope_version`, grant/scope değişikliği ve check kapsamı karşılaştırmasına zorunlu karşılaştırılabilirlik denetimi ekle.
4. P1: Gerçek TypeScript compiler'ı CI'a ekle; Node sürüm politikasını düzelt.
5. P1: Ağsız demo ile gerçek ağ taramasının yeteneklerini ayrı olarak etiketle; gerçek uzak taramayı ancak ağ çıkış doğrulama katmanı hazır olunca aç.
6. P1: Gerçek Semgrep/Trivy çalıştırma ve izolasyon entegrasyon testlerini ekle; veritabanı freshness ve scanner version metadata kaydet.
7. P2: JSON Schema ve SARIF validator testleri; negatif gizlilik fixture'larını genişlet.
8. P2: Güncel roadmap/README/Changelog/GitHub dökümantasyonunu eşitle.
9. Sonraki sürüm: Gerçek izolasyon + izinli hedefler kanıtlandıktan sonra Laravel/PostgreSQL API, Next.js UI, bildirimler ve staging-only kontrollü DAST.

## 6. Son değerlendirme

**HegoSentinel iyi düşünülmüş, gerçek kod içeren ve sentetik senaryolarda çalışan bir alpha çekirdeğidir.** Tek başına tüm güvenlik açıklarını bulan veya otomatik pentest yapan bir araç değildir. Ürünü açık kaynak olarak tanıtmak mümkün olsa da müşteri kaynak kodlarıyla ya da production hedeflerle kullanmadan önce P0'lar kapatılmalı ve gerçek hedef/network izolasyon testleri bağımsız olarak yapılmalıdır.
