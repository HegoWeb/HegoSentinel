# HegoSentinel alpha.4 — Bağımsız Kod Denetimi ve Geliştirme Raporu

**Kaynak:** Kullanıcının 4 Kasım 2026 tarihli `(5).zip` arşivi. İncelenen sürüm: `0.1.0-alpha.3` + önceki denetim yamaları.

## Başlangıç doğrulaması
- Node.js `v22.16.0` üzerinde `npm run lint`, `npm run typecheck`, `npm test`, `npm run demo` başarıyla çalıştı.
- Önceki sürümde test sonucu **26/26 PASS** idi; çalışan demo yalnızca çevrimdışı sentetik örnekleri kullanıyor.
- Canlı uzak tarama, gerçek egress sandbox doğrulanmadığından kapalı. Semgrep ve Trivy adaptörleri var; üçüncü taraf binary uçtan uca çalıştırılması bu denetimde yapılmadı.

## Yeni bulunan ve düzeltilen riskler

### AUD-06-A / HIGH: Başka çereze dayanarak yanlış `verified_fixed`
Eski `WEB-COOKIE-001` yalnızca aynı URL üzerinde **herhangi** bir güvenli çerez varsa `positive_validation_passed=true` yapabiliyordu. Başlangıçtaki `auth_session` kaybolup yerine `new_cookie` gelmesi eski sorunu düzeltilmiş göstermemelidir.

**Düzeltme:** Tarayıcı ilgili çerez adına göre tenant/proje/rule/asset kapsamlı SHA-256 bulgu parmak izini `positive_validation_fingerprints` alanına ekliyor. Recheck yalnızca eski bulgunun aynı parmak izine ait pozitif kanıtı olduğunda `verified_fixed` üretiyor. Eski raporların bu kanıtı yoksa `no_longer_observed` kalır. Çerez değerleri bu alanda tutulmuyor.

### AUD-06-B / MEDIUM: Geçersiz `SameSite` kabulü
Eski ayrıştırıcı `SameSite=Unknown` gibi ifadeleri gerçek tarayıcı tarafından uygulanabilir politikaymış gibi kabul ediyordu.

**Düzeltme:** Sadece `Lax`, `Strict`, `None` geçerli sayılıyor; eksik veya geçersiz değer gözlem olarak kalıyor.

### AUD-06-C / HIGH: CSP'de eksik semantik denetim
`default-src *; default-src 'self'` gibi birleştirilmiş tekrarlar veya `default-src 'self'; script-src-elem *` gibi kurallar, bir tarayıcıdaki gerçek etkin politikayı yanlış yorumlatabiliyordu.

**Düzeltme:** Tekrarlanan direktifler ve virgülle birleştirilmiş çoklu politikalar pozitif kanıt sayılmıyor. `script-src-elem` aşırı genişse de otomatik `verified_fixed` engelleniyor. Bu hâlâ tam bir W3C CSP doğrulayıcısı değildir.

## Yapılan kod değişiklikleri
- `packages/scanner-core/src/index.ts`: CSP ve SameSite, kimliğe bağlı çerez kanıtı.
- `packages/recheck-engine/src/index.ts`: cookie-fingerprint bazlı pozitif doğrulama.
- `packages/findings-schema/src/index.ts`, `schemas/report.schema.json`: yeni isteğe bağlı kanıt alanı ve çapraz alan kontrolü.
- `tests/security/cookie-csp-identity-regression.test.ts`: 6 yeni sınama (4 tanesi eski sürümde başarısız olacak şekilde yeniden üretildi).
- `package.json`, `package-lock.json`, `README*`, `CHANGELOG.md`, `docs/ROADMAP.md`: sürüm ve kapsam belgeleri güncellendi.

## Test sonucu
- Başlangıç: **26/26 PASS**.
- Düzeltilmeden önce altı yeni testin **4'ü FAIL** idi.
- Düzeltmeden sonra: **32/32 PASS**; lint, gerçek `tsc` typecheck ve çevrimdışı demo başarılı.

## Kalan işler (öncelik)
1. **P0:** İzole, egress firewall doğrulanmış worker. Gerçek hedef erişimini açmadan ağ düzeyi testleri ve yetki bağlamı doğrulanmalı.
2. **P0:** Tarayıcı adaptörleri için salt-okunur konteyner ve gerçek dosya-sistemi izolasyonu. Yol doğrulaması tek başına sandbox değildir.
3. **P1:** Semgrep/Trivy kurulu binary ve kural/veri tabanı sürümüyle entegrasyon testleri.
4. **P1:** CSP semantiğini ve pozitif düzeltme iddialarını tarayıcı farklarına göre ayrıca inceleme, false-positive senaryoları.
5. **P2:** Laravel API, PostgreSQL multi-tenant, Next.js panel, rapor teslimi ve onaylı bildirimler.
6. **P3:** İnsan onaylı staging DAST, ZAP ve yetkilendirme matrisleri.

**Not:** Alpha.4, önceki ZIP'e uygulanan yerel bir geliştirme/sürüm tanımıdır; production-ready veya tam sızma testi ürünü değildir.

## Dağıtım doğrulaması ve sınırlamalar
- `package-lock.json`, monorepo workspace tanımları ile yeniden eşitlendi. Eski dosya temiz `npm ci` sırasında eksik workspace girdileri veriyordu.
- Kaynak ZIP ayrı bir dizine çıkarıldı; `npm install --package-lock-only --offline` başarılı. Çıkarılan kaynakta 32 test, çevrimdışı demo ve mevcut kurulu TypeScript derleyicisi kullanılarak `tsc --noEmit` başarılı.
- **Sınır:** Bu çalışma ortamında TypeScript 5.9.3 tarball'ı npm önbelleğinde bulunmadığından tamamen temiz `npm ci --offline` kurulumu doğrulanamadı. İnternet erişimli makinede `npm ci --ignore-scripts` ayrıca çalıştırılmalı.
- `.patch` dosyası orijinal kullanıcı ZIP'ine karşı `git apply --check` ile doğrulandı.
- `node_modules`, üretilmiş raporlar ve müşteri verileri dağıtım ZIP'ine dahil edilmedi.

**Takip edilecek diğer konu (Revizyon ile Tamamlandı):** Yerel Workbench sunucusundaki POST gövdesi okuma boyutu, Host/Origin kontrolleri ve CSP `unsafe-inline` kullanımı ile RFC 6265bis `__Host-`/`__Secure-` çerez önekleri ve `script-src-attr` CSP kontrolleri aşağıdaki revizyon ile çözüldü ve test altına alındı.

---

## Alpha.4 Revizyonu — Ek Güvenlik ve Doğrulama Sertleştirmeleri (38/38 PASS)

Denetim raporunun 56. satırında ve `HegoSentinel_alpha4_Sonraki_Gelistirme_Talimati.md` belgesinde işaret edilen açık noktalar aynı gün içinde revize edilerek kod tabanına ve regresyon testlerine eklendi:

1. **Yerel Workbench Sunucusu Sertleştirmesi (`packages/scanner-core/src/server.ts`):**
   - **Loopback `Host` ve `Origin` / `Sec-Fetch-Site` Doğrulaması (`validateLoopbackRequest`):** Yalnızca `localhost`, `127.0.0.1` ve `[::1]` Host başlıklarına izin verilir; DNS rebinding veya dış kaynaklı (`Origin` / `Sec-Fetch-Site: cross-site`) `POST` istekleri HTTP `403 Forbidden` ile reddedilir.
   - **Sınırlı Gövde Okuma ve Katı JSON Ayrıştırma (`readJsonBody`):** `MAX_WORKBENCH_POST_BYTES = 16384` (16 KB) sınırı getirildi; aşım durumunda HTTP `413 Payload Too Large`, bozuk JSON veya nesne olmayan gövdelerde sessiz `{}` yerine HTTP `400 Bad Request` döndürülür.
   - **`'unsafe-inline'` İçermeyen Enforcing CSP (`WORKBENCH_CSP_HEADER`):** Satır içi `<style>`, `<script>` ve `style="..."` öznitelikleri kaldırılarak `/workbench.css` ve `/workbench.js` uç noktalarına taşındı. Workbench kendi `evaluateCspPolicySemantics` denetiminden `positiveValidationPassed: true` (`enforcing`) olarak geçmektedir.
2. **Genişletilmiş Çerez ve CSP Semantiği (`packages/scanner-core/src/index.ts`):**
   - **RFC 6265bis `__Host-` ve `__Secure-` Önek Kuralları:** `__Host-` önekli çerezlerde `Secure`, `Path=/` ve `Domain` bulunmaması şartı; `__Secure-` önekli çerezlerde `Secure` şartı ve tekrarlanan `SameSite` özniteliklerinin reddi eklendi.
   - **`script-src-attr` CSP Denetimi:** `default-src 'self'; script-src-attr 'unsafe-inline'` gibi satır içi olay yöneticisi izinleri pozitif doğrulamayı (`positive_validation_passed: false`) engeller.
3. **Güncel Test Sonucu:**
   - `tests/security/cookie-csp-identity-regression.test.ts` dosyasına 6 yeni regresyon testi eklendi (toplam **12 test**, tüm repoda **9 suite / 38/38 PASS**).
