# Antigravity IDE — HegoSentinel güvenlik ve doğruluk düzeltme görevi

HegoSentinel `v0.1.0-alpha.1` kaynak kodunu düzenle. İnceleme raporu `HegoSentinel_Gercek_Kod_Denetimi_2026-11-04.md` dosyasındaki bulgular esas alınacak.

## 1. Önce düzeltilecek güvenlik ve doğruluk hataları

1. **Recheck yanlış `verified_fixed` sorunu:** `findMatchingCoverageCheck` fonksiyonu, `rule_id` aynı ancak `asset_key` farklıysa başkasının coverage'ını kullanamaz. Yalnızca aynı rule, asset, rule_version, profile ve uygun coverage karşılaştırması. `scope_version` ve `grant_id` değiştiğinde eşdeğerlik varsayma. Baseline `/old` CSP eksik, current yalnızca `/different-page` CSP mevcut senaryosunda `verified_fixed` ASLA üretilmesin.
2. **Kaynak kod kapsam ihlali:** `validateAuthorizedRepositoryPath` gerçek filesystem hedeflerini `realpath` ile kontrol etsin. İzinli dizinden izin dışı klasöre symlink varsa `denied` dönmeli. Yan etkisiz test fixture ekle. Path bazlı kontrolün tek başına security sandbox olmadığını dokümante et.
3. **TypeScript:** `tsc -p tsconfig.json --noEmit` komutunu gerçek CI typecheck olarak çalıştır. `RuleId` kullanılmayan import'u kaldır. Syntax check ile typecheck'i birbirine karıştırma.
4. **Node uyumluluğu:** `engines.node` beyanını ve komutları birbirine uydur. Gerçekten desteklenen en düşük Node sürümünde `npm run lint`, `npm run typecheck`, `npm test`, `npm run demo` tamamı ek bayrak olmadan çalışmalı veya bayrak/tsx ihtiyacı şeffaf biçimde belgelenmeli.

## 2. Kesinlikle yapılmaması gerekenler

- Mevcut güvenlik kısıtlarını gevşetme, gerçek müşterileri/üçüncü taraf hedefleri tarama.
- SSRF geçidini sahte boolean ile geçip canlı uzak tarama açma.
- Testsiz `verified_fixed` veya `production-ready` iddiası sunma.
- Repo içinden otomatik npm/composer kurulum ve build hook'ları çalıştırma.
- Sır, cookie değeri veya müşteri kodunu log/rapor/AI servisine gönderme.

## 3. Kabul kapıları

- Yeni adversarial testler önce başarısız olmalı, düzeltmeden sonra geçmeli.
- `14/14` mevcut testler korunmalı; yeni negatif testler eklendiği için test sayısı artmalı.
- Gerçek `tsc` ve CI matrisi çalışmalı.
- `docs/ROADMAP.md`, `README.md`, `CHANGELOG.md` ve sürüm/özellik matrisi güncel ve tutarlı olmalı.
- CLI yalnızca doğru yetkilendirilmiş kapsamda çalışmalı, demo offline olarak kalmalı.
- Son raporda değişen dosyaları, kullanılan komutları, gerçek test çıktısını, engellenen özellikleri ve kalan riskleri göster.

## 4. Sonraki sprint — mevcut P0 sorunları kapandıktan sonra

Doğrulanmış network isolation + gerçek DNS, socket peer-IP kontrolü + izinli local staging web server üzerinde canlı HTTP/TLS gözlemcileri; gerçek Semgrep/Trivy binary adaptör testleri; schema validator; ardından Laravel API + Next.js dashboard.
