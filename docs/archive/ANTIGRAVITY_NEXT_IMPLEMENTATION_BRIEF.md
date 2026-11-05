# Antigravity IDE — HegoSentinel sonraki uygulama görevi

## Rol ve sınır
HegoSentinel'in mevcut alpha.4 kod tabanında güvenlik mühendisliği ve çalışır izolasyon doğrulaması yap. Kaynak kodu olmadan uygulandı iddiasında bulunma. Mevcut veriyi koru; müşteri kodları, canlı hedefler ve üçüncü taraf servisleri test etme. `restricted-remote` modu, gerçek OS ağ izolasyonu kanıtlanana kadar KAPALI kalacak.

## İlk işlem: doğrulama
1. Git commit SHA, Node, npm, Docker Engine ve işletim sistemi sürümlerini kaydet.
2. Kod ağacında `apps/worker`, `generatePerRunNetworkPolicy`, `SimulatedNetworkNamespaceFirewall`, `signWorkerCapabilityAttestation`, `executeBoundedPassiveRequest` işlevlerini gerçek davranışlarına göre incele.
3. `npm ci --ignore-scripts`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run demo` çalıştır; gerçek terminal çıktısı ve exit code sun.
4. README'deki `38/38`, `44/44`, "11 paket" ve listelenen test dosyası sayısı farklarını gerçek test runner kayıtlarıyla düzelt.
5. Şu yetenekleri ayrı etiketle: `implemented`, `simulated`, `blocked`, `unverified`, `planned`.

## Sprint A: offline worker'ın gerçek izolasyonu (öncelik P0)
- Bir `source-offline` runtime manifest'i ve gerçek Docker test runner oluştur.
- Worker için non-root kullanıcı, no-new-privileges, cap_drop ALL, read-only root, yalnızca izinli repo :ro, network none, tmpfs scratch ve CPU/RAM/PID/timeout sınırlarını runtime'da uygula.
- Worker'a host Docker socket veya sır içeren bind mount verilmesin; git/npm/composer hooks ve build/install scriptleri çalıştırılmasın.
- README'den bağımsız doğrulanabilir WKR-001..WKR-006 testlerini ekle; eksik Docker ortamı `SKIP (not verified)` olsun, ASLA PASS olmasın.
- Worker çıkışı ve tüm alt süreçleri iptalde bitir; rapor `coverage` ve `tool_status` durumlarını doğru yansıtsın.

## Sprint B: remote-web egress tasarımı (P0, ilk sprintte etkinleştirme yok)
- `networkMode:none` altında HTTP'nin çalışmayacağını açıkça dokümante et. Offline ve remote profilleri ayır.
- Worker'a `CAP_NET_ADMIN` vermeden egress policy uygulayacak güvenilir, dışsal proxy/orchestrator tasarla.
- HMAC kanıtını kernel/network enforcement kanıtı olarak sunma. İmzalı grant'i trusted signer, run ID, target, scope version, expiry, nonce ve network policy id ile ilişkilendir. Replay/stale grant testleri ekle.
- Test laboratuvarında DNS rebinding, IPv4/IPv6 private ranges, redirect, metadata, proxy env, egress bypass ve cancel testlerini tanımla.
- Gerçek test kanıtı olmadan canlı taramayı kesinlikle aktif etme.

## Sprint C: gerçek tarama entegrasyonu (P1)
- Semgrep ve Trivy'nin sabitlenmiş, gerçek binary versiyonlarıyla ayrı local fixture koş; exit code, timeout, DB freshness ve version bilgilerini rapora koy.
- CSP, cookie, TLS ve re-test için eksik sınır testlerini ekle; `verified_fixed` durumunun pozitif kanıt ve karşılaştırılabilir endpoint gerektirdiğini koru.
- JSON Schema/SARIF çıktısını gerçek validator ile doğrula; sır sızıntısı, kısmi scan, atlanan kural ve hata durumlarını negatif testlerle değerlendir.

## Teslim raporu (zorunlu)
- Değişen dosya listesi, mimari ve nedenleri.
- Başarılı/başarısız/atlanan testlerin ayrı sayıları; kullanılan Docker/OS/Node sürümleri ve çalıştırma komutları.
- Gerçek negatif test sonuçları ve hash/attestation kanıtının güven sınırı.
- Her özellik için `implemented / simulated / blocked / unverified / planned` durum tablosu.
- Eksik testler ve kalan riskler; nerede ve neden DURULDUĞU.

**Kesin yasak:** güvenlik kontrollerini testleri geçirmek için gevşetmek; yetkisiz canlı tarama, mass scanning, brute force, exploit, destructive checks, prod DAST, müşteri kaynak kodu aktarımı, otomatik public GitHub issue veya dış AI'ya özel kod gönderimi.
