# HegoSentinel — alpha.4 Sonrası Bağımsız Tasarım İncelemesi ve Mühendislik Yol Haritası

**Tarih:** 4 Kasım 2026  
**İnceleme girdisi:** `Yapıştırılan markdown.md` (geliştirme ekibinin durum raporu).  
**Kanıt sınırı:** Bu incelemede güncel `apps/worker` kaynak kodu, Docker yapılandırmaları, ham test çıktıları ve çalışır bir konteyner teslim edilmemiştir. Buradaki "yapıldı" ifadeleri kaynak belgenin beyanlarıdır; bağımsız çalışma doğrulaması değildir.

## 1. Mevcut durum

Rapora göre önceki alpha.4 çekirdeğine şu çalışmalar eklenmiş:
- Yerel Workbench için `Host`, `Origin`, JSON gövde boyutu ve CSP sertleştirmesi.
- `apps/worker` (Dockerfile, yapılandırma, seccomp profili, ağ politikası şablonu ve TypeScript worker giriş noktası).
- `generatePerRunNetworkPolicy` ile `nftables` kural üretimi.
- `SimulatedNetworkNamespaceFirewall` ile simüle engelleme kontrolleri.
- `signWorkerCapabilityAttestation` / `verifyWorkerCapabilityAttestation` ile HMAC tabanlı yetenek kanıtı.
- `executeBoundedPassiveRequest` ile sınırlı HTTP GET/HEAD yürütücüsü.
- Semgrep ve Trivy için alt süreç sınırları ve DB tazelik denetimleri.
- Rapora göre 44/44 test sonucu.

**Önemli:** Bir firewall kuralının oluşturulması, onun çekirdek/namespace seviyesinde uygulandığı anlamına gelmez. `SimulatedNetworkNamespaceFirewall` bir güvenlik kabul testi değildir. HMAC imzası yalnızca güvenilen bir üreticinin doğru bilgiyi imzaladığını gösterebilir; gerçek ağ izolasyonu veya container güvenliğini tek başına ispatlamaz.

### Belgelerdeki tutarsızlıklar
1. Üst sürüm açıklaması `38/38`, bölüm 5 `44/44` diyor. Tek bir kanonik CI run ID/commit SHA ve test sayısı kullanılmalı.
2. Aşama 6'da "11 test paketi" iddiası geçerken test tablosunda sekiz dosya listeleniyor. Toplam test sayısı ile test dosyası/paketi sayısı ayrı tutulmalı.
3. Worker mimarisi `networkMode: none` diyor; bu doğru **offline yerel tarama** profili için, fakat **uzak HTTPS incelemesi** için farklı, kanıtlanmış ağ sınırına ihtiyaç var.
4. UI'daki simülasyonların başarı sonuçları gerçek bir internet hedefinin test edildiği gibi sunulmamalı.
5. Zero tracker / katı CSP, tek başına KVKK veya GDPR uyumluluğunun kanıtı değildir.

## 2. P0 — G0.5: Gerçek izole local source-scanner worker

**Amaç:** Yerel repo SAST/SCA çalışırken tarayıcı asla host dosyalarına, sırlara veya ağa erişemesin.

### Uygulama
- Ayrı bir `source-offline` çalışma profili oluştur. Container: `--network=none`, non-root UID, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, sürümlenmiş seccomp, `--pids-limit`, CPU/memory/time limit. Yalnızca izinli repo salt-okunur mount; temiz `tmpfs` scratch (noexec/nosuid mümkünse); Docker socket ve host system mounts yasak.
- `docker run` parametreleri ve compose/policy belgelerinin **çalışan runtime'da** etkin olduğunu `docker inspect` ve negatif testlerle doğrula.
- SAST/SCA alt süreçlerini yalnızca allowlist edilmiş sabitlenmiş binary digest ile başlat. Projedeki hook/script/build/install dosyalarını yürütme.
- Temiz kapanış: `SIGTERM`, süre dolunca `SIGKILL`, çocuk süreçler dahil. Artefakt saklama ve temp temizliği.
- Devasa dizinlerde doğrulama maliyetini azaltan güvenli seçici/yürüyücü; symlink/junction, sınır ve TOCTOU kontrolleri korunmalı.

### G0.5 kabul testleri
| ID | Deneme | Geçiş şartı |
|---|---|---|
| WKR-001 | Worker içinden dış DNS, HTTPS, metadata, iç ağ | Bağlantı yok; her deneme reddediliyor |
| WKR-002 | `/var/run/docker.sock` ve host secrets erişimi | Hiçbir erişim yok |
| WKR-003 | Salt-okunur repo ve root FS üzerinde yazma | Reddediliyor; yalnızca izinli tmpfs yazılabilir |
| WKR-004 | Kötü amaçlı symlink/junction ve path traversal | Kapsam dışı dosya okunmuyor |
| WKR-005 | CPU / RAM / PID / wall-clock sınırları | Container ve çocuk süreçler sınırlandırılıyor/sonlandırılıyor |
| WKR-006 | Semgrep/Trivy yok, çöküyor veya DB stale | `skipped`/`failed`/`completed_with_gaps`; asla güvenli/temiz olarak işaretlenmiyor |

**Kapı:** Bu kontroller gerçek Docker runtime'da gözlenmeden G0.5 tamamlandı denmesin.

## 3. P0 — G0.6: Uzak hedef için ayrı güvenli egress mimarisi

**Mimari kararı:** Source-offline worker asla ağ erişimi kazanmayacak. Remote-web worker, açık kapsam doğrulamasına ve **bağımsız ağ erişim arabulucusuna** ihtiyaç duyar.

Önerilen güven sınırı:
```
[İzin ve Scope API] -> [Kısa ömürlü signed grant] -> [Job Scheduler]
   -> [Remote-web worker (non-root, no NET_ADMIN)]
   -> [Trusted egress broker/proxy + host-level network policy]
   -> [yalnızca izinli public IP ve TCP portları]
```
- `nftables` uygulamasını worker'a `NET_ADMIN` vererek yapma. Politika bağımsız, dar yetkili host orchestrator veya güvenli egress broker tarafından uygulanmalı.
- Grant `run_id`, `project_id`, `scope_version`, hedef host/port/path, GET/HEAD, test penceresi, maksimum istek bütçesi, expiry, nonce ve emergency stop bilgilerine bağlanmalı.
- Kullanıcının sağladığı HMAC imzası/boolean/attestation asla otorite olmamalı; imzalayan servis yalnızca doğrulanmış kontrollerin ardından kısa ömürlü grant vermeli. Replay, stale grant ve grant substitution negatif testleri şart.
- URL/DNS doğrula, A/AAAA tüm adreslerini değerlendir, IP sabitle, TLS `Host`/SNI/sertifika hostname doğrulamasını koru; gerçek bağlanan IP'yi doğrula; yönlendirme başına scope tekrar değerlendir. IPv4/IPv6, NAT64, metadata ve env proxy kaçışlarını ağ sınırında engelle.
- GET/HEAD dışı yöntem yok, kimlik bilgisi taşınması yok, derin crawl yok, request concurrency / response size / timeout / redirect sayısı sınırlı. Kill switch her aktif bağlantıyı ve çocuk süreci kesmeli.
- DNS rebind, yönlendirme, IPv6, bağlantı yarışı, proxy bypass, konteynerden iç ağa istek, iptal sonrası istek yokluğu için **gerçek network namespace / veth / broker testleri** yaz.

**Kapı:** En az bir gerçek izolasyon negative-test matrisi (ci runner veya kontrol edilen staging) sunulmadan `restricted-remote` modu aktifleştirilmesin.

## 4. P1 — Tarama kalitesi, kanıt ve rapor

- Gerçek binary Semgrep/Trivy entegrasyon testi; imza/digest/sürüm pin ve SBOM; Trivy DB yaşına göre `stale/unknown` ayrı göster.
- HTTP/TLS taraması ve CSP/çerez doğrulaması için pozitif/negatif fixture dizisi: çoklu CSP başlığı, `report-only`, HTML olmayan yanıt, 401/403/404, redirect, sertifika chain, yanlış hostname, TLS handshake error.
- `verified_fixed` yalnızca aynı fingerprint + karşılaştırılabilir ve **pozitif doğrulanmış** koşul için mümkün. `no_longer_observed` güvenli değildir. Scope/grant, hedef, scan profile, kural sürümü ve coverage eşleşmeli.
- Tam JSON Schema ve gerçek SARIF 2.1.0 validator ile karşılıklı fixture testleri; raporlar sır, çerez ve ham özel kod içermemeli. Tool unavailable ve partial coverage saklanmamalı.
- Re-test sonucu karşılaştırmalarında source scanner DB version ve rulepack version drift'i açıkça belirt.

## 5. P2 — Laravel + Next.js platformu (yalnızca G0.5/G0.6 sonrası)

- Multi-tenant model ve explicit RBAC; her tablo ve artefakt API'sinde tenant boundary testi (`SEC-011`).
- İzin ve kapsam sürümlemesi; at-rest encryption, erişim kontrolü, retention; audit kayıtlarının tamper evident olması isteniyorsa hash chain + ayrı depolama.
- İşçi kuyrukları için iptal/timeout/retry/backoff/idempotency/dead-letter; hiçbir scan doğrudan API konteynerinde çalışmamalı.
- Next.js ekranları: yetkili varlık envanteri; kapsam/consent; tarama ve kapsama; bulgular; çözümler; karşılaştırma; rapor ve incelemeci onayları.
- SMTP ve GitHub issue'lar varsayılan kapalı, yetkili alıcı ve insan onayı zorunlu. Public issue'da açık detay yok.

## 6. P3 — Controlled DAST

Ayrı staging onayı, test hesapları, hız ve istek bütçesi, sağlık kontrolü, iptal ve insan incelemesi olmadan ZAP aktif testlerini açma. Bu, otomatik tam pentest iddiası değildir.

## 7. Sıralı geliştirici teslimatı

1. **Şimdi:** Geliştirme durumunu doğrula; kod, Docker image ve test çıktısını kontrol et, rapor tutarsızlıklarını düzelt.
2. **Sprint A:** `source-offline` worker'ı gerçek runtime'da ayağa kaldır; WKR-001..006 koşullarını geç.
3. **Sprint B:** `remote-web` egress mimarisi ve gerçek ağ negatif testleri; HMAC attestation bağlamını ve güven sınırını düzelt.
4. **Sprint C:** Tam tarama fixture, Semgrep/Trivy gerçek binary, JSON/SARIF ve re-test kalite matrisi.
5. **Sprint D:** Laravel/Next.js çok kiracılı platform ve onaylı bildirimler.
6. **Sprint E:** Ayrı izinli staging DAST.

**Yayın kriteri:** README her yeteneği `implemented / simulated / unverified / planned` olarak işaretlemeli. CI'nin en son `commit SHA`, Node/OS/Docker sürümleri, test komutları ve ham çıktıları eklenmeli. `44/44 PASS`, gerçek kernel izolasyonunun veya güvenli canlı taramanın kanıtı değildir.
