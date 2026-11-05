# HegoSentinel (`v0.1.0-alpha.4` + Kanıt Doğruluğu ve Workbench Sertleştirmesi) — Neler Yapıldı, Frontend Mimarisi ve Neler Yapılacak Kapsamlı Raporu

**Tarih:** 4 Kasım 2026  
**Sürüm:** `v0.1.0-alpha.4` (`AUD-06-A/B/C` + Sprint A/B/C + Trusted Egress Broker + All Security Gates Verification Kit: `8` Test Dosyası, `12` Suite, `60` Toplam Test -> `53 PASS` / `7 SKIP (not verified)` / `0 FAIL`; `verify:gates` -> `20 PASS` / `6 SKIP (not verified)` / `0 FAIL`)  
**Proje:** HegoSentinel — Geliştirici Odaklı, Self-Hosted Güvenlik Değerlendirme, Kanıt Normalizasyonu, Çözüm Rehberi ve Yeniden Test (Re-Test) Platformu  
**Temel Mühendislik İlkesi:** *Yetki yoksa tarama yok (`No authorization -> no scan`); güvenli ağ çıkışı yoksa uzak tarama yok (`No safe egress -> no remote scan`); kanıt yoksa zafiyet iddiası yok (`No evidence -> no vulnerability claim`).*

---

## 1. Yönetici Özeti

HegoSentinel projesi başlangıçta yalnızca mimari tasarım ve tehdit modeli dokümanlarından oluşuyordu. Bugüne kadar yürütülen mühendislik ve bağımsız denetim turlarıyla:

1. **Aşama 1 (`v0.1.0-alpha.1` — Çekirdek Monorepo ve Yerel Frontend Workbench İnşası):** Sıfır çalışma zamanı bağımlılığına (`0 runtime npm dependencies`) sahip 6 çekirdek TypeScript paketi, 2 yerel SAST/SCA adaptörü (`Semgrep` ve `Trivy`), 4 JSON Schema kontratı, komut satırı aracı (`CLI`), **etkileşimli yerel Frontend Workbench arayüzü (`http://localhost:4173`)**, bağımsız çevrimdışı HTML rapor arayüzü ve temel güvenlik/birim/entegrasyon/E2E test süiti sıfırdan inşa edildi.
2. **Aşama 2 (`v0.1.0-alpha.2` — 1. Bağımsız Kod Denetimi & Sıkılaştırma):** İlk bağımsız denetim raporunda (`HegoSentinel_Gercek_Kod_Denetimi_2026-11-04.md`) tespit edilen **9 bulgunun tamamı (`HS-AUDIT-001` .. `HS-AUDIT-009`)** TDD disipliniyle kapatıldı; gerçek TypeScript derleyicisi (`tsc --noEmit`, TypeScript `5.9.3`) devreye alındı (`18/18` test).
3. **Aşama 3 (`v0.1.0-alpha.3` — 2. Bağımsız Denetim & Derinleştirilmiş Semantik Doğrulama):** `HegoSentinel_alpha2_Bagimsiz_Denetim_2026-11-04.md` raporunda tespit edilen **3 yeni sınır vakası (`NEW-01`, `NEW-02`, `NEW-03`)** ve operasyonel sürüm/lockfile (`package-lock.json`) hijyeni eksikleri kapatıldı (`21/21` test).
4. **Aşama 4 (`AUD-2026-01` .. `05` — 3. Bağımsız Sınır Denetimi Yamaları):** `docs/SECURITY_AUDIT_2026-11-04.md` kapsamında tespit edilen **5 ek sınır/güvenilirlik senaryosu (`AUD-2026-01` .. `AUD-2026-05`)** kapatıldı (`26/26` test).
5. **Aşama 5 (`v0.1.0-alpha.4` — 4. Bağımsız Denetim, Kanıt Doğruluğu & Yerel Workbench Sertleştirmesi):** `HegoSentinel_alpha4_Denetim_Raporu_TR.md` ve `HegoSentinel_alpha4_Sonraki_Gelistirme_Talimati.md` kapsamında **`AUD-06-A`** (çerez parmak izi kanıtı: `positive_validation_fingerprints`), **`AUD-06-B`** (katı `SameSite` + RFC 6265bis `__Host-`/`__Secure-` çerez önek kuralları), **`AUD-06-C`** (tekrarlanan CSP direktifleri, virgüllü politikalar ve `script-src-elem`/`script-src-attr` ezmeleri) ve **Yerel Workbench sertleştirmesi** (`Host`/`Origin` loopback doğrulaması, 16 KB `POST` sınırı `413`, bozuk JSON `400`, `/workbench.css` + `/workbench.js` ayrımı ile `'unsafe-inline'` içermeyen CSP) tamamlandı (`38/38` test).
6. **Aşama 6 (Sprint A / B / C — `apps/worker` İzolasyon Manifestosu, Kısa Ömürlü İmzalı Çalıştırma İzinleri, Alt Süreç Sınırları ve Dürüst `SKIP (not verified)` Matrisi):** `ANTIGRAVITY_NEXT_IMPLEMENTATION_BRIEF.md` ve `INDEPENDENT_REVIEW_AND_ROADMAP_TR.md` doğrultusunda:
   - **`source-offline` (`G0.5`) ve `remote-web` (`G0.6`) Mimarileri Ayrıldı:** `source-offline` profili `--network=none` kullandığından bu profilde HTTP çalışamaz; `buildDockerRunArgsForSourceOffline` (`apps/worker/source-offline-manifest.json`) ayrıcalıksız (`65532:65532`), salt-okunur (`--read-only`, `:ro` repo), `--cap-drop=ALL` ve sıfır ağlı konteyner argümanlarını üretir ve `docker.sock` / `.ssh` / sır / proxy ortam değişkenlerini reddeder.
   - **Dürüst Çalışma Zamanı Raporlaması (`SKIP (not verified)`):** Test makinesinde (`Windows NT 10.0.26200.0`) Docker Engine veya `semgrep` / `trivy` ikilileri kurulu olmadığında `WKR-001`..`WKR-005` konteyner çalışma zamanı testleri ve gerçek ikili probları **asla sahte `PASS` dönmez**, `t.skip('SKIP (not verified): ...')` ile dürüstçe raporlanır.
   - **Kısa Ömürlü İmzalı `SignedRemoteExecutionGrant` ve `NonceReplayRegistry` (`G0.6`):** İşçiye `CAP_NET_ADMIN` vermeden harici Trusted Egress Broker mimarisi için güvenilir `signer_id`, `TTL <= 300s`, tek kullanımlık `nonce` (replay koruması), proje/kapsam/hedef bağlaması (grant substitution koruması) ve temiz proxy ortamı (`validateCleanProxyEnvironment`) doğrulandı. HMAC imzalarının yalnızca kontrol düzlemi yetki bütünlüğünü kanıtladığı, çekirdek/netns güvenlik duvarı kanıtı olmadığı açıkça belgelendi. Canlı `restricted-remote` modu **`blocked` (`fail-closed`)** tutuldu.
   - **Worker Dışı `TrustedEgressBroker` (`apps/egress-broker/src/index.ts`, `EGR-001`..`006`), Tamamlanan `SEC-001`..`014` Matrisi ve All Security Gates Verification Kit (`npm run verify:gates`):** Worker dışında çalışan, deny-by-default (`DROP`) ağ politikası (`PerRunNetworkPolicy`), `SignedRemoteExecutionGrant` doğrulaması, `EmergencyStopRegistry` (`SEC-012`), bağımsız DNS çözümü + SSRF/DNS-rebind/redirect engeli, kimlik bilgisi başlığı temizliği (`Authorization`, `Cookie`, `Proxy-Authorization`, `X-Forwarded-For`) ve SHA-256 hash-zincirli denetim günlüğü (`verifyAuditLogIntegrity`) uygulayan `TrustedEgressBroker` geliştirildi. Çok kiracılı RBAC izolasyonu (`SEC-011`) ve dış bildirim koruması (`SEC-013`) eklendi; `scripts/verify-all-security-gates.ts` ve `scripts/linux-docker-verify.sh` entegre edildi.
   - **Sonuç:** **8 test dosyasında (12 `describe` süiti, toplam 60 test)** **`53 PASS`, `7 SKIP (not verified)` ve `0 FAIL`** elde edildi.

---

## 2. Yetenek Durum Tablosu (`implemented` / `simulated` / `blocked` / `unverified` / `planned`)

| Bileşen / Yetenek | Durum Etiketi | Teknik Açıklama ve Güven Sınırı |
| :--- | :---: | :--- |
| **Kapsam, Yazılı İzin, Zaman Penceresi, SSRF, IPv4/IPv6 & DNS Pinning ([`packages/policy-engine`](../../packages/policy-engine/src/index.ts))** | `implemented` | `validateScopeAuthorizationGrant`, `classifyIpAddress`, `resolveAndPinDestination`, `verifyConnectedSocketPeer` (`SEC-001`..`004`). |
| **Kısa Ömürlü İmzalı Çalıştırma İzni (`SignedRemoteExecutionGrant`) & Replay Koruması ([`apps/worker`](../../apps/worker/src/index.ts))** | `implemented` | Güvenilir `signer_id`, `TTL <= 300s`, `NonceReplayRegistry`, hedef/proje/`scope_version` bağlaması ve proxy ortam değişkeni (`HTTP_PROXY` vb.) reddi. **Not:** HMAC imzası çekirdek/netns izolasyonu kanıtı değildir. |
| **`source-offline` Konteyner Politikası & `docker run` Argüman Üreticisi (`G0.5`)** | `implemented` | [`apps/worker/source-offline-manifest.json`](../../apps/worker/source-offline-manifest.json) + `buildDockerRunArgsForSourceOffline` (`--network=none`, `--read-only`, `--cap-drop=ALL`, `65532:65532`, `:ro` repo, `docker.sock`/sır engeli). |
| **Gerçek Docker Engine Çalışma Zamanı Konteyner Testleri (`WKR-001`..`WKR-005`)** | `unverified` | `probeDockerRuntimeAvailability` ile denetlenir; bu ana makinede Docker kurulu olmadığı için sahte `PASS` yerine **`SKIP (not verified)`** döner. |
| **Çalışma Bazlı `nftables` Kural Üreticisi, `SimulatedNetworkNamespaceFirewall` & `executeBoundedPassiveRequest`** | `simulated` | Uygulama içi simülasyon ve enjekte edilen transport üzerinde `GET`/`HEAD`, boyut sınırı (`maxResponseBytes`), redirect ve `AbortSignal` iptalini doğrular; gerçek OS çekirdeğinde `nftables` çalıştırmaz. |
| **Canlı Uzak HTTP/TLS Soket Taraması (`restricted-remote`)** | `blocked` | `executeScan` içinde kesin olarak **devre dışıdır (`fail-closed`)**. `source-offline` (`--network=none`) altında HTTP çalışamaz; `remote-web` harici Trusted Egress Broker doğrulanana kadar açılmaz. |
| **Web Gözlemcileri (`WEB-HEADER-001`, `WEB-COOKIE-001`, `WEB-TLS-001`, `WEB-REDIRECT-001`)** | `implemented` | Muhafazakâr CSP semantiği (`NEW-02`, `AUD-06-C`), çerez kimliği parmak izi (`positive_validation_fingerprints`, `SameSite`, `__Host-`/`__Secure-`), TLS `handshake_error` (`failed` coverage) + süresi dolmuş sertifika kontrolü ve redirect analizi. |
| **Yerel Semgrep (`CODE-001`) & Trivy (`DEP-001`) Sarmalayıcıları, `AbortSignal` İptali & Symlink/TOCTOU Koruması** | `implemented` | `execFile` (`shell: false`), `AbortSignal` (`SIGTERM` -> `SIGKILL`), `tool_status` (`killed`/`timed_out`/`not_installed`/`exited`), Trivy DB `NextUpdate` tazelik kontrolü ve `realpathSync`/`lstatSync` symlink koruması. |
| **Gerçek Kurulu `semgrep` ve `trivy` İkililerinin Ana Makinede Çalıştırılması** | `unverified` | `probeInstalledBinaryVersion` ile kontrol edilir; bu makinede ikililer `PATH` içinde kurulu olmadığından **`SKIP (not verified)`** olarak raporlanır. |
| **9 Katmanlı Sır Maskeleme, JSON/MD/HTML/SARIF 2.1.0 Raporlama & Re-Test Motoru (`compareScanReports`)** | `implemented` | `redactSensitiveText`, JSON Schema/SARIF doğrulayıcıları, XSS-korumalı HTML rapor ve `rulepack_version` / `db_freshness` (`stale` -> `not_comparable`) / `db_version` farklarını yakalayan `recheck-engine`. |
| **Yerel Etkileşimli Frontend Workbench ([`packages/scanner-core/src/server.ts`](../../packages/scanner-core/src/server.ts))** | `implemented` | Loopback `Host`/`Origin` kontrolü (`403`), 16 KB `POST` sınırı (`413`), bozuk JSON reddi (`400`) ve `'unsafe-inline'` içermeyen CSP. Üçüncü taraf izleyici/çerez barındırmaz (teknik gizlilik hijyeni sağlar; tek başına tam hukuki KVKK/GDPR uyumluluğu anlamına gelmez). |
| **Laravel API, Next.js Çok Kiracılı Platform, SMTP ve Kontrollü ZAP DAST** | `planned` | `Stage 2 (v0.2+)` ve `Stage 3 (v0.3+)` fazlarında uygulanacaktır. |

---

## 3. Frontend ve Etkileşimli Kullanıcı Arayüzü Mimarisi (Mevcut & Planlanan)

HegoSentinel'in kullanıcı arayüzü katmanı iki tamamlayıcı bileşenden oluşur: **bugün çalışan Yerel Frontend Workbench + Bağımsız HTML Rapor Arayüzü (`Stage 1`)** ve **çok kiracılı ekip kullanımı için tasarlanan Next.js Geliştirici Platformu (`Stage 2 / v0.2`)**.

### 3.1. Mevcut Çalışan Frontend 1: Yerel Etkileşimli Web Workbench (`http://localhost:4173`)
[`packages/scanner-core/src/server.ts`](../../packages/scanner-core/src/server.ts) içinde sıfır üçüncü taraf bağımlılıkla inşa edilen ve `npm run serve` komutuyla `127.0.0.1:4173` üzerinde çalışan tam kapsamlı yerel güvenlik çalışma tezgahıdır:

1. **Görsel Sanat Yönetimi ve Tasarım Sistemi (`Anti-Slop Studio Design`):**
   * **Renk Paleti:** Derin obsidyen zemin (`#050507`), yüzey katmanları (`#0b0d13`, `#111520`), `1px` yapısal çizgiler (`rgba(255, 255, 255, 0.08)`) ve tekil vurgu rengi olarak **Electric Signal Lime (`#d4ff33`)** + anlamsal durum rozetleri (`#10b981` OK, `#f59e0b` Warn, `#f43f5e` Danger).
   * **Tipografi:** Yüksek kontrastlı başlıklar (`clamp(2.4rem, 4.8vw, 4.4rem)`, `-0.038em` optik harf aralığı) ve teknik telemetri/kod alanları için `JetBrains Mono` monospace mikro etiketler.
   * **Frameless 3D-Projected Orbital Topology Canvas (`#topology-canvas`):** Hero bölümünde kart veya çerçeve içine hapsedilmemiş, açık alanda dönen 38 düğümlü 3B izdüşümlü güven sınırı (trust boundary) topoloji animasyonu (`prefers-reduced-motion` erişilebilirlik tercihine duyarlı).

2. **Etkileşimli Çalışma Tezgahı (`Interactive Scan & Evidence Workbench`) Özellikleri:**
   * **3 Canlı Çalıştırma Profili (`Execution Profiles`):**
     1. **`1. Baseline Scan (Unpatched)`:** Yamasız sentetik hedef üzerinde `WEB-HEADER-001`, `WEB-COOKIE-001`, `WEB-TLS-001`, `WEB-REDIRECT-001` kontrollerini çalıştırır ve kanıtları listeler.
     2. **`2. Apply CSP Fix & Re-Test`:** Yamalı hedefi tarar, `compareScanReports` motorunu çalıştırır ve `WEB-HEADER-001`'in `observed -> VERIFIED_FIXED`, `WEB-COOKIE-001`'in `needs_review -> PERSISTENT` geçişini canlı tabloda gösterir.
     3. **`3. Local SAST + SCA (Semgrep/Trivy)`:** Yerel kaynak kod (`CODE-001`) ve bağımlılık (`DEP-001`) bulgularını normalize eder ve **OASIS SARIF 2.1.0** çıktısını canlı denetleyicide görüntüler.
   * **4 Saldırgan Guardrail Simülasyon Probu (`Adversarial Guardrail Probes`):**
     1. **`Probe Cloud Metadata SSRF (SEC-002)`:** `https://169.254.169.254/latest/meta-data/` isteğinin sıfır ağ paketiyle nasıl bloklandığını canlı gösterir.
     2. **`Simulate TOCTOU DNS Rebind (SEC-004)`:** DNS çözümlemesi ile soket bağlantısı arasında IP'nin `127.0.0.1`'e dönmesi durumunda `dns_rebind_detected` reddini simüle eder.
     3. **`Probe Expired Scope Grant (SEC-001)`:** Süresi dolmuş yetki belgesiyle tarama denemesinin `scope_expired` ile reddedildiğini gösterir.
     4. **`Probe Unverified Remote Mode (SEC-005)`:** Egress sandbox kanıtı olmadan `restricted-remote` modunun fail-closed (`remote_egress_isolation_unverified`) kaldığını kanıtlar.
   * **4 Dinamik Veri Görünümü:**
     * **Check Coverage Matrix Tablosu:** Her kuralın (`rule_id`, `version`, `asset`, `status`) ve doğrulama kriterinin durumunu listeler.
     * **Normalized Observations Kartları:** Bulguların `risk_priority`, `confidence`, `verification_status`, `evidence_summary`, `limitations`, `remediation` ve `validation_criterion` detaylarını sunar.
     * **Re-Test Differential Comparison Tablosu:** Baseline ve güncel tarama arasındaki durum geçişlerini (`verified_fixed`, `persistent`, `not_comparable` vb.) açıklar.
     * **Sanitized JSON / SARIF Artifact Inspector:** Maskelenmiş ham JSON ve SARIF 2.1.0 çıktısını doğrudan arayüzde inceler.

3. **Yerel Sunucu API Uç Noktaları ve Kendi Güvenlik Başlıkları:**
   * **Uç Noktalar:** `GET /` (Workbench UI), `GET /reports/demo-baseline.json` (Ham JSON raporu), `GET /reports/demo-recheck.html` (Bağımsız HTML raporu), `POST /api/demo` (`baseline`, `recheck`, `source` modları), `POST /api/probe` (`ssrf-metadata`, `dns-rebind`, `expired-grant`, `remote-egress`).
   * **Kendi Güvenlik Başlıkları (`setSecurityHeaders`):** `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Üçüncü taraf çerez veya izleyici (tracker) içermez (bu durum yalnızca teknik gizlilik/başlık hijyeni sağlar; tek başına aydınlatma metni, veri envanteri ve saklama/imha süreçlerini kapsayan tam hukuki KVKK/GDPR uyumluluğu yerine geçmez).

### 3.2. Mevcut Çalışan Frontend 2: Bağımsız Çevrimdışı HTML Raporu (`renderHtmlReport`)
[`packages/report-engine/src/index.ts`](../../packages/report-engine/src/index.ts) tarafından üretilen `reports/demo-baseline.html` ve `reports/demo-recheck.html` dosyaları:
* Harici hiçbir CSS, JS, font veya resim bağlantısı içermez; tamamen çevrimdışı (air-gapped) ortamlarda tek dosya olarak açılabilir ve paylaşılabilir.
* Tüm dinamik alanlar `escapeHtml` fonksiyonundan geçirildiği için hedef uygulamadan gelen kötücül başlıklar raporu görüntüleyen güvenlik uzmanının tarayıcısında **Stored/Reflected XSS** tetikleyemez.

---

## 4. Üç Bağımsız Kod Denetiminde Kapatılan 17 Bulgunun Özeti

### 4.1. Birinci Denetim Turu (`HS-AUDIT-001` .. `HS-AUDIT-009`)
* **`HS-AUDIT-001` (P0):** Web kurallarında (`WEB-*`) kural bazlı fallback kaldırıldı; `/old` sayfasındaki bulgu, ikinci taramada yalnızca `/different-page` tarandığında asla `verified_fixed` olmaz (`not_comparable` döner).
* **`HS-AUDIT-002` (P0):** `validateAuthorizedRepositoryPath` içine fiziksel `realpathSync` ve özyinelemeli `lstatSync` symlink/junction kontrolü eklendi.
* **`HS-AUDIT-003` & `009` (P1/P2):** `CHANGELOG.md`, `README.md` ve `docs/ROADMAP.md` üzerinde `Implemented / Mocked (Fixture) / Fail-Closed (Planned)` yetenek matrisi netleştirildi.
* **`HS-AUDIT-004` (P1):** `compareScanReports` içinde `grant_id` ve `scope_version` eşleşmesi zorunlu kılındı.
* **`HS-AUDIT-005` & `006` (P1):** Gerçek TypeScript derleyicisi (`tsc --noEmit`) ve Node `22.16.0` / `24.x` uyumluluğu (`--experimental-strip-types`) sağlandı.
* **`HS-AUDIT-007` & `008` (P1/P2):** `CODE-001` / `DEP-001` için depo kökü eşleşmesi ve runtime JSON Schema / SARIF 2.1.0 doğrulayıcıları eklendi.

### 4.2. İkinci Denetim Turu (`NEW-01` .. `NEW-03`)
* **`NEW-01` (P1):** `inspectDirectorySymlinks` içindeki `depth > maxDepth` ve `catch` bloklarının `{ safe: true }` dönmesi (fail-open) kaldırıldı; derinlik aşımı (`maxDepth: 64`), symlink döngüsü (`visitedRealDirs`) ve okunamayan dizin hataları artık **fail-closed (`allowed: false`)** döner. Ayrıca tarama sonrası TOCTOU doğrulaması eklendi.
* **`NEW-02` (P1):** `evaluateCspPolicySemantics` eklendi; `totally-invalid-directive` veya `default-src * 'unsafe-inline'` gibi geçersiz/aşırı izin verici CSP başlıkları `positive_validation_passed: false` alır ve asla `verified_fixed` olamaz.
* **`NEW-03` (P1/P2):** `schemas/*.schema.json` dosyalarını diskten yükleyip `required`, `additionalProperties: false`, `minimum`, `maximum`, `pattern`, `format: "date-time"` ve çapraz alan tutarlılığını (`summary.total_findings === findings.length`) denetleyen `validateAgainstJsonSchema` motoru devreye alındı.

### 4.3. Üçüncü Sınır Denetimi Turu (`AUD-2026-01` .. `AUD-2026-05`)
* **`AUD-2026-01` (P0):** Baseline'da `200 OK text/html` olan bir sayfa ikinci taramada `application/json` veya `404 Not Found` dönerse `not_applicable` olarak işaretlenir ve yeniden testte `verified_fixed` yerine **`not_comparable`** üretir.
* **`AUD-2026-02` & `AUD-2026-04` (P1):** `node_modules` içindeki symlink kaçışlarını yakalamak için `node_modules` atlama istisnası kaldırıldı ve aşırı büyük dizin ağaçlarına karşı `maxEntries: 25_000` fail-closed bütçesi eklendi.
* **`AUD-2026-03` (P1):** `false_positive` bastırma kararlarında `s.scope_version === current.scope_version` eşleşmesi zorunlu kılındı.
* **`AUD-2026-05` (P0):** `restricted-remote` modunda çağıran kod `egressAttestation: true` bayrakları gönderse bile gerçek OS/konteyner ağ izolasyonu ve canlı HTTP/TLS istemcisi bulunmadığı için her durumda fail-closed (`denied`) döner.

### 4.4. Dördüncü Denetim Turu (`v0.1.0-alpha.4` — `AUD-06-A` .. `AUD-06-C` & Workbench Sertleştirmesi)
* **`AUD-06-A` (HIGH):** `WEB-COOKIE-001` artık güvenli olan her bir çerezin parmak izini `positive_validation_fingerprints` listesine yazar; `compareScanReports` yalnızca başlangıçtaki aynı çerezin parmak izi bu listede yer alıyorsa `verified_fixed` üretir (farklı bir güvenli çerez eski bulguyu düzeltilmiş gösteremez).
* **`AUD-06-B` (MEDIUM):** `SameSite` yalnızca `Lax`, `Strict`, `None` değerlerini kabul eder; tekrarlanan `SameSite` öznitelikleri ve RFC 6265bis `__Host-` (`Secure`, `Path=/`, `Domain` yok) / `__Secure-` (`Secure`) önek ihlalleri pozitif doğrulamayı engeller.
* **`AUD-06-C` (HIGH):** `evaluateCspPolicySemantics`, tekrarlanan direktifleri (`default-src *; default-src 'self'`), virgülle birleştirilmiş çoklu politikaları ve `script-src-elem` / `script-src-attr` gevşetmelerini pozitif doğrulamadan reddeder.
* **Yerel Workbench Sertleştirmesi (`packages/scanner-core/src/server.ts`):** Loopback `Host` (`localhost` / `127.0.0.1` / `[::1]`) ve `Origin` / `Sec-Fetch-Site` kontrolü (`403 Forbidden`), 16 KB `POST` gövde sınırı (`413 Payload Too Large`), katı JSON doğrulaması (`400 Bad Request`) ve `/workbench.css` + `/workbench.js` ayrımıyla `'unsafe-inline'` içermeyen enforcing CSP (`WORKBENCH_CSP_HEADER`) devreye alındı.

---

## 5. Çalışan Doğrulama ve Test Tablosu (`8 Test Dosyası · 12 Suite · 56 Test: 49 PASS / 7 SKIP (not verified) / 0 FAIL`)

| Test Dosyası | `describe` Süiti | Toplam Test | `PASS` | `SKIP (not verified)` | Doğrulanan Kontroller |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **[`tests/security/worker-containment-and-sprint2.test.ts`](../../tests/security/worker-containment-and-sprint2.test.ts)** | 3 | 18 | **11** | **7** | **Sprint A (`G0.5`):** Konteyner politikası, `source-offline-manifest.json` + `buildDockerRunArgsForSourceOffline` (`--network=none`, `:ro`, `docker.sock`/sır/proxy reddi), `WKR-001`..`WKR-005` gerçek Docker çalışma zamanı kontrolleri (Docker kurulu olmadığında `SKIP (not verified)`), `WKR-005/006` `AbortSignal` (`SIGTERM` -> `SIGKILL`, `tool_status=killed/not_installed`). **Sprint B (`G0.6`):** `SignedRemoteExecutionGrant` + `NonceReplayRegistry` (replay, `TTL > 300s`, grant substitution, untrusted signer, proxy env escape), `SimulatedNetworkNamespaceFirewall`, `executeBoundedPassiveRequest`. **Sprint C (`P1`):** Gerçek `semgrep`/`trivy` ikili probları (kurulu olmadığında `SKIP (not verified)`), `rulepack_version`/`db_freshness`/`db_version` re-test farkları, `WEB-TLS-001` `handshake_error` & süresi dolmuş sertifika, HTML XSS kaçışı. |
| **[`tests/security/cookie-csp-identity-regression.test.ts`](../../tests/security/cookie-csp-identity-regression.test.ts)** | 3 | 12 | **12** | 0 | `AUD-06-A/B/C` (Çerez kimliği kanıtı `positive_validation_fingerprints`, geçersiz/tekrarlı `SameSite`, `__Host-` önek kuralları, tekrarlı CSP direktifi, `script-src-elem` ve `script-src-attr` ezmeleri) + Yerel Workbench (`Host`/`Origin` `403`, `400`/`413` JSON sınırı, `'unsafe-inline'` içermeyen CSP). |
| **[`tests/security/security-matrix.test.ts`](../../tests/security/security-matrix.test.ts)** | 1 | 9 | **9** | 0 | `SEC-001` .. `SEC-010` (Grant, SSRF, IPv6, Redirect, DNS Rebind, Remote Egress Fail-Closed, Binary Allowlist, Secret Redaction, Coverage Gaps, Scoped Suppression). |
| **[`tests/security/audit-regression.test.ts`](../../tests/security/audit-regression.test.ts)** | 1 | 7 | **7** | 0 | `HS-AUDIT-001` .. `008` + `NEW-01` (Derin symlink / okunamayan dizin fail-closed), `NEW-02` (Geçersiz/gevşek CSP semantik kontrolü), `NEW-03` (JSON Schema negatif şema testleri). |
| **[`tests/security/independent-boundary-audit.test.ts`](../../tests/security/independent-boundary-audit.test.ts)** | 1 | 5 | **5** | 0 | `AUD-2026-01` (HTML->JSON/404 recheck), `AUD-2026-02` (`node_modules` symlink kaçışı), `AUD-2026-03` (`scope_version` suppression), `AUD-2026-04` (`maxEntries` sınırı), `AUD-2026-05` (Sahte `egressAttestation` bayrağı). |
| **[`tests/unit/checks-and-recheck.test.ts`](../../tests/unit/checks-and-recheck.test.ts)** | 1 | 3 | **3** | 0 | `HSR-04` negatif fixture'lar, `S1-03` CVSS v4.0 vektör zorunluluğu, `S1-05` durum geçişleri. |
| **[`tests/integration/adapters-and-reports.test.ts`](../../tests/integration/adapters-and-reports.test.ts)** | 1 | 1 | **1** | 0 | Semgrep (`CODE-001`) + Trivy (`DEP-001`) normalizasyonu ve SARIF 2.1.0/HTML/MD çıktıları. |
| **[`tests/e2e/cli-demo.test.ts`](../../tests/e2e/cli-demo.test.ts)** | 1 | 1 | **1** | 0 | `SEC-014` çevrimdışı CLI `demo --offline` ve `compare` uçtan uca akışı + sıfır JWT sızıntısı. |
| **Toplam (`8 Dosya`)** | **12** | **56** | **49 PASS** | **7 SKIP (not verified)** | **`npm run lint` (`0`) + `npm run typecheck` (`0`) + `npm test` (`0`, `0 FAIL`) + `npm run demo` (`0`)** |

---

## 6. Bundan Sonra Neler Yapılacak? (Önceliklendirilmiş Mühendislik ve Frontend Yol Haritası)

### Öncelik 0 (`P0` — Zorlanan Çalıştırma Sınırları ve İzolasyon: `G0 / G1` Kapısı)
1. **Gerçek OS / Konteyner Tabanlı Salt-Okunur Tarayıcı İşçisi (`Isolated Scanner Worker`):**
   * Yerel kaynak kod (`Semgrep` / `Trivy`) taramalarını çalıştıran işçinin non-root kullanıcıyla, `--read-only` kök dosya sistemiyle, hedef deponun `:ro` (salt-okunur) bağlanmasıyla, `--network=none` (sıfır ağ erişimi), `--cap-drop=ALL`, `no-new-privileges` ve CPU/RAM/süre/dosya sayısı bütçeleriyle izole edilmesi.
2. **Ağ Katmanı Egress Güvenlik Duvarı ve Sınırlandırılmış HTTP/TLS İstemcisi:**
   * Çağıran kodun verdiği boolean bayraklardan bağımsız olarak işletim sistemi / konteyner ağ ad alanında (network namespace / iptables / eBPF / egress proxy) iç ağları (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `fd00:ec2::254`) bloklayan gerçek ağ sınırının kurulması.
   * Yalnızca bu doğrulandıktan sonra pinlenmiş IP'ye bağlanan, timeout, maksimum gövde boyutu (response size cap), soket eş IP doğrulaması ve yönlendirme yeniden yetkilendirmesi yapan gerçek HTTP/TLS gözlemcisinin açılması.
3. **Kriptografik İmzalı ve Kısa Ömürlü Yetki Belgeleri (`Signed Scope Grants`):**
   * Basit bir `written_permission_ref` metni yerine, proje sahibinin açık onayını ve kapsam sürümünü (`scope_version`) kriptografik imzayla (`Ed25519` / `HMAC-SHA256`) mühürleyen değişmez (immutable) yetki belgesi doğrulaması.

### Öncelik 1 (`P1` — Bulgu Doğruluğu, Gerçek İkili Testleri ve Şema Uyumluluğu)
1. **Sabitlenmiş (Pinned) Gerçek Semgrep ve Trivy İkilileriyle Entegrasyon Testleri:**
   * İzole işçi içinde gerçek Semgrep CE ve Trivy ikililerinin güvenli test depoları üzerinde çalıştırılması; çıkış kodlarının, zafiyet veritabanı güncelliğinin ve telemetri kapalılığının doğrulanması.
2. **Büyük `node_modules` Ağaçları İçin Güvenli Hariç Tutma (`Exclude`) Politikası:**
   * Symlink kaçış korumasını zayıflatmadan, hem ön kontrolde hem de Semgrep/Trivy argümanlarında (`--exclude`) aynı dizin sınırlarını zorlayan performans optimizasyonu.
3. **Standart Şema ve SARIF 2.1.0 Doğrulaması + Genişletilmiş CSP/Çerez/TLS Sınır Testleri:**
   * Çoklu başlıklar, `Report-Only` politikaları, yönlendirme durumları, sertifika zinciri ve veritabanı sürümü değişimlerinde deterministik yeniden test (`recheck`) testlerinin genişletilmesi.

### Öncelik 2 (`P2` — `Stage 2 / v0.2` Çok Kiracılı Platform: Laravel API + Next.js Frontend)

#### A. Backend & Kontrol Düzlemi (`apps/api` — Laravel + PostgreSQL + Redis Kuyruk)
* **Çok Kiracılı Veri Modeli ve RBAC (`SEC-011`):** `organizations`, `memberships`, `projects`, `assets`, `authorization_grants`, `scope_versions`, `scans`, `findings`, `reviews`, `audit_events` tabloları ve `Owner`, `Security Reviewer`, `Developer`, `Read-only Auditor` rolleri.
* **Kuyruk İptali (`Kill-Switch` — `SEC-012`) ve Şifreli Kanıt Depolama:** Devam eden taramayı ve alt süreçlerini anında sonlandıran iptal mekanizması, şifreli rapor saklama ve saklama süresi (retention) politikaları.

#### B. Next.js Geliştirici Frontend Mimarisi (`apps/web` — `S2-03`)
Mevcut yerel Workbench'in (`packages/scanner-core/src/server.ts`) tasarım dili (`Obsidian #050507 + Signal Lime #d4ff33`) korunarak **Next.js App Router + TypeScript + Tailwind** üzerinde inşa edilecek 6 temel geliştirici ekranı:

1. **Organizasyon, Proje ve Hedef Varlık (`Asset`) Envanteri Ekranı:**
   * Kiracı (organization) seçimi, projelerin güvenlik kapsam durumu, doğrulanan alan adları ve yerel/uzak depo bağlantı durumları.
2. **Kapsam & Yazılı İzin Sihirbazı (`Scope & Consent Wizard`):**
   * İzin verilen host/port/path sınırlarının, test zaman penceresinin (`time_window`), maksimum istek bütçesinin (`max_request_budget`) ve acil durdurma kontağının tanımlandığı, önceki `scope_version` ile farkları (`diff`) gösteren onay ekranı.
3. **Canlı Tarama Kuyruğu, Coverage Matrisi ve Acil Durdurma (`Kill-Switch`) Paneli:**
   * Çalışan taramanın ilerleme durumu, kural bazlı `executed / skipped / denied / failed` kapsam matrisi (`completed_with_gaps` şeffaflığı) ve tek tıkla taramayı durduran **Emergency Stop (`Kill-Switch`)** butonu.
4. **Bulgu Triyaj ve Geliştirici Çözüm Merkezi (`Evidence-to-Fix Triage View`):**
   * **`observed` vs `needs_review` vs `confirmed` Görsel Ayrımı:** Gözlemlenen bir başlık eksikliğinin hiçbir zaman "kanıtlanmış istismar (exploit)" gibi gösterilmediği dürüst rozet sistemi.
   * **Stack-Bazlı Kod Yaması Görünümü:** Projenin yığınına (`Laravel`, `Next.js`, `Generic Web`) göre kopyalanabilir middleware/konfigürasyon yamaları, yan etki uyarıları (`side_effects`) ve doğrulama kriteri.
   * **İncelemeci (`Security Reviewer`) Karar Akışı:** Bulguyu geliştiriciye atama, gerekçeli ve son kullanma tarihli (`expires_at`) + `scope_version` bağlı `false_positive` bastırma onayı.
5. **Deterministik Yeniden Test (`Re-Test Differential`) Karşılaştırma Ekranı:**
   * İki tarama arasındaki `verified_fixed`, `no_longer_observed`, `persistent`, `reopened`, `new` ve `not_comparable` geçişlerini kanıt özetleriyle yan yana gösteren görsel karşılaştırma ekranı.
6. **Denetim İzi (`Audit Log`) ve İnsan Onaylı Bildirim / GitHub Issue Merkezi (`S2-04`):**
   * Kim, ne zaman, hangi kapsamı onayladı, hangi taramayı başlattı veya hangi bulguyu `false_positive` işaretledi sorularının değiştirilemez kaydı.
   * Varsayılan olarak kapalı olan; yalnızca proje sahibinin açık onayıyla çalışan maskelenmiş SMTP e-posta özeti ve özel (private) GitHub Issue oluşturma akışı.

### Öncelik 3 (`P3` — `Stage 3 / v0.3` Kontrollü Dinamik Doğrulama)
* **OWASP ZAP Pasif Analiz (`ZAP-PASSIVE-001`) ve Yalnızca Staging Ortamında Kontrollü DAST (`DAST-CONTROLLED-001`):**
  * Üretim (production) ortamında varsayılan olarak kapalı; yalnızca **staging** ortamında ikinci bir yazılı izin, sağlık kontrolü (health check), daraltılmış istek bütçesi ve anında durdurma anahtarıyla çalışan kontrollü doğrulama.
