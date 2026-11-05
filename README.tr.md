# HegoSentinel (Türkçe Özet)

**HegoSentinel**, yalnızca yetkilendirilmiş web uygulamalarını, API'leri ve kaynak kod depolarını incelemek için tasarlanan, geliştirici odaklı, kendi sunucunuzda çalışan açık kaynak güvenlik denetimi ve düzeltme takip aracıdır: yetkili tarama → normalize kanıt → düzeltme görevi → karşılaştırılabilir yeniden test.

> [!WARNING]
> **Experimental / Alpha / Not Production Ready (Deneysel / Alpha / Production'a Hazır Değil).** `v0.1.0-alpha.4` + yayımlanmamış Sprint 7–9 güvenlik çalışmaları. Bazı kontroller yalnızca tek bir Windows makinesinde veya yalnızca süreç içinde doğrulandı; **gerçek Linux Docker izolasyonu (`WKR-001..005`) ve gerçek ağ ad alanı (netns) izolasyonu (`EGR-LINUX-NETNS-RUNTIME`) henüz doğrulanmadı.** Canlı uzak tarama (`restricted-remote`) bilinçli olarak kapalıdır. Bkz. [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) ve [GITHUB_RELEASE_PREPARATION.md](GITHUB_RELEASE_PREPARATION.md).

## Bugün gerçekten çalışanlar

| Alan | Durum | Özet |
| --- | --- | --- |
| Yetki ve politika motoru | **uygulandı · test edildi** | Yazılı izinli kapsam, zaman penceresi, yalnızca `GET`/`HEAD`, joker/IP-literal reddi, SSRF IPv4/IPv6 sınıflandırma, DNS rebinding sabitleme, yönlendirme doğrulama. |
| Kanıt hattı | **uygulandı · test edildi** | Çevrimdışı fixture üzerinde web gözlemcileri, 9 geçişli sır maskeleme, JSON/MD/HTML/SARIF 2.1.0 dışa aktarma, deterministik yeniden test. |
| Semgrep CE ve Trivy | **uygulandı · test edildi** | **Gerçek ikililer Windows 10 / Node 24.19.0 üzerinde Semgrep CE `1.183.0` ve Trivy `0.76.1` ile doğrulandı.** Linux CI'da **henüz doğrulanmadı**. |
| Trusted Egress Broker | **uygulandı · süreç içi/loopback test edildi** | Varsayılan-reddet, imzalı tek kullanımlık kısa ömürlü grant, SSRF/rebinding/yönlendirme engeli, **giden başlık izin listesi, ilk log kaydından önce URL/sır maskeleme, broker saati (worker grant'ı geriye tarihleyemez)**. Ağ zorlaması **simüle**; API'ye **bağlı değil**. |
| Platform API (`apps/api`) | **uygulandı (prototip) · test edildi** | SQLite üzerinde **özel PHP 8.2 servis katmanı**, 14 modül. **Laravel uygulaması değildir** (framework kurulu değil); PostgreSQL, Redis ve Horizon **kullanılmıyor** (yalnız yapılandırma dosyası). |
| Web arayüzü (`apps/web`) | **uygulandı (prototip) · test edildi** | Bağımlılıksız **Node HTTP sunucusu + gömülü HTML/JS** (9 ekran, TR/EN). **Next.js derlemesi değildir**; `src/app/*.tsx` kullanılmayan iskelettir. |
| `restricted-remote` | **kapalı (tasarım gereği)** | Bağımsız ağ izolasyonu doğrulanana kadar fail-closed. |
| Gerçek Docker worker izolasyonu | **doğrulanmadı** | Docker Engine yok → `SKIP`. |
| Gerçek Linux netns izolasyonu | **doğrulanmadı** | Betik var, hiç çalıştırılmadı. |
| GitHub Actions CI | **doğrulanmadı** | Workflow var, hiç çalışmadı. |

## Sprint 9 güvenlik değişiklikleri

* Kimlik yalnızca sunucunun verdiği `Authorization: Bearer` oturum belirtecinden gelir. Eski `X-Demo-Principal` taklit yolu **kaldırıldı**.
* Kayıt her zaman **yeni** bir organizasyon oluşturur; istemci organizasyon veya rol seçemez.
* Her nesne erişiminde sunucu tarafı kiracı/proje/RBAC denetimi; denetim izini yalnızca `owner`/`security_lead` okur; bir görev yalnızca doğrulanmış yeniden testle `verified_closed` olur.
* Depo yolları çalışma alanına hapsedilir (path traversal ve projeler arası tarama engellenir).
* Demo modu (bilinen demo kullanıcıları ve parola) yalnızca operatör `HEGOSENTINEL_DEMO_MODE=1` verdiğinde vardır; `APP_ENV=production` iken kesinlikle kapalıdır.

## Hızlı başlangıç

```bash
npm run lint && npm run typecheck && npm test && npm run test:api
npm run verify:gates && npm run verify:release-gate   # bugün BLOCKED dönmesi beklenir
```

Yerel demo platformu (yalnızca kendi makinenizde):

```powershell
$env:HEGOSENTINEL_DEMO_MODE = "1"
npm run start:api     # http://127.0.0.1:8000
npm run start:web     # http://127.0.0.1:3000
```

Değişken verilmezse servisler **boş ve kilitli** açılır; arayüzden hesap oluşturup giriş yapın. Erişilebilir bir sunucuda bu değişkeni asla ayarlamayın.

## Bilinen sınırlamalar

1. Gerçek Linux Docker/netns doğrulaması yok (5 konteyner kontrolü ve netns/broker uçtan uca kontrolü `SKIP`).
2. API Laravel değildir; PostgreSQL/Redis/Horizon kullanılmıyor. 3. Arayüz Next.js değildir.
4. API taramaları host `node` alt süreciyle çalışır; API broker'ı çağırmaz.
5. Alan adı sahipliği ve bildirim alan adı doğrulaması kriptografik olarak doğrulanmaz; e-posta "gönderimi" bir veritabanı kaydıdır.
6. Broker nonce/bütçe/audit belleğte tutulur. 7. MFA zorlanmıyor. 8. Özel sır tarayıcısı (`gitleaks`) çalıştırılmadı. 9. Bağımsız sızma testi yapılmadı.

Ayrıntılar: İngilizce [README.md](README.md), [PROJECT_STATUS.md](PROJECT_STATUS.md), [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md), [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md) ve tarihsel belgeler için [docs/archive/](docs/archive/).
