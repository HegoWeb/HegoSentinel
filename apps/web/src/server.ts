import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PLATFORM_I18N } from './lib/i18n.ts';

const CURRENT_DIR = dirname(fileURLToPath(import.meta.url));
const CSS_PATH = resolve(CURRENT_DIR, 'app/globals.css');

export interface WebPlatformServerOptions {
  port?: number;
  host?: string;
  apiUpstreamUrl?: string;
  /** Test/embedding override. Defaults to the operator environment (never request data). */
  demoMode?: boolean;
}

function loadGlobalCss(): string {
  try {
    return readFileSync(CSS_PATH, 'utf8');
  } catch {
    return ':root { color-scheme: dark; background: #050507; color: #f4f6f8; }';
  }
}

/**
 * Demo mode is decided ONLY by the server operator's environment, never by any request data.
 * It is hard-disabled when NODE_ENV or APP_ENV is production.
 */
export function isDemoModeEnabled(env: Record<string, string | undefined> = process.env): boolean {
  const prod = (v?: string) => ['production', 'prod'].includes((v ?? '').toLowerCase());
  if (prod(env.NODE_ENV) || prod(env.APP_ENV)) return false;
  return env.HEGOSENTINEL_DEMO_MODE === '1';
}

export function renderPlatformAppDocument(options: { demoMode?: boolean } = {}): string {
  const demoMode = options.demoMode === true;
  const css = loadGlobalCss();
  const i18nJson = JSON.stringify(PLATFORM_I18N);

  const jsonLd = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'HegoSentinel Security Platform',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Linux, Windows, macOS',
    softwareVersion: '0.1.0-alpha.4',
    description:
      'Self-hosted, fail-closed cybersecurity assessment, evidence normalization, developer remediation, and re-test verification platform.'
  });

  return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="dark" />
  <title>HegoSentinel — Yetkili Güvenlik Tarama, Kanıt Normalizasyonu ve Yeniden Test Platformu</title>
  <meta name="description" content="HegoSentinel: Gerçek Semgrep CE (1.183.0), Trivy (0.76.1), Trusted Egress Broker ve SHA-256 denetim zinciri ile açık kaynak siber güvenlik platformu." />
  <link rel="canonical" href="http://127.0.0.1:3000/" />
  <meta property="og:title" content="HegoSentinel Security Platform (v0.1.0-alpha.4)" />
  <meta property="og:description" content="Authorized security assessment, evidence normalization, developer remediation, and re-test verification platform." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="http://127.0.0.1:3000/" />
  <meta name="twitter:card" content="summary_large_image" />
  <script type="application/ld+json">${jsonLd}</script>
  <style>${css}</style>
</head>
<body>
  <div class="hs-shell" id="hs-app">
    <aside class="hs-sidebar" aria-label="Platform Kenar Çubuğu">
      <div>
        <div class="hs-brand">
          <div class="hs-brand-mark" aria-hidden="true">HS</div>
          <div>
            <div style="font-weight:700;font-size:0.95rem;letter-spacing:-0.02em;">HEGOSENTINEL</div>
            <div class="mono" style="font-size:0.68rem;color:var(--accent-lime);">v0.1.0-alpha.4 · STAGE 2</div>
          </div>
        </div>

        <div style="margin-top:0.85rem;padding:0.65rem;background:var(--bg-surface);border:1px solid var(--border-hairline);border-radius:6px;">
          <div class="mono" style="font-size:0.68rem;color:var(--text-secondary);text-transform:uppercase;">Aktif Oturum / RBAC</div>
          <div id="sidebar-principal-name" style="font-weight:600;font-size:0.84rem;margin-top:0.15rem;">${demoMode ? 'Demo Owner' : 'Oturum Açılmadı'}</div>
          <div style="display:flex;align-items:center;gap:0.4rem;margin-top:0.35rem;flex-wrap:wrap;">
            <span class="hs-badge lime" id="sidebar-principal-role">${demoMode ? 'owner' : 'unauthenticated'}</span>
            <span class="hs-badge" id="sidebar-principal-org">${demoMode ? 'org-hegoweb-sec' : '—'}</span>
          </div>
        </div>

        <nav class="hs-nav-list" aria-label="Ana Navigasyon">
          <button type="button" class="hs-nav-btn active" data-screen="dashboard">
            <span data-i18n="nav.dashboard">Genel Bakış</span>
            <span class="hs-nav-index">01</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="projects">
            <span data-i18n="nav.projects">Projeler &amp; Kapsam</span>
            <span class="hs-nav-index">02</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="scanner">
            <span data-i18n="nav.scanner">Güvenlik Tarayıcı</span>
            <span class="hs-nav-index">03</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="vulnerabilities">
            <span data-i18n="nav.vulnerabilities">Zafiyet Bulguları</span>
            <span class="hs-nav-index">04</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="remediation">
            <span data-i18n="nav.remediation">Çözüm Merkezi</span>
            <span class="hs-nav-index">05</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="rechecks">
            <span data-i18n="nav.rechecks">Yeniden Test &amp; Fark</span>
            <span class="hs-nav-index">06</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="reports">
            <span data-i18n="nav.reports">Raporlar &amp; Bildirim</span>
            <span class="hs-nav-index">07</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="settings">
            <span data-i18n="nav.settings">Ayarlar &amp; Denetim</span>
            <span class="hs-nav-index">08</span>
          </button>
          <button type="button" class="hs-nav-btn" data-screen="auth">
            <span data-i18n="nav.auth">Oturum &amp; Rol</span>
            <span class="hs-nav-index">09</span>
          </button>
        </nav>
      </div>

      <div style="margin-top:1.25rem;padding-top:0.85rem;border-top:1px solid var(--border-hairline);font-size:0.73rem;color:var(--text-secondary);">
        <div class="mono" style="color:var(--accent-lime);">SEMGREP CE 1.183.0 · TRIVY 0.76.1</div>
        <div style="margin-top:0.2rem;">TrustedEgressBroker: DROP-BY-DEFAULT</div>
      </div>
    </aside>

    <main class="hs-main">
      <header class="hs-topbar">
        <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
          <span class="hs-badge lime" data-i18n="status.remoteBlocked">RESTRICTED-REMOTE: KAPALI (FAIL-CLOSED)</span>
          <span class="hs-badge" id="topbar-audit-badge" data-i18n="status.auditChainValid">SHA-256 DENETİM ZİNCİRİ: DOĞRULANDI</span>
          <span class="hs-badge" id="topbar-scanner-badge">Semgrep 1.183.0 · Trivy 0.76.1</span>
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;">
          <label for="quick-role-select" class="mono" style="font-size:0.72rem;color:var(--text-secondary);">RBAC:</label>
          <select id="quick-role-select" class="hs-select" style="width:auto;padding:0.35rem 0.6rem;font-size:0.78rem;" aria-label="Hızlı RBAC Oturum Seçici">
            <option value="admin@hegoweb.local">Demo Owner - full access</option>
            <option value="sec-lead@hegoweb.local">Demo Security Lead</option>
            <option value="dev@hegoweb.local">Demo Developer</option>
            <option value="auditor@hegoweb.local">Demo Viewer - read only</option>
            <option value="owner@betafintech.example.test">Beta FinTech - isolated tenant (SEC-011)</option>
          </select>
          <button type="button" id="locale-toggle-btn" class="hs-btn" style="padding:0.38rem 0.7rem;" aria-label="Dil Değiştir">EN</button>
        </div>
      </header>

      <div class="hs-content">
        <div id="status-banner" class="hs-panel" style="display:none;border-color:var(--accent-lime);padding:0.75rem 1rem;" role="status" aria-live="polite"></div>

        <!-- Frameless Hero Command Stage (Strict Frameless Hero Visual Law) -->
        <section class="hs-hero-stage" aria-labelledby="hero-heading">
          <div>
            <div class="mono" style="font-size:0.72rem;color:var(--accent-lime);letter-spacing:0.08em;text-transform:uppercase;margin-bottom:0.4rem;" data-i18n="brandSubtitle">
              YETKİLİ GÜVENLİK TARAMA, KANIT NORMALİZASYONU VE YENİDEN TEST PLATFORMU
            </div>
            <h1 id="hero-heading" class="hs-hero-title" data-i18n="dashboard.title">Siber Güvenlik Komuta Merkezi</h1>
            <p style="color:var(--text-secondary);margin-top:0.55rem;max-width:64ch;" data-i18n="dashboard.subtitle">
              Gerçek Semgrep CE (1.183.0), Trivy (0.76.1) ve pasif web güvenlik kontrolleri ile çok kiracılı güvenlik telemetrisi.
            </p>
            <div style="display:flex;gap:0.65rem;flex-wrap:wrap;margin-top:1rem;">
              <button type="button" class="hs-btn primary" id="hero-launch-scan-btn" data-i18n="scanner.launchScan">Yetkili Taramayı Başlat</button>
              <button type="button" class="hs-btn" id="hero-new-project-btn" data-i18n="projects.createProject">Yeni Yetkili Proje Oluştur</button>
              <button type="button" class="hs-btn danger" id="hero-emergency-stop-btn" data-i18n="scanner.emergencyStop">ACİL DURDURMA (SEC-012 KILL-SWITCH)</button>
            </div>
          </div>
          <div class="hs-hero-radar" aria-hidden="true">
            <svg width="220" height="168" viewBox="0 0 220 168" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="110" cy="84" r="72" stroke="rgba(212,255,51,0.18)" stroke-width="1" stroke-dasharray="3 3" />
              <circle cx="110" cy="84" r="50" stroke="rgba(212,255,51,0.32)" stroke-width="1" />
              <circle cx="110" cy="84" r="26" stroke="rgba(212,255,51,0.55)" stroke-width="1.2" />
              <line x1="22" y1="84" x2="198" y2="84" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
              <line x1="110" y1="6" x2="110" y2="162" stroke="rgba(255,255,255,0.08)" stroke-width="1" />
              <path d="M110 84 L164 42" stroke="#d4ff33" stroke-width="1.6" />
              <circle cx="164" cy="42" r="4" fill="#d4ff33" />
              <circle cx="82" cy="64" r="3" fill="#38bdf8" />
              <circle cx="136" cy="112" r="3" fill="#ff8a2b" />
              <circle cx="110" cy="84" r="4.5" fill="#d4ff33" />
              <text x="110" y="158" text-anchor="middle" fill="#9ba3b0" font-family="JetBrains Mono, monospace" font-size="9">EGRESS: DENY-BY-DEFAULT · NETNS</text>
            </svg>
          </div>
        </section>

        <!-- SCREEN 01: DASHBOARD -->
        <section id="screen-dashboard" class="hs-screen" style="display:flex;flex-direction:column;gap:1.25rem;">
          <div class="hs-kpi-grid">
            <div class="hs-panel">
              <div class="mono" style="font-size:0.72rem;color:var(--text-secondary);" data-i18n="dashboard.totalProjects">Yetkili Projeler</div>
              <div class="hs-kpi-value" id="kpi-total-projects">3</div>
              <div class="mono" style="font-size:0.74rem;color:var(--accent-lime);" id="kpi-projects-breakdown">2 Gerçek Hedef · 1 Sentetik Demo</div>
            </div>
            <div class="hs-panel">
              <div class="mono" style="font-size:0.72rem;color:var(--text-secondary);" data-i18n="dashboard.totalScans">Toplam Tarama</div>
              <div class="hs-kpi-value" id="kpi-total-scans">1</div>
              <div class="mono" style="font-size:0.74rem;color:var(--text-secondary);" id="kpi-scans-detail">Semgrep 1.183.0 &amp; Trivy 0.76.1</div>
            </div>
            <div class="hs-panel">
              <div class="mono" style="font-size:0.72rem;color:var(--text-secondary);" data-i18n="dashboard.totalFindings">Normalize Bulgular</div>
              <div class="hs-kpi-value" id="kpi-total-findings">0</div>
              <div class="mono" style="font-size:0.74rem;color:var(--accent-lime);" id="kpi-findings-breakdown">Gerçek Tarama vs Demo Ayrımı Aktif</div>
            </div>
            <div class="hs-panel">
              <div class="mono" style="font-size:0.72rem;color:var(--text-secondary);" data-i18n="dashboard.remediationTasks">Düzeltme Görevleri</div>
              <div class="hs-kpi-value" id="kpi-open-tasks">0</div>
              <div class="mono" style="font-size:0.74rem;color:var(--text-secondary);" id="kpi-tasks-breakdown">0 Doğrulandı &amp; Kapatıldı</div>
            </div>
          </div>

          <div class="hs-grid-2">
            <div class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1rem;" data-i18n="dashboard.riskDistribution">Öncelik Dağılımı (Internal Priority &amp; CVSS v4)</h2>
                <span class="hs-badge lime">HSR-07 DOĞRULANDI</span>
              </div>
              <div id="dashboard-risk-bars" style="display:flex;flex-direction:column;gap:0.65rem;"></div>
            </div>

            <div class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1rem;" data-i18n="dashboard.securityPosture">Çalışma Zamanı Güvenlik Sınırları</h2>
                <span class="hs-badge lime">SEC-001..014</span>
              </div>
              <div id="dashboard-posture-list" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0.6rem;font-size:0.8rem;"></div>
            </div>
          </div>

          <div class="hs-grid-2">
            <div class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1rem;" data-i18n="dashboard.recentScans">Son Tarama Çalışmaları</h2>
                <button type="button" class="hs-btn" data-goto="scanner" style="padding:0.3rem 0.65rem;font-size:0.75rem;">Tarayıcıyı Aç &rarr;</button>
              </div>
              <div class="hs-table-wrap">
                <table class="hs-table">
                  <thead>
                    <tr>
                      <th>Tarama ID</th>
                      <th>Proje</th>
                      <th>Veri Kaynağı</th>
                      <th>Kapsam</th>
                      <th>Bulgular</th>
                    </tr>
                  </thead>
                  <tbody id="dashboard-recent-scans-tbody"></tbody>
                </table>
              </div>
            </div>

            <div class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1rem;" data-i18n="dashboard.recentAudit">Kriptografik Denetim Kayıtları (SHA-256)</h2>
                <span class="hs-badge lime" id="dashboard-audit-count">Zincir Tam</span>
              </div>
              <div class="hs-table-wrap">
                <table class="hs-table">
                  <thead>
                    <tr>
                      <th>Sıra</th>
                      <th>Aktör / Rol</th>
                      <th>İşlem</th>
                      <th>Sonuç</th>
                      <th>SHA-256 Hash</th>
                    </tr>
                  </thead>
                  <tbody id="dashboard-recent-audit-tbody"></tbody>
                </table>
              </div>
            </div>
          </div>
        </section>

        <!-- SCREEN 02: PROJECTS & SCOPE GRANTS -->
        <section id="screen-projects" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-panel">
            <div class="hs-panel-header">
              <div>
                <h2 style="font-size:1.15rem;" data-i18n="projects.title">Projeler, Hedef Varlıklar ve Kapsam Yetkisi</h2>
                <p style="color:var(--text-secondary);font-size:0.82rem;" data-i18n="projects.subtitle">
                  SEC-001 ve SEC-002 kapsamında alan adı sahipliği kanıtı ve yazılı tarama izni (ScopeAuthorizationGrant) yönetimi.
                </p>
              </div>
              <span class="hs-badge lime">SEC-001 &amp; SEC-002</span>
            </div>

            <div class="hs-table-wrap">
              <table class="hs-table">
                <thead>
                  <tr>
                    <th>Proje</th>
                    <th>Tür (Gerçek / Demo)</th>
                    <th>Ortam &amp; Yığın</th>
                    <th>Hedef Alan Adı &amp; Depo</th>
                    <th>Aktif Kapsam Yetkisi (Grant)</th>
                    <th>İşlem</th>
                  </tr>
                </thead>
                <tbody id="projects-tbody"></tbody>
              </table>
            </div>
          </div>

          <div class="hs-grid-2">
            <form id="create-project-form" class="hs-panel">
              <div class="hs-panel-header">
                <h3 style="font-size:1rem;" data-i18n="projects.createProject">Yeni Yetkili Proje Oluştur</h3>
                <span class="hs-badge">Owner / Security Lead</span>
              </div>
              <div>
                <label class="hs-label" for="proj-name" data-i18n="projects.projectName">Proje Adı</label>
                <input id="proj-name" class="hs-input" type="text" required placeholder="Örn: HegoPay Core API" value="HegoPay Core API" />
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="proj-env" data-i18n="projects.environment">Ortam</label>
                  <select id="proj-env" class="hs-select">
                    <option value="staging">staging</option>
                    <option value="production">production</option>
                    <option value="local-demo">local-demo</option>
                  </select>
                </div>
                <div>
                  <label class="hs-label" for="proj-stack" data-i18n="projects.stack">Teknoloji Yığını</label>
                  <select id="proj-stack" class="hs-select">
                    <option value="laravel,generic-web">Laravel + Generic Web</option>
                    <option value="nextjs,generic-web">Next.js + Generic Web</option>
                    <option value="generic-web">Node.js / Generic Web</option>
                  </select>
                </div>
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="proj-host" data-i18n="projects.hostname">Hedef Alan Adı (Hostname)</label>
                  <input id="proj-host" class="hs-input" type="text" required value="demo.example.test" />
                </div>
                <div>
                  <label class="hs-label" for="proj-repo" data-i18n="projects.repoPath">Yerel Kaynak Depo Yolu</label>
                  <select id="proj-repo" class="hs-select">
                    <option value="examples/synthetic-targets/laravel-app">examples/synthetic-targets/laravel-app</option>
                    <option value="examples/synthetic-targets/nextjs-app">examples/synthetic-targets/nextjs-app</option>
                    <option value="examples/synthetic-targets/nodejs-service">examples/synthetic-targets/nodejs-service</option>
                  </select>
                </div>
              </div>
              <div>
                <label class="hs-label" for="proj-written-ref" data-i18n="projects.writtenPermissionRef">Yazılı İzin Referans No (SEC-001)</label>
                <input id="proj-written-ref" class="hs-input" type="text" required value="AUTH-DOC-2026-HEGOPAY-09" />
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="projects.submitProject">Projeyi ve Kapsam Yetkisini Kaydet</button>
            </form>

            <form id="approve-grant-form" class="hs-panel">
              <div class="hs-panel-header">
                <h3 style="font-size:1rem;" data-i18n="projects.approveGrant">Yeni Kapsam Yetkisi (Grant) Onayla</h3>
                <span class="hs-badge lime">Scope Version +1</span>
              </div>
              <div>
                <label class="hs-label" for="grant-proj-id">Hedef Proje</label>
                <select id="grant-proj-id" class="hs-select"></select>
              </div>
              <div>
                <label class="hs-label" for="grant-written-ref" data-i18n="projects.writtenPermissionRef">Yazılı İzin Referans No (SEC-001)</label>
                <input id="grant-written-ref" class="hs-input" type="text" required value="AUTH-RENEW-2026-V2" />
              </div>
              <div>
                <label class="hs-label" for="grant-dns-proof" data-i18n="projects.domainControlProof">Alan Adı Sahiplik Kanıtı (DNS TXT)</label>
                <input id="grant-dns-proof" class="hs-input" type="text" required value="dns-txt:hegosentinel-verify-2026-v2" />
              </div>
              <div>
                <label class="hs-label" for="grant-host">Hedef Hostname</label>
                <input id="grant-host" class="hs-input" type="text" required value="demo.example.test" />
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="projects.submitGrant">Kapsam Versiyonunu Onayla</button>
            </form>
          </div>
        </section>

        <!-- SCREEN 03: SECURITY SCANNER -->
        <section id="screen-scanner" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-grid-2">
            <form id="launch-scan-form" class="hs-panel">
              <div class="hs-panel-header">
                <div>
                  <h2 style="font-size:1.1rem;" data-i18n="scanner.title">Yetkili Güvenlik Tarayıcı &amp; Kapsam Matrisi</h2>
                  <p style="color:var(--text-secondary);font-size:0.8rem;" data-i18n="scanner.subtitle">
                    Yalnızca aktif ScopeAuthorizationGrant bulunan hedeflerde izole alt süreç ile tarama başlatın.
                  </p>
                </div>
                <span class="hs-badge lime">Isolated Subprocess</span>
              </div>

              <div>
                <label class="hs-label" for="scan-project-select" data-i18n="scanner.selectProject">Hedef Proje Seçin</label>
                <select id="scan-project-select" class="hs-select"></select>
              </div>

              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="scan-mode-select" data-i18n="scanner.selectMode">Çalışma Modu</label>
                  <select id="scan-mode-select" class="hs-select">
                    <option value="offline-fixture">offline-fixture + Real Semgrep/Trivy Local Repo</option>
                    <option value="restricted-remote">restricted-remote (Fail-Closed Testi — SEC-005)</option>
                  </select>
                </div>
                <div>
                  <label class="hs-label" for="scan-variant-select" data-i18n="scanner.selectVariant">Hedef / Fikstür Durumu</label>
                  <select id="scan-variant-select" class="hs-select">
                    <option value="baseline">baseline (Savunmasız / İlk Tarama)</option>
                    <option value="patched">patched (Yamalanmış / Düzeltme Sonrası)</option>
                  </select>
                </div>
              </div>

              <div>
                <label class="hs-label" for="scan-repo-select">Analiz Edilecek Kaynak Kod Deposu (SAST &amp; SCA)</label>
                <select id="scan-repo-select" class="hs-select">
                  <option value="examples/synthetic-targets/laravel-app">examples/synthetic-targets/laravel-app (Laravel)</option>
                  <option value="examples/synthetic-targets/nextjs-app">examples/synthetic-targets/nextjs-app (Next.js)</option>
                  <option value="examples/synthetic-targets/nodejs-service">examples/synthetic-targets/nodejs-service (Node.js)</option>
                </select>
              </div>

              <div style="display:flex;gap:0.65rem;flex-wrap:wrap;margin-top:0.4rem;">
                <button type="submit" class="hs-btn primary" data-i18n="scanner.launchScan">Yetkili Taramayı Başlat</button>
                <button type="button" id="scanner-estop-btn" class="hs-btn danger" data-i18n="scanner.emergencyStop">ACİL DURDURMA (SEC-012 KILL-SWITCH)</button>
              </div>
            </form>

            <div class="hs-panel">
              <div class="hs-panel-header">
                <h3 style="font-size:1rem;" data-i18n="scanner.coverageMatrix">Kural Kapsam Matrisi (Gerçek Kapsam Doğrulaması)</h3>
                <span class="hs-badge lime" id="scanner-active-scan-badge">SCAN-LATEST</span>
              </div>
              <div class="hs-table-wrap">
                <table class="hs-table">
                  <thead>
                    <tr>
                      <th>Kural ID</th>
                      <th>Versiyon</th>
                      <th>Durum</th>
                      <th>Araç / Sürüm</th>
                      <th>Detay / Kanıt</th>
                    </tr>
                  </thead>
                  <tbody id="scanner-coverage-tbody"></tbody>
                </table>
              </div>
            </div>
          </div>

          <div class="hs-panel">
            <div class="hs-panel-header">
              <h3 style="font-size:1rem;">Tüm Tarama Geçmişi ve Kuyruk İzolasyon Kayıtları</h3>
              <span class="hs-badge">Horizon / Queue: hegosentinel-scans</span>
            </div>
            <div class="hs-table-wrap">
              <table class="hs-table">
                <thead>
                  <tr>
                    <th>Tarama ID</th>
                    <th>Proje</th>
                    <th>Grant / Scope</th>
                    <th>Mod &amp; Kaynak</th>
                    <th>Kapsam Durumu</th>
                    <th>Bulgular (C/H/M/L)</th>
                    <th>İşlemler</th>
                  </tr>
                </thead>
                <tbody id="scanner-history-tbody"></tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- SCREEN 04: VULNERABILITIES -->
        <section id="screen-vulnerabilities" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-panel">
            <div class="hs-panel-header">
              <div>
                <h2 style="font-size:1.15rem;" data-i18n="vulnerabilities.title">Zafiyet Bulguları ve Kanıt İnceleme</h2>
                <p style="color:var(--text-secondary);font-size:0.82rem;" data-i18n="vulnerabilities.subtitle">
                  Dokuz aşamalı gizli veri maskelemesi uygulanmış kanıt özetleri, OWASP ASVS/WSTG eşlemeleri ve kapsam bazlı yanlış pozitif (SEC-010) yönetimi.
                </p>
              </div>
              <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                <select id="filter-priority" class="hs-select" style="width:auto;" aria-label="Öncelik Filtresi">
                  <option value="">Tüm Öncelikler</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select id="filter-rule" class="hs-select" style="width:auto;" aria-label="Kural Filtresi">
                  <option value="">Tüm Kurallar</option>
                  <option value="CODE-001">CODE-001 (Semgrep SAST)</option>
                  <option value="DEP-001">DEP-001 (Trivy SCA)</option>
                  <option value="WEB-HEADER-001">WEB-HEADER-001</option>
                  <option value="WEB-COOKIE-001">WEB-COOKIE-001</option>
                  <option value="WEB-TLS-001">WEB-TLS-001</option>
                  <option value="WEB-REDIRECT-001">WEB-REDIRECT-001</option>
                </select>
                <select id="filter-source" class="hs-select" style="width:auto;" aria-label="Veri Kaynağı Filtresi">
                  <option value="">Tüm Veri Kaynakları</option>
                  <option value="real_scan">Gerçek Tarama (real_scan)</option>
                  <option value="demo_seed">Sentetik Demo (demo_seed)</option>
                </select>
              </div>
            </div>

            <div class="hs-table-wrap">
              <table class="hs-table">
                <thead>
                  <tr>
                    <th>Bulgu &amp; Kural</th>
                    <th>Öncelik &amp; Güven</th>
                    <th>Varlık (Asset) &amp; Kaynak</th>
                    <th>Maskelenmiş Kanıt &amp; SHA-256 Hash</th>
                    <th>Standartlar (OWASP / CWE)</th>
                    <th>Yanlış Pozitif Bastırma (SEC-010)</th>
                  </tr>
                </thead>
                <tbody id="vulnerabilities-tbody"></tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- SCREEN 05: REMEDIATION CENTER -->
        <section id="screen-remediation" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-panel">
            <div class="hs-panel-header">
              <div>
                <h2 style="font-size:1.15rem;" data-i18n="remediation.title">Geliştirici Çözüm ve Yama Merkezi</h2>
                <p style="color:var(--text-secondary);font-size:0.82rem;" data-i18n="remediation.subtitle">
                  Laravel, Next.js ve Node.js için çerçeveye özel kod yamaları, sorumlu geliştirici ataması ve yeniden test hazırlığı.
                </p>
              </div>
              <span class="hs-badge lime">Actionable Developer Queue</span>
            </div>
            <div id="remediation-cards-container" style="display:flex;flex-direction:column;gap:1rem;"></div>
          </div>
        </section>

        <!-- SCREEN 06: RE-TEST COMPARISON -->
        <section id="screen-rechecks" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-panel">
            <div class="hs-panel-header">
              <div>
                <h2 style="font-size:1.15rem;" data-i18n="rechecks.title">Yeniden Test (Re-Test) ve Karşılaştırma Motoru</h2>
                <p style="color:var(--text-secondary);font-size:0.82rem;" data-i18n="rechecks.subtitle">
                  Temel (Baseline) tarama ile düzeltme sonrası taramayı parmak izi ve kapsam versiyonuna göre yan yana karşılaştırın.
                </p>
              </div>
              <span class="hs-badge lime">S1-05 · SEC-010</span>
            </div>

            <form id="recheck-form" style="display:grid;grid-template-columns:1fr 1fr auto;gap:0.85rem;align-items:end;">
              <div>
                <label class="hs-label" for="recheck-baseline-select" data-i18n="rechecks.baselineScan">Temel (Baseline) Tarama</label>
                <select id="recheck-baseline-select" class="hs-select"></select>
              </div>
              <div>
                <label class="hs-label" for="recheck-current-select" data-i18n="rechecks.currentScan">Güncel (Düzeltme Sonrası) Tarama</label>
                <select id="recheck-current-select" class="hs-select"></select>
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="rechecks.runComparison">Karşılaştırmayı Çalıştır</button>
            </form>
          </div>

          <div class="hs-panel">
            <div class="hs-panel-header">
              <h3 style="font-size:1rem;">Karşılaştırma Sonuç Matrisi (verified_fixed / persistent / false_positive / reopened)</h3>
              <span class="hs-badge lime" id="recheck-summary-badge">Hazır</span>
            </div>
            <div class="hs-table-wrap">
              <table class="hs-table">
                <thead>
                  <tr>
                    <th>Kural ID</th>
                    <th>Varlık (Asset)</th>
                    <th>Bulgu Başlığı</th>
                    <th>Önceki Durum</th>
                    <th>Yeniden Test Durumu</th>
                    <th>Teknik Açıklama</th>
                  </tr>
                </thead>
                <tbody id="recheck-items-tbody"></tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- SCREEN 07: REPORTS & NOTIFICATIONS -->
        <section id="screen-reports" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-grid-2">
            <form id="export-report-form" class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1.05rem;" data-i18n="reports.title">Güvenli Rapor Dışa Aktarımı</h2>
                <span class="hs-badge lime">9-Pass Secret Scrubbing</span>
              </div>
              <div>
                <label class="hs-label" for="report-scan-select">Tarama Seçin</label>
                <select id="report-scan-select" class="hs-select"></select>
              </div>
              <div>
                <label class="hs-label" for="report-format-select" data-i18n="reports.exportFormat">Rapor Formatı</label>
                <select id="report-format-select" class="hs-select">
                  <option value="json">JSON (Sanitized Schema v1.0.0)</option>
                  <option value="md">Markdown (.md Developer Report)</option>
                  <option value="html">HTML (Self-Contained CSP Dark Report)</option>
                  <option value="sarif">SARIF 2.1.0 (OASIS Code Scanning)</option>
                  <option value="pdf">PDF-Printable HTML</option>
                </select>
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="reports.downloadReport">Raporu Oluştur &amp; Önizle</button>
              <pre id="report-preview-box" class="hs-code-block" style="max-height:280px;">Rapor önizlemesi burada görüntülenecektir...</pre>
            </form>

            <form id="send-notification-form" class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1.05rem;" data-i18n="reports.sendNotification">Onaylı Bildirim Gönder (SEC-013)</h2>
                <span class="hs-badge lime">Public Sink Guard</span>
              </div>
              <div>
                <label class="hs-label" for="notif-project-select">Proje</label>
                <select id="notif-project-select" class="hs-select"></select>
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="notif-channel" data-i18n="reports.channelLabel">Kanal</label>
                  <select id="notif-channel" class="hs-select">
                    <option value="email">email (Verified Org Domain)</option>
                    <option value="webhook">webhook (Verified Internal Endpoint)</option>
                  </select>
                </div>
                <div>
                  <label class="hs-label" for="notif-recipient" data-i18n="reports.recipientLabel">Alıcı E-Posta / Webhook</label>
                  <input id="notif-recipient" class="hs-input" type="text" required value="dev@hegoweb.local" />
                </div>
              </div>
              <div>
                <label class="hs-label" for="notif-summary" data-i18n="reports.summaryLabel">Maskelenmiş Bildirim Özeti</label>
                <textarea id="notif-summary" class="hs-textarea" rows="3" required>Yetkili güvenlik taraması tamamlandı. Çözüm merkezindeki 3 görevi inceleyip yeniden test başlatabilirsiniz.</textarea>
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="reports.sendNotification">Onaylı Bildirim Gönder (SEC-013)</button>

              <div class="hs-table-wrap" style="margin-top:0.5rem;">
                <table class="hs-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Alıcı</th>
                      <th>Durum</th>
                      <th>Detay</th>
                    </tr>
                  </thead>
                  <tbody id="notifications-tbody"></tbody>
                </table>
              </div>
            </form>
          </div>
        </section>

        <!-- SCREEN 08: SETTINGS, RBAC & AUDIT LOGS -->
        <section id="screen-settings" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-grid-2">
            <div class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1.05rem;" data-i18n="settings.teamRbac">Ekip Üyeleri ve RBAC Yetki Matrisi</h2>
                <span class="hs-badge lime">SEC-011 Multi-Tenant</span>
              </div>
              <div class="hs-table-wrap">
                <table class="hs-table">
                  <thead>
                    <tr>
                      <th>Üye</th>
                      <th>E-Posta</th>
                      <th>RBAC Rolü</th>
                      <th>Yetkili Projeler</th>
                    </tr>
                  </thead>
                  <tbody id="settings-members-tbody"></tbody>
                </table>
              </div>
            </div>

            <form id="invite-member-form" class="hs-panel">
              <div class="hs-panel-header">
                <h3 style="font-size:1rem;" data-i18n="settings.inviteMember">Ekip Üyesi Ekle / Rol Güncelle</h3>
                <span class="hs-badge">Owner Only</span>
              </div>
              <div>
                <label class="hs-label" for="mem-name">Ad Soyad</label>
                <input id="mem-name" class="hs-input" type="text" required value="Demo SecOps" />
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="mem-email">E-Posta</label>
                  <input id="mem-email" class="hs-input" type="email" required value="secops@hegoweb.local" />
                </div>
                <div>
                  <label class="hs-label" for="mem-password">Initial password (min. 10)</label>
                  <input id="mem-password" class="hs-input" type="password" minlength="10" autocomplete="new-password" placeholder="shared out-of-band" />
                </div>
                <div>
                  <label class="hs-label" for="mem-role">RBAC Rolü</label>
                  <select id="mem-role" class="hs-select">
                    <option value="security_lead">security_lead</option>
                    <option value="developer">developer</option>
                    <option value="viewer">viewer</option>
                    <option value="owner">owner</option>
                  </select>
                </div>
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="settings.inviteMember">Ekip Üyesi Ekle / Rol Güncelle</button>
            </form>
          </div>

          <div class="hs-panel">
            <div class="hs-panel-header">
              <h3 style="font-size:1rem;" data-i18n="settings.auditLedger">Değiştirilemez SHA-256 Denetim Kayıtları (Audit Logs)</h3>
              <span class="hs-badge lime" id="settings-audit-integrity-badge">SHA-256 Zinciri Doğrulandı</span>
            </div>
            <div class="hs-table-wrap">
              <table class="hs-table">
                <thead>
                  <tr>
                    <th>Sıra</th>
                    <th>Event ID</th>
                    <th>Aktör &amp; Rol</th>
                    <th>İşlem &amp; Sonuç</th>
                    <th>Açıklama</th>
                    <th>Önceki Hash &rarr; Kayıt Hash</th>
                  </tr>
                </thead>
                <tbody id="settings-audit-tbody"></tbody>
              </table>
            </div>
          </div>
        </section>

        <!-- SCREEN 09: AUTHENTICATION & SESSION MANAGEMENT -->
        <section id="screen-auth" class="hs-screen" style="display:none;flex-direction:column;gap:1.25rem;">
          <div class="hs-grid-2">
            <form id="auth-login-form" class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1.05rem;" data-i18n="auth.loginTab">Giriş Yap</h2>
                <span class="hs-badge lime">Bearer Session Token</span>
              </div>
              <div>
                <label class="hs-label" for="login-email" data-i18n="auth.email">E-Posta Adresi</label>
                <input id="login-email" class="hs-input" type="email" required autocomplete="username" value="${demoMode ? 'admin@hegoweb.local' : ''}" />
              </div>
              <div>
                <label class="hs-label" for="login-password" data-i18n="auth.password">Şifre</label>
                <input id="login-password" class="hs-input" type="password" required autocomplete="current-password" value="${demoMode ? 'HegoSentinel!2026' : ''}" />
              </div>
              <div style="display:flex;gap:0.65rem;flex-wrap:wrap;">
                <button type="submit" class="hs-btn primary" data-i18n="auth.signIn">Güvenli Oturum Aç</button>
                <button type="button" id="auth-logout-btn" class="hs-btn danger" data-i18n="auth.signOut">Oturumu Kapat</button>
              </div>
            </form>

            <form id="auth-register-form" class="hs-panel">
              <div class="hs-panel-header">
                <h2 style="font-size:1.05rem;" data-i18n="auth.registerTab">Yeni Kayıt &amp; Organizasyon</h2>
                <span class="hs-badge">Tenant Isolation</span>
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="reg-name" data-i18n="auth.fullName">Ad Soyad</label>
                  <input id="reg-name" class="hs-input" type="text" required placeholder="Demo Operator" />
                </div>
                <div>
                  <label class="hs-label" for="reg-org" data-i18n="auth.organizationName">Organizasyon Adı</label>
                  <input id="reg-org" class="hs-input" type="text" required placeholder="Example Security Org" />
                </div>
              </div>
              <div class="hs-grid-2">
                <div>
                  <label class="hs-label" for="reg-email" data-i18n="auth.email">E-Posta Adresi</label>
                  <input id="reg-email" class="hs-input" type="email" required placeholder="operator@example.test" />
                </div>
                <div>
                  <label class="hs-label" for="reg-password" data-i18n="auth.password">Şifre (&gt;=10 karakter)</label>
                  <input id="reg-password" class="hs-input" type="password" required minlength="10" autocomplete="new-password" placeholder="min. 10 characters" />
                </div>
              </div>
              <button type="submit" class="hs-btn primary" data-i18n="auth.signUp">Organizasyon &amp; Hesap Oluştur</button>
            </form>
          </div>
        </section>
      </div>
    </main>
  </div>

  <script>
    (function() {
      const I18N = ${i18nJson};
      let currentLocale = 'tr';
      let sessionToken = null;
      const DEMO_MODE = ${demoMode ? 'true' : 'false'};
      const DEMO_PASSWORD = ${demoMode ? JSON.stringify('HegoSentinel!2026') : "''"};
      let state = {
        dashboard: null,
        projects: [],
        scans: [],
        findings: [],
        tasks: [],
        rechecks: [],
        notifications: [],
        organization: null,
        auditLogs: null
      };

      function esc(str) {
        return String(str == null ? '' : str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }

      function showBanner(text, isError) {
        const el = document.getElementById('status-banner');
        if (!el) return;
        el.style.display = 'block';
        el.style.borderColor = isError ? 'var(--severity-critical)' : 'var(--accent-lime)';
        el.style.color = isError ? '#ff8da1' : 'var(--accent-lime)';
        el.textContent = text;
      }

      async function apiCall(method, path, body) {
        const headers = { 'Accept': 'application/json', 'Content-Type': 'application/json' };
        if (sessionToken) {
          headers['Authorization'] = 'Bearer ' + sessionToken;
        }
        const res = await fetch(path, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined
        });
        const json = await res.json();
        if (res.status === 401 && sessionToken && path.indexOf('/auth/') === -1) {
          sessionToken = null;
          showBanner('Session expired or invalid - please sign in again.', true);
          switchScreen('auth');
        }
        return json;
      }

      function switchScreen(screenKey) {
        document.querySelectorAll('.hs-screen').forEach((sec) => {
          sec.style.display = sec.id === 'screen-' + screenKey ? 'flex' : 'none';
        });
        document.querySelectorAll('.hs-nav-btn').forEach((btn) => {
          btn.classList.toggle('active', btn.getAttribute('data-screen') === screenKey);
        });
      }

      function applyTranslations() {
        const dict = I18N[currentLocale];
        document.documentElement.lang = currentLocale;
        const toggleBtn = document.getElementById('locale-toggle-btn');
        if (toggleBtn) toggleBtn.textContent = currentLocale === 'tr' ? 'EN' : 'TR';

        document.querySelectorAll('[data-i18n]').forEach((node) => {
          const keyPath = node.getAttribute('data-i18n').split('.');
          let val = dict;
          for (const k of keyPath) {
            if (val && typeof val === 'object') val = val[k];
          }
          if (typeof val === 'string') {
            node.textContent = val;
          }
        });
      }

      function renderAll() {
        const d = state.dashboard;
        if (d && d.principal) {
          document.getElementById('sidebar-principal-name').textContent = d.principal.name;
          document.getElementById('sidebar-principal-role').textContent = d.principal.role;
          document.getElementById('sidebar-principal-org').textContent = d.principal.organization_id;
        }

        if (d && d.metrics) {
          const m = d.metrics;
          document.getElementById('kpi-total-projects').textContent = String(m.total_projects);
          document.getElementById('kpi-projects-breakdown').textContent =
            m.real_projects + ' Gerçek Hedef · ' + m.demo_projects + ' Sentetik Demo';
          document.getElementById('kpi-total-scans').textContent = String(m.total_scans);
          document.getElementById('kpi-total-findings').textContent = String(m.total_findings);
          document.getElementById('kpi-findings-breakdown').textContent =
            m.real_scan_findings + ' Gerçek Tarama · ' + m.demo_seed_findings + ' Demo Verisi';
          document.getElementById('kpi-open-tasks').textContent = String(m.open_remediation_tasks);
          document.getElementById('kpi-tasks-breakdown').textContent =
            m.verified_closed_tasks + ' Doğrulandı & Kapatıldı';

          const dist = m.risk_distribution || { critical: 0, high: 0, medium: 0, low: 0 };
          const totalF = Math.max(m.total_findings || 1, 1);
          const barsHtml = [
            ['CRITICAL', dist.critical || 0, 'var(--severity-critical)'],
            ['HIGH', dist.high || 0, 'var(--severity-high)'],
            ['MEDIUM', dist.medium || 0, 'var(--severity-medium)'],
            ['LOW', dist.low || 0, 'var(--severity-low)']
          ].map(([label, count, color]) => {
            const pct = Math.min(100, Math.round((count / totalF) * 100));
            return '<div>' +
              '<div style="display:flex;justify-content:space-between;font-size:0.76rem;margin-bottom:0.2rem;">' +
                '<span class="mono" style="font-weight:600;">' + label + '</span>' +
                '<span class="mono">' + count + ' bulgu (' + pct + '%)</span>' +
              '</div>' +
              '<div style="height:7px;background:#161922;border-radius:4px;overflow:hidden;">' +
                '<div style="width:' + Math.max(pct, count > 0 ? 8 : 0) + '%;height:100%;background:' + color + ';"></div>' +
              '</div>' +
            '</div>';
          }).join('');
          document.getElementById('dashboard-risk-bars').innerHTML = barsHtml;
        }

        if (d && d.security_posture) {
          const sp = d.security_posture;
          document.getElementById('dashboard-posture-list').innerHTML = [
            ['Restricted Remote', sp.restricted_remote_mode],
            ['Worker İzolasyonu', sp.worker_isolation],
            ['Egress Broker', sp.egress_broker_policy],
            ['Semgrep & Trivy', 'v' + sp.pinned_semgrep_version + ' / v' + sp.pinned_trivy_version],
            ['Denetim Zinciri', sp.audit_chain_valid ? 'DOĞRULANDI (' + sp.audit_entries_checked + ' kayıt)' : 'BOZUK']
          ].map(([k, v]) =>
            '<div style="padding:0.55rem;background:var(--bg-surface);border:1px solid var(--border-hairline);border-radius:6px;">' +
              '<div class="mono" style="font-size:0.68rem;color:var(--text-secondary);">' + esc(k) + '</div>' +
              '<div class="mono" style="font-size:0.76rem;color:var(--accent-lime);margin-top:0.15rem;">' + esc(v) + '</div>' +
            '</div>'
          ).join('');
        }

        // Recent scans on dashboard
        const recentScansTbody = document.getElementById('dashboard-recent-scans-tbody');
        if (recentScansTbody) {
          recentScansTbody.innerHTML = (state.scans || []).slice(0, 5).map((s) =>
            '<tr>' +
              '<td class="mono">' + esc(s.id) + '</td>' +
              '<td>' + esc(s.project_name) + '</td>' +
              '<td><span class="hs-badge ' + (s.data_source === 'real_scan' ? 'lime' : '') + '">' + esc(s.data_source) + '</span></td>' +
              '<td><span class="hs-badge">' + esc(s.global_coverage_status) + '</span></td>' +
              '<td class="mono">' + esc(s.total_findings) + '</td>' +
            '</tr>'
          ).join('');
        }

        // Recent audit on dashboard
        const recentAuditTbody = document.getElementById('dashboard-recent-audit-tbody');
        const auditEntries = (state.auditLogs && state.auditLogs.entries) ? state.auditLogs.entries : [];
        if (recentAuditTbody) {
          recentAuditTbody.innerHTML = auditEntries.slice(0, 5).map((a) =>
            '<tr>' +
              '<td class="mono">#' + esc(a.sequence) + '</td>' +
              '<td class="mono">' + esc(a.actor_role) + '</td>' +
              '<td class="mono">' + esc(a.action) + '</td>' +
              '<td><span class="hs-badge ' + (a.outcome === 'allow' ? 'lime' : 'critical') + '">' + esc(a.outcome) + '</span></td>' +
              '<td class="mono">' + esc(String(a.entry_hash || '').slice(0, 12)) + '…</td>' +
            '</tr>'
          ).join('');
        }

        // Projects table & selects
        const projectsTbody = document.getElementById('projects-tbody');
        if (projectsTbody) {
          projectsTbody.innerHTML = (state.projects || []).map((p) => {
            const asset = (p.assets && p.assets[0]) || {};
            const grant = (p.grants && p.grants[0]) || {};
            return '<tr>' +
              '<td><strong>' + esc(p.name) + '</strong><div class="mono" style="font-size:0.72rem;color:var(--text-secondary);">' + esc(p.id) + '</div></td>' +
              '<td><span class="hs-badge ' + (p.is_demo ? '' : 'lime') + '">' + (p.is_demo ? 'SENTETİK DEMO' : 'GERÇEK HEDEF') + '</span></td>' +
              '<td class="mono">' + esc(p.environment) + ' · ' + esc((p.stack || []).join(', ')) + '</td>' +
              '<td class="mono">' + esc(asset.hostname || 'demo.example.test') + '<div style="font-size:0.7rem;color:var(--text-secondary);">' + esc(asset.repository_path || '') + '</div></td>' +
              '<td class="mono">' + esc(grant.grant_id || 'YOK') + ' (v' + esc(grant.scope_version || 0) + ')</td>' +
              '<td><button type="button" class="hs-btn primary quick-scan-proj-btn" data-proj="' + esc(p.id) + '" style="padding:0.3rem 0.6rem;font-size:0.74rem;">Tara</button></td>' +
            '</tr>';
          }).join('');
        }

        const projOptions = (state.projects || []).map((p) =>
          '<option value="' + esc(p.id) + '">' + esc(p.name) + ' (' + (p.is_demo ? 'Demo' : 'Gerçek') + ')</option>'
        ).join('');
        ['grant-proj-id', 'scan-project-select', 'notif-project-select'].forEach((id) => {
          const el = document.getElementById(id);
          if (el && projOptions) el.innerHTML = projOptions;
        });

        // Scanner coverage matrix & history
        const latestScan = (state.scans && state.scans[0]) || null;
        if (latestScan) {
          document.getElementById('scanner-active-scan-badge').textContent = latestScan.id + ' (' + latestScan.global_coverage_status + ')';
          const covTbody = document.getElementById('scanner-coverage-tbody');
          if (covTbody) {
            covTbody.innerHTML = (latestScan.coverage_checks || []).map((c) =>
              '<tr>' +
                '<td class="mono"><strong>' + esc(c.rule_id) + '</strong></td>' +
                '<td class="mono">v' + esc(c.rule_version) + '</td>' +
                '<td><span class="hs-badge ' + (c.status === 'executed' ? 'lime' : 'critical') + '">' + esc(c.status) + '</span></td>' +
                '<td class="mono">' + esc(c.tool_version || 'native-engine') + '</td>' +
                '<td>' + esc(c.reason || 'Doğrulandı (executed)') + '</td>' +
              '</tr>'
            ).join('');
          }
        }

        const scanHistoryTbody = document.getElementById('scanner-history-tbody');
        if (scanHistoryTbody) {
          scanHistoryTbody.innerHTML = (state.scans || []).map((s) =>
            '<tr>' +
              '<td class="mono">' + esc(s.id) + '</td>' +
              '<td>' + esc(s.project_name) + '</td>' +
              '<td class="mono">' + esc(s.grant_id) + ' (v' + esc(s.scope_version) + ')</td>' +
              '<td class="mono">' + esc(s.mode) + ' · <span class="hs-badge ' + (s.data_source === 'real_scan' ? 'lime' : '') + '">' + esc(s.data_source) + '</span></td>' +
              '<td><span class="hs-badge ' + (s.status === 'completed' ? 'lime' : 'critical') + '">' + esc(s.status) + ' / ' + esc(s.global_coverage_status) + '</span></td>' +
              '<td class="mono">' + esc(s.total_findings) + ' (' + esc(s.critical_count) + '/' + esc(s.high_count) + '/' + esc(s.medium_count) + '/' + esc(s.low_count) + ')</td>' +
              '<td><button type="button" class="hs-btn export-scan-Jump-btn" data-scan="' + esc(s.id) + '" style="padding:0.25rem 0.55rem;font-size:0.73rem;">Rapor</button></td>' +
            '</tr>'
          ).join('');
        }

        // Scan selects for Rechecks & Reports
        const scanOptions = (state.scans || []).map((s) =>
          '<option value="' + esc(s.id) + '">' + esc(s.id) + ' — ' + esc(s.project_name) + ' (' + esc(s.total_findings) + ' bulgu)</option>'
        ).join('');
        ['recheck-baseline-select', 'recheck-current-select', 'report-scan-select'].forEach((id) => {
          const el = document.getElementById(id);
          if (el && scanOptions) el.innerHTML = scanOptions;
        });

        // Vulnerabilities table
        renderFindingsTable();

        // Remediation tasks
        const remContainer = document.getElementById('remediation-cards-container');
        if (remContainer) {
          remContainer.innerHTML = (state.tasks || []).map((t) =>
            '<div class="hs-panel" style="background:var(--bg-surface);">' +
              '<div class="hs-panel-header">' +
                '<div>' +
                  '<span class="hs-badge ' + esc(t.priority) + '">' + esc(String(t.priority).toUpperCase()) + '</span> ' +
                  '<strong style="margin-left:0.4rem;">' + esc(t.title) + '</strong>' +
                  '<div class="mono" style="font-size:0.72rem;color:var(--text-secondary);margin-top:0.2rem;">' +
                    esc(t.id) + ' · Kural: ' + esc(t.rule_id) + ' · Çerçeve: ' + esc(t.framework) + ' · Sorumlu: ' + esc(t.assigned_to_name) +
                  '</div>' +
                '</div>' +
                '<span class="hs-badge ' + (t.status === 'verified_closed' ? 'lime' : '') + '">' + esc(t.status) + '</span>' +
              '</div>' +
              '<p style="font-size:0.83rem;color:var(--text-secondary);">' + esc(t.guidance_summary) + '</p>' +
              '<pre class="hs-code-block">' + esc(t.code_patch_example || '// Yapılandırma sertleştirmesi uygulayın ve yeniden test edin.') + '</pre>' +
              '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">' +
                '<span class="mono" style="font-size:0.73rem;color:var(--text-secondary);">Doğrulama: ' + esc(t.validation_command) + '</span>' +
                '<div style="display:flex;gap:0.4rem;flex-wrap:wrap;">' +
                  '<button type="button" class="hs-btn task-status-btn" data-id="' + esc(t.id) + '" data-status="in_progress">in_progress</button>' +
                  '<button type="button" class="hs-btn primary task-status-btn" data-id="' + esc(t.id) + '" data-status="ready_for_retest">ready_for_retest</button>' +
                '</div>' +
              '</div>' +
            '</div>'
          ).join('');
        }

        // Rechecks table
        const latestRecheck = (state.rechecks && state.rechecks[0]) || null;
        const recheckTbody = document.getElementById('recheck-items-tbody');
        if (recheckTbody) {
          if (latestRecheck && latestRecheck.items) {
            const c = latestRecheck.counts || {};
            document.getElementById('recheck-summary-badge').textContent =
              'verified_fixed: ' + (c.verified_fixed || 0) + ' · persistent: ' + (c.persistent || 0) + ' · false_positive: ' + (c.false_positive || 0);
            recheckTbody.innerHTML = latestRecheck.items.map((item) =>
              '<tr>' +
                '<td class="mono">' + esc(item.rule_id) + '</td>' +
                '<td class="mono">' + esc(item.asset_key) + '</td>' +
                '<td>' + esc(item.title) + '</td>' +
                '<td class="mono">' + esc(item.previous_state) + '</td>' +
                '<td><span class="hs-badge ' + (item.recheck_state === 'verified_fixed' ? 'lime' : 'high') + '">' + esc(item.recheck_state) + '</span></td>' +
                '<td>' + esc(item.explanation) + '</td>' +
              '</tr>'
            ).join('');
          } else {
            recheckTbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-secondary);">Karşılaştırma görmek için yukarıdan iki tarama seçip "Karşılaştırmayı Çalıştır" düğmesine tıklayın.</td></tr>';
          }
        }

        // Notifications table
        const notifTbody = document.getElementById('notifications-tbody');
        if (notifTbody) {
          notifTbody.innerHTML = (state.notifications || []).slice(0, 6).map((n) =>
            '<tr>' +
              '<td class="mono">' + esc(n.id) + '</td>' +
              '<td class="mono">' + esc(n.recipient) + '</td>' +
              '<td><span class="hs-badge ' + (n.status === 'dispatched' ? 'lime' : 'critical') + '">' + esc(n.status) + '</span></td>' +
              '<td>' + esc(n.rejection_reason || n.sanitized_summary) + '</td>' +
            '</tr>'
          ).join('');
        }

        // Settings members & audit ledger
        const memTbody = document.getElementById('settings-members-tbody');
        if (memTbody && state.organization && state.organization.members) {
          memTbody.innerHTML = state.organization.members.map((m) =>
            '<tr>' +
              '<td><strong>' + esc(m.name) + '</strong></td>' +
              '<td class="mono">' + esc(m.email) + '</td>' +
              '<td><span class="hs-badge lime">' + esc(m.role) + '</span></td>' +
              '<td class="mono">' + esc((m.allowed_project_ids || []).join(', ')) + '</td>' +
            '</tr>'
          ).join('');
        }

        const settingsAuditTbody = document.getElementById('settings-audit-tbody');
        if (settingsAuditTbody) {
          settingsAuditTbody.innerHTML = auditEntries.slice(0, 20).map((a) =>
            '<tr>' +
              '<td class="mono">#' + esc(a.sequence) + '</td>' +
              '<td class="mono">' + esc(a.event_id) + '</td>' +
              '<td class="mono">' + esc(a.actor_user_id) + ' (' + esc(a.actor_role) + ')</td>' +
              '<td><span class="hs-badge ' + (a.outcome === 'allow' ? 'lime' : 'critical') + '">' + esc(a.action) + ' : ' + esc(a.outcome) + '</span></td>' +
              '<td>' + esc(a.detail) + '</td>' +
              '<td class="mono" style="font-size:0.7rem;">' + esc(String(a.prev_hash || '').slice(0, 10)) + '… &rarr; ' + esc(String(a.entry_hash || '').slice(0, 10)) + '…</td>' +
            '</tr>'
          ).join('');
        }
      }

      function renderFindingsTable() {
        const prioFilter = (document.getElementById('filter-priority') || {}).value || '';
        const ruleFilter = (document.getElementById('filter-rule') || {}).value || '';
        const srcFilter = (document.getElementById('filter-source') || {}).value || '';

        const filtered = (state.findings || []).filter((f) => {
          if (prioFilter && f.risk_priority !== prioFilter) return false;
          if (ruleFilter && f.rule_id !== ruleFilter) return false;
          if (srcFilter && f.data_source !== srcFilter) return false;
          return true;
        });

        const tbody = document.getElementById('vulnerabilities-tbody');
        if (!tbody) return;
        tbody.innerHTML = filtered.map((f) => {
          const std = f.standards || {};
          const stdList = [].concat(std.cwe || [], std.owasp_asvs_5_0 || [], std.owasp_wstg_4_2 || []).slice(0, 4).join(' · ');
          return '<tr>' +
            '<td><strong>' + esc(f.title) + '</strong><div class="mono" style="font-size:0.72rem;color:var(--accent-lime);">' + esc(f.rule_id) + ' · ' + esc(f.id) + '</div></td>' +
            '<td><span class="hs-badge ' + esc(f.risk_priority) + '">' + esc(String(f.risk_priority).toUpperCase()) + '</span><div class="mono" style="font-size:0.7rem;margin-top:0.2rem;">Güven: ' + esc(f.confidence) + '</div></td>' +
            '<td class="mono">' + esc(f.asset_key) + '<div style="margin-top:0.2rem;"><span class="hs-badge ' + (f.data_source === 'real_scan' ? 'lime' : '') + '">' + esc(f.data_source) + '</span></div></td>' +
            '<td><div style="font-size:0.78rem;">' + esc(f.evidence_summary) + '</div><div class="mono" style="font-size:0.68rem;color:var(--text-secondary);margin-top:0.2rem;">SHA-256: ' + esc(String(f.evidence_hash || '').slice(0, 16)) + '…</div></td>' +
            '<td class="mono" style="font-size:0.72rem;">' + esc(stdList) + '</td>' +
            '<td><button type="button" class="hs-btn suppress-finding-btn" data-id="' + esc(f.id) + '" style="padding:0.28rem 0.55rem;font-size:0.72rem;">Bastır (SEC-010)</button></td>' +
          '</tr>';
        }).join('');
      }

      async function loadAllData() {
        if (!sessionToken) {
          renderAll();
          return;
        }
        const [dash, projs, scans, finds, tasks, rechecks, notifs, org, aud] = await Promise.all([
          apiCall('GET', '/api/v1/dashboard'),
          apiCall('GET', '/api/v1/projects'),
          apiCall('GET', '/api/v1/scans'),
          apiCall('GET', '/api/v1/findings'),
          apiCall('GET', '/api/v1/remediation-tasks'),
          apiCall('GET', '/api/v1/rechecks'),
          apiCall('GET', '/api/v1/notifications'),
          apiCall('GET', '/api/v1/organization'),
          apiCall('GET', '/api/v1/audit-logs')
        ]);
        if (dash.ok) state.dashboard = dash.data;
        if (projs.ok) state.projects = projs.data;
        if (scans.ok) state.scans = scans.data;
        if (finds.ok) state.findings = finds.data;
        if (tasks.ok) state.tasks = tasks.data;
        if (rechecks.ok) state.rechecks = rechecks.data;
        if (notifs.ok) state.notifications = notifs.data;
        if (org.ok) state.organization = org.data;
        if (aud.ok) state.auditLogs = aud.data;
        renderAll();
      }

      // Navigation clicks
      document.querySelectorAll('.hs-nav-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          switchScreen(btn.getAttribute('data-screen'));
        });
      });

      document.querySelectorAll('[data-goto]').forEach((btn) => {
        btn.addEventListener('click', () => {
          switchScreen(btn.getAttribute('data-goto'));
        });
      });

      document.getElementById('hero-launch-scan-btn').addEventListener('click', () => switchScreen('scanner'));
      document.getElementById('hero-new-project-btn').addEventListener('click', () => switchScreen('projects'));

      // Locale switch
      document.getElementById('locale-toggle-btn').addEventListener('click', () => {
        currentLocale = currentLocale === 'tr' ? 'en' : 'tr';
        applyTranslations();
      });

      // Quick RBAC Role Switcher (performs real login against /api/v1/auth/login)
      document.getElementById('quick-role-select').addEventListener('change', async (e) => {
        const email = e.target.value;
        const res = await apiCall('POST', '/api/v1/auth/login', {
          email,
          password: DEMO_PASSWORD
        });
        if (res.ok && res.data && res.data.token) {
          sessionToken = res.data.token;
          showBanner('Aktif RBAC oturumu değiştirildi: ' + res.data.principal.name + ' (' + res.data.principal.role + ')', false);
          await loadAllData();
        } else {
          showBanner(res.message || 'Oturum değiştirilemedi', true);
        }
      });

      // Emergency Stop (SEC-012)
      async function triggerEmergencyStop() {
        const scanId = (state.scans && state.scans[0]) ? state.scans[0].id : null;
        const projId = (state.projects && state.projects[0]) ? state.projects[0].id : null;
        const res = await apiCall('POST', '/api/v1/emergency-stop', {
          project_id: projId,
          scan_run_id: scanId,
          reason: 'Operatör tarafından web arayüzünden SEC-012 acil durdurma tetiklendi'
        });
        if (res.ok) {
          showBanner('SEC-012 Acil Durdurma uygulandı (' + res.data.id + '). Alt süreçler sonlandırıldı.', false);
          await loadAllData();
        } else {
          showBanner('SEC-012 Engellendi: ' + (res.message || 'Yetkisiz işlem'), true);
        }
      }
      document.getElementById('hero-emergency-stop-btn').addEventListener('click', triggerEmergencyStop);
      document.getElementById('scanner-estop-btn').addEventListener('click', triggerEmergencyStop);

      // Create Project Form
      document.getElementById('create-project-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await apiCall('POST', '/api/v1/projects', {
          name: document.getElementById('proj-name').value,
          environment: document.getElementById('proj-env').value,
          stack: document.getElementById('proj-stack').value.split(','),
          hostname: document.getElementById('proj-host').value,
          repository_path: document.getElementById('proj-repo').value,
          written_permission_ref: document.getElementById('proj-written-ref').value
        });
        if (res.ok) {
          showBanner('Proje ve ScopeAuthorizationGrant oluşturuldu: ' + res.data.name, false);
          await loadAllData();
        } else {
          showBanner(res.message || 'Proje oluşturulamadı', true);
        }
      });

      // Approve Grant Form
      document.getElementById('approve-grant-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const projId = document.getElementById('grant-proj-id').value;
        const res = await apiCall('POST', '/api/v1/projects/' + encodeURIComponent(projId) + '/grants', {
          written_permission_ref: document.getElementById('grant-written-ref').value,
          domain_control_proof: document.getElementById('grant-dns-proof').value,
          hostname: document.getElementById('grant-host').value
        });
        if (res.ok) {
          showBanner('Yeni Kapsam Yetkisi onaylandı: ' + res.data.grant_id + ' (v' + res.data.scope_version + ')', false);
          await loadAllData();
        } else {
          showBanner(res.message || 'Kapsam yetkisi reddedildi', true);
        }
      });

      // Launch Scan Form
      document.getElementById('launch-scan-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await apiCall('POST', '/api/v1/scans', {
          project_id: document.getElementById('scan-project-select').value,
          mode: document.getElementById('scan-mode-select').value,
          fixture_variant: document.getElementById('scan-variant-select').value,
          repository_path: document.getElementById('scan-repo-select').value
        });
        if (res.ok) {
          showBanner('Tarama tamamlandı: ' + res.data.id + ' (' + res.data.total_findings + ' bulgu)', false);
          await loadAllData();
        } else {
          const reason = (res.data && res.data.cancelled_reason) || res.message || 'Tarama politikası tarafından engellendi';
          showBanner('Tarama Engellendi (Fail-Closed): ' + reason, true);
          await loadAllData();
        }
      });

      // Filter changes on Vulnerabilities
      ['filter-priority', 'filter-rule', 'filter-source'].forEach((id) => {
        document.getElementById(id).addEventListener('change', renderFindingsTable);
      });

      // Delegated clicks for dynamic buttons
      document.body.addEventListener('click', async (e) => {
        const target = e.target;
        if (!(target instanceof HTMLElement)) return;

        if (target.classList.contains('quick-scan-proj-btn')) {
          const projId = target.getAttribute('data-proj');
          document.getElementById('scan-project-select').value = projId;
          switchScreen('scanner');
        }

        if (target.classList.contains('export-scan-Jump-btn')) {
          const scanId = target.getAttribute('data-scan');
          document.getElementById('report-scan-select').value = scanId;
          switchScreen('reports');
        }

        if (target.classList.contains('suppress-finding-btn')) {
          const findingId = target.getAttribute('data-id');
          const res = await apiCall('POST', '/api/v1/findings/' + encodeURIComponent(findingId) + '/suppress', {
            rationale: 'Doğrulanmış kenar WAF kuralı ve mimari telafi edici kontrol (SEC-010).'
          });
          if (res.ok) {
            showBanner('Kapsam bazlı yanlış pozitif (false_positive) bastırma kaydı oluşturuldu: ' + res.data.id, false);
            await loadAllData();
          } else {
            showBanner(res.message || 'Bastırma işlemi reddedildi', true);
          }
        }

        if (target.classList.contains('task-status-btn')) {
          const taskId = target.getAttribute('data-id');
          const status = target.getAttribute('data-status');
          const res = await apiCall('PATCH', '/api/v1/remediation-tasks/' + encodeURIComponent(taskId), {
            status
          });
          if (res.ok) {
            showBanner('Düzeltme görevi güncellendi: ' + taskId + ' -> ' + status, false);
            await loadAllData();
          } else {
            showBanner(res.message || 'Görev güncellenemedi', true);
          }
        }
      });

      // Recheck Comparison Form
      document.getElementById('recheck-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await apiCall('POST', '/api/v1/rechecks', {
          baseline_scan_id: document.getElementById('recheck-baseline-select').value,
          current_scan_id: document.getElementById('recheck-current-select').value
        });
        if (res.ok) {
          showBanner('Yeniden test karşılaştırması tamamlandı: ' + res.data.id, false);
          await loadAllData();
        } else {
          showBanner(res.message || 'Karşılaştırma başarısız', true);
        }
      });

      // Export Report Form
      document.getElementById('export-report-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const scanId = document.getElementById('report-scan-select').value;
        const fmt = document.getElementById('report-format-select').value;
        const res = await apiCall('GET', '/api/v1/scans/' + encodeURIComponent(scanId) + '/export?format=' + encodeURIComponent(fmt));
        if (res.ok && res.data) {
          document.getElementById('report-preview-box').textContent = res.data.content;
          showBanner('Rapor dışa aktarıldı: ' + res.data.filename + ' (' + res.data.content_type + ')', false);
        } else {
          showBanner(res.message || 'Rapor dışa aktarılamadı', true);
        }
      });

      // Send Notification Form (SEC-013)
      document.getElementById('send-notification-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const scanId = (state.scans && state.scans[0]) ? state.scans[0].id : 'SCAN-INIT';
        const res = await apiCall('POST', '/api/v1/notifications', {
          project_id: document.getElementById('notif-project-select').value,
          scan_run_id: scanId,
          channel: document.getElementById('notif-channel').value,
          recipient: document.getElementById('notif-recipient').value,
          summary: document.getElementById('notif-summary').value
        });
        if (res.ok) {
          showBanner('Onaylı bildirim gönderildi: ' + res.data.id + ' -> ' + res.data.recipient, false);
          await loadAllData();
        } else {
          showBanner('SEC-013 Bildirim Engellendi: ' + (res.message || 'Doğrulanmamış alıcı'), true);
          await loadAllData();
        }
      });

      // Invite Member Form
      document.getElementById('invite-member-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const orgProjectIds = (state.projects || []).map((p) => p.id).filter(Boolean);
        const res = await apiCall('POST', '/api/v1/organization/members', {
          name: document.getElementById('mem-name').value,
          email: document.getElementById('mem-email').value,
          password: document.getElementById('mem-password').value || undefined,
          role: document.getElementById('mem-role').value,
          allowed_project_ids: orgProjectIds
        });
        if (res.ok) {
          showBanner('Ekip üyesi ve RBAC rolü güncellendi.', false);
          await loadAllData();
        } else {
          showBanner(res.message || 'Ekip üyesi eklenemedi (SEC-011)', true);
        }
      });

      // Auth Login Form
      document.getElementById('auth-login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await apiCall('POST', '/api/v1/auth/login', {
          email: document.getElementById('login-email').value,
          password: document.getElementById('login-password').value
        });
        if (res.ok && res.data) {
          sessionToken = res.data.token;
          showBanner('Oturum açıldı: ' + res.data.principal.name + ' (' + res.data.principal.role + ')', false);
          await loadAllData();
          switchScreen('dashboard');
        } else {
          showBanner(res.message || 'Giriş başarısız', true);
        }
      });

      document.getElementById('auth-logout-btn').addEventListener('click', async () => {
        await apiCall('POST', '/api/v1/auth/logout', {});
        sessionToken = null;
        state = { dashboard: null, projects: [], scans: [], findings: [], tasks: [], rechecks: [], notifications: [], organization: null, auditLogs: null };
        showBanner('Signed out.', false);
        switchScreen('auth');
        renderAll();
      });

      // Auth Register Form
      document.getElementById('auth-register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const res = await apiCall('POST', '/api/v1/auth/register', {
          name: document.getElementById('reg-name').value,
          organization_name: document.getElementById('reg-org').value,
          email: document.getElementById('reg-email').value,
          password: document.getElementById('reg-password').value,
          preferred_locale: currentLocale
        });
        if (res.ok && res.data) {
          sessionToken = res.data.token;
          showBanner('Yeni organizasyon ve hesap oluşturuldu: ' + res.data.principal.organization_name, false);
          await loadAllData();
          switchScreen('dashboard');
        } else {
          showBanner(res.message || 'Kayıt başarısız', true);
        }
      });

      // Initial load
      applyTranslations();
      if (DEMO_MODE) {
        // Explicit operator-enabled demo mode only: real password login as the demo owner.
        void (async () => {
          const res = await apiCall('POST', '/api/v1/auth/login', { email: 'admin@hegoweb.local', password: DEMO_PASSWORD });
          if (res.ok && res.data && res.data.token) {
            sessionToken = res.data.token;
            await loadAllData();
          } else {
            showBanner(res.message || 'Demo login failed - start the API with HEGOSENTINEL_DEMO_MODE=1', true);
            switchScreen('auth');
          }
        })();
      } else {
        // Production-safe default: no identity, no data until a real sign-in succeeds.
        const roleSelect = document.getElementById('quick-role-select');
        if (roleSelect) {
          const roleLabel = document.querySelector('label[for="quick-role-select"]');
          roleSelect.remove();
          if (roleLabel) roleLabel.remove();
        }
        switchScreen('auth');
      }
    })();
  </script>
</body>
</html>`;
}

function proxyToLaravelApi(
  req: IncomingMessage,
  res: ServerResponse,
  apiUpstreamUrl: string
): void {
  const upstream = new URL(apiUpstreamUrl);
  const target = new URL(req.url ?? '/api/v1/health', upstream);
  // Dot-segments (including %2e%2e) are normalised by URL: re-check after parsing so the proxy can
  // only ever reach /api/v1/* on the configured upstream origin.
  if (target.origin !== upstream.origin || !target.pathname.startsWith('/api/v1/')) {
    res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, error: 'bad_request', message: 'Invalid API path' }));
    return;
  }
  const MAX_BODY_BYTES = 1024 * 1024;
  let bodyText = '';
  let tooLarge = false;
  req.on('data', (chunk: unknown) => {
    if (tooLarge) return;
    bodyText += String(chunk ?? '');
    if (bodyText.length > MAX_BODY_BYTES) {
      tooLarge = true;
      res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'payload_too_large', message: 'Request body exceeds 1 MiB' }));
    }
  });
  req.on('end', () => {
    if (tooLarge) return;
    const forwardHeaders: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    };
    const rawHeaders = req.headers;
    if (typeof rawHeaders.authorization === 'string') {
      forwardHeaders.Authorization = rawHeaders.authorization;
    }

    const method = (req.method ?? 'GET').toUpperCase();
    void fetch(target.toString(), {
      method,
      headers: forwardHeaders,
      body: method !== 'GET' && method !== 'HEAD' && bodyText.length > 0 ? bodyText : undefined
    })
      .then(async (upstreamRes) => {
        const text = await upstreamRes.text();
        res.writeHead(upstreamRes.status, {
          'Content-Type': upstreamRes.headers.get('content-type') ?? 'application/json; charset=utf-8',
          'X-Content-Type-Options': 'nosniff'
        });
        res.end(text);
      })
      .catch((err: unknown) => {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(
          JSON.stringify({
            ok: false,
            error: 'bad_gateway',
            message: `Laravel API upstream (${apiUpstreamUrl}) unreachable: ${err instanceof Error ? err.message : String(err)}`
          })
        );
      });
  });
}

export function handleWebPlatformRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: WebPlatformServerOptions = {}
): void {
  const apiUpstreamUrl =
    options.apiUpstreamUrl ?? process.env.NEXT_PUBLIC_API_URL ?? 'http://127.0.0.1:8000';
  const urlPath = (req.url ?? '/').split('?')[0];

  if (urlPath.startsWith('/api/v1/')) {
    proxyToLaravelApi(req, res, apiUpstreamUrl);
    return;
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  if (urlPath === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('User-agent: *\nAllow: /\nSitemap: http://127.0.0.1:3000/sitemap.xml\n');
    return;
  }

  if (urlPath === '/sitemap.xml') {
    res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8' });
    res.end(
      '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://127.0.0.1:3000/</loc></url></urlset>\n'
    );
    return;
  }

  if (urlPath === '/llms.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(
      '# HegoSentinel Security Platform\n> Authorized security assessment, evidence normalization, developer remediation, and re-test verification platform.\n'
    );
    return;
  }

  const html = renderPlatformAppDocument({ demoMode: options.demoMode ?? isDemoModeEnabled() });
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

export function createWebPlatformServer(options: WebPlatformServerOptions = {}) {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    handleWebPlatformRequest(req, res, options);
  });
}

const isMainModule =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMainModule || process.argv.includes('--serve')) {
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';
  const server = createWebPlatformServer({ port, host });
  server.listen(port, host, () => {
    console.log(`[HegoSentinel Web Platform] Listening on http://${host}:${port}`);
  });
}
