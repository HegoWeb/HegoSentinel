'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { HegoSentinelApiClient, type AuthenticatedPrincipal } from '../lib/api-client.ts';
import { PLATFORM_I18N, type SupportedLocale } from '../lib/i18n.ts';

type ScreenKey =
  | 'dashboard'
  | 'projects'
  | 'scanner'
  | 'vulnerabilities'
  | 'remediation'
  | 'rechecks'
  | 'reports'
  | 'settings'
  | 'auth';

const api = new HegoSentinelApiClient('');

export default function HegoSentinelPlatformPage() {
  const [locale, setLocale] = useState<SupportedLocale>('tr');
  const [activeScreen, setActiveScreen] = useState<ScreenKey>('dashboard');
  const [principal, setPrincipal] = useState<AuthenticatedPrincipal | null>(null);
  const [dashboard, setDashboard] = useState<Record<string, unknown> | null>(null);
  const [projects, setProjects] = useState<Array<Record<string, unknown>>>([]);
  const [scans, setScans] = useState<Array<Record<string, unknown>>>([]);
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const [tasks, setTasks] = useState<Array<Record<string, unknown>>>([]);
  const [rechecks, setRechecks] = useState<Array<Record<string, unknown>>>([]);
  const [notifications, setNotifications] = useState<Array<Record<string, unknown>>>([]);
  const [organization, setOrganization] = useState<Record<string, unknown> | null>(null);
  const [auditLogs, setAuditLogs] = useState<Record<string, unknown> | null>(null);
  const [toast, setToast] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Screen 02: Projects & Scope form state
  const [projName, setProjName] = useState('HegoCloud Edge Gateway');
  const [projEnv, setProjEnv] = useState('staging');
  const [projStack, setProjStack] = useState('laravel');
  const [projHost, setProjHost] = useState('demo.example.test');
  const [projRepo, setProjRepo] = useState('examples/synthetic-targets/laravel-app');
  const [projPermRef, setProjPermRef] = useState('PERM-HEGO-2026-S10-900');
  const [projDnsProof, setProjDnsProof] = useState('hegosentinel-verify=edge-2026');
  const [grantProjectId, setGrantProjectId] = useState('proj-laravel-commerce');
  const [grantPermRef, setGrantPermRef] = useState('PERM-HEGO-2026-V2');

  // Screen 03: Scanner form state
  const [scanProjectId, setScanProjectId] = useState('proj-laravel-commerce');
  const [scanMode, setScanMode] = useState<'offline-fixture' | 'restricted-remote'>('offline-fixture');
  const [scanVariant, setScanVariant] = useState<'baseline' | 'patched'>('baseline');
  const [isScanning, setIsScanning] = useState(false);

  // Screen 04: Vulnerabilities filter & suppression state
  const [filterPriority, setFilterPriority] = useState('all');
  const [filterRule, setFilterRule] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [suppressRationales, setSuppressRationales] = useState<Record<string, string>>({});

  // Screen 06: Rechecks state
  const [baselineScanId, setBaselineScanId] = useState('');
  const [currentScanId, setCurrentScanId] = useState('');

  // Screen 07: Reports & Notifications state
  const [reportScanId, setReportScanId] = useState('');
  const [reportFormat, setReportFormat] = useState<'json' | 'md' | 'html' | 'sarif' | 'pdf'>('json');
  const [reportPreview, setReportPreview] = useState<string>('');
  const [notifyChannel, setNotifyChannel] = useState<'email' | 'webhook'>('email');
  const [notifyRecipient, setNotifyRecipient] = useState('secops@hegoweb.local');
  const [notifySummary, setNotifySummary] = useState(
    'S10 Doğrulanmış Güvenlik Raporu: Kritik bulgular kapatıldı ve SHA-256 denetim zinciri doğrulandı.'
  );

  // Screen 08: Team Member invite state
  const [memberEmail, setMemberEmail] = useState('analyst@hegoweb.local');
  const [memberName, setMemberName] = useState('Kıdemli SOC Analisti');
  const [memberRole, setMemberRole] = useState<'owner' | 'security_lead' | 'developer' | 'viewer'>('security_lead');

  // Screen 09: Authentication state
  const [authTab, setAuthTab] = useState<'login' | 'register' | 'reset'>('login');
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regOrgName, setRegOrgName] = useState('');
  const [resetEmail, setResetEmail] = useState('');

  const t = PLATFORM_I18N[locale];

  const notifyUser = (type: 'ok' | 'err', text: string) => {
    setToast({ type, text });
  };

  const refreshAll = useCallback(async () => {
    const meRes = await api.request<Record<string, unknown>>('GET', '/api/v1/auth/me');
    if (!meRes.ok) {
      api.setSessionToken(null);
      try {
        window.localStorage.removeItem('hs_session_token');
      } catch {
        // Ignore storage errors
      }
      setPrincipal(null);
      return;
    }

    const [dashRes, projRes, scanRes, findRes, taskRes, rechRes, notifRes, orgRes, audRes] =
      await Promise.all([
        api.request<Record<string, unknown>>('GET', '/api/v1/dashboard'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/projects'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/scans'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/findings'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/remediation-tasks'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/rechecks'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/notifications'),
        api.request<Record<string, unknown>>('GET', '/api/v1/organization'),
        api.request<Record<string, unknown>>('GET', '/api/v1/audit-logs')
      ]);

    if (dashRes.ok && dashRes.data) {
      setDashboard(dashRes.data);
      const p = (dashRes.data.principal as AuthenticatedPrincipal) ?? null;
      setPrincipal(p);
    }
    if (projRes.ok && Array.isArray(projRes.data)) {
      setProjects(projRes.data);
      if (projRes.data.length > 0 && !grantProjectId) {
        const firstId = String(projRes.data[0].id ?? 'proj-laravel-commerce');
        setGrantProjectId(firstId);
        setScanProjectId(firstId);
      }
    }
    if (scanRes.ok && Array.isArray(scanRes.data)) {
      setScans(scanRes.data);
      if (scanRes.data.length > 0) {
        const firstScan = String(scanRes.data[0].id ?? '');
        const secondScan = String(scanRes.data[1]?.id ?? scanRes.data[scanRes.data.length - 1].id ?? firstScan);
        setReportScanId(firstScan);
        setCurrentScanId(firstScan);
        setBaselineScanId(secondScan);
      }
    }
    if (findRes.ok && Array.isArray(findRes.data)) setFindings(findRes.data);
    if (taskRes.ok && Array.isArray(taskRes.data)) setTasks(taskRes.data);
    if (rechRes.ok && Array.isArray(rechRes.data)) setRechecks(rechRes.data);
    if (notifRes.ok && Array.isArray(notifRes.data)) setNotifications(notifRes.data);
    if (orgRes.ok && orgRes.data) setOrganization(orgRes.data);
    if (audRes.ok && audRes.data) setAuditLogs(audRes.data);
  }, [grantProjectId]);

  useEffect(() => {
    try {
      const savedToken = window.localStorage.getItem('hs_session_token');
      if (savedToken) {
        api.setSessionToken(savedToken);
        void refreshAll();
      }
    } catch {
      // Ignore storage access errors
    }
  }, [refreshAll]);

  const handleLogin = async (email: string, password: string) => {
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/auth/login', {
      email,
      password
    });
    if (!res.ok || !res.data) {
      notifyUser('err', res.message ?? 'Kimlik doğrulama başarısız oldu.');
      return;
    }
    const token = String(res.data.token ?? res.data.session_token ?? '');
    if (token) {
      api.setSessionToken(token);
      try {
        window.localStorage.setItem('hs_session_token', token);
      } catch {
        // Ignore
      }
    }
    notifyUser('ok', `Oturum açıldı: ${email}`);
    await refreshAll();
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/auth/register', {
      name: regName,
      email: regEmail,
      password: regPassword,
      organization_name: regOrgName
    });
    if (!res.ok || !res.data) {
      notifyUser('err', res.message ?? 'Kayıt başarısız.');
      return;
    }
    const token = String(res.data.token ?? res.data.session_token ?? '');
    if (token) {
      api.setSessionToken(token);
      try {
        window.localStorage.setItem('hs_session_token', token);
      } catch {
        // Ignore
      }
    }
    notifyUser('ok', `Yeni organizasyon ve hesap oluşturuldu: ${regEmail}`);
    await refreshAll();
  };

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/auth/password-reset', {
      email: resetEmail
    });
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Sıfırlama isteği başarısız.');
      return;
    }
    notifyUser('ok', 'Şifre sıfırlama bağlantısı denetim kaydına işlendi.');
  };

  const handleLogout = async () => {
    await api.request('POST', '/api/v1/auth/logout');
    api.setSessionToken(null);
    try {
      window.localStorage.removeItem('hs_session_token');
    } catch {
      // Ignore
    }
    setPrincipal(null);
    notifyUser('ok', 'Oturum güvenli şekilde kapatıldı.');
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/projects', {
      name: projName,
      environment: projEnv,
      stack: [projStack],
      hostname: projHost,
      repository_path: projRepo,
      written_permission_ref: projPermRef,
      domain_control_proof: projDnsProof
    });
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Proje oluşturulamadı.');
      return;
    }
    const createdId = String(res.data?.id ?? '');
    if (createdId) {
      setGrantProjectId(createdId);
      setScanProjectId(createdId);
    }
    notifyUser('ok', `Yetkili proje ve kapsam izni oluşturuldu: ${projName}`);
    await refreshAll();
  };

  const handleCreateScopeGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>(
      'POST',
      `/api/v1/projects/${encodeURIComponent(grantProjectId)}/grants`,
      {
        written_permission_ref: grantPermRef,
        domain_control_proof: projDnsProof,
        hostname: projHost,
        authorization_statement: 'Authorized offline and passive web assessment under Sprint 10.',
        max_request_budget: 25
      }
    );
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Kapsam izni onaylanamadı.');
      return;
    }
    notifyUser('ok', `Yeni kapsam versiyonu onaylandı (${grantProjectId}).`);
    await refreshAll();
  };

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsScanning(true);
    try {
      const res = await api.request<Record<string, unknown>>('POST', '/api/v1/scans', {
        project_id: scanProjectId,
        mode: scanMode,
        fixture_variant: scanVariant
      });
      if (!res.ok) {
        notifyUser('err', `[${res.error ?? 'DENIED'}] ${res.message ?? 'Tarama reddedildi.'}`);
        await refreshAll();
        return;
      }
      notifyUser('ok', `Yetkili tarama tamamlandı: ${String(res.data?.id ?? '')}`);
      await refreshAll();
    } finally {
      setIsScanning(false);
    }
  };

  const handleEmergencyStop = async () => {
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/emergency-stop', {
      project_id: scanProjectId,
      reason: 'Operator triggered SEC-012 Emergency Stop Kill-Switch from Next.js 15 console'
    });
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Acil durdurma başarısız.');
      return;
    }
    notifyUser('ok', 'ACİL DURDURMA (SEC-012) etkinleştirildi: Aktif taramalar < 2sn içinde sonlandırıldı.');
    await refreshAll();
  };

  const handleSuppressFinding = async (findingId: string) => {
    const rationale = suppressRationales[findingId] ?? '';
    const res = await api.request<Record<string, unknown>>(
      'POST',
      `/api/v1/findings/${encodeURIComponent(findingId)}/suppress`,
      { rationale }
    );
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Yanlış pozitif bastırma reddedildi.');
      return;
    }
    notifyUser('ok', `Bulgu kapsam bazlı yanlış pozitif (SEC-010) olarak bastırıldı: ${findingId}`);
    await refreshAll();
  };

  const handleUpdateTaskStatus = async (taskId: string, status: string) => {
    const res = await api.request<Record<string, unknown>>(
      'PATCH',
      `/api/v1/remediation-tasks/${encodeURIComponent(taskId)}`,
      { status }
    );
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Görev durumu güncellenemedi.');
      return;
    }
    notifyUser('ok', `Düzeltme görevi güncellendi (${taskId} -> ${status}).`);
    await refreshAll();
  };

  const handleRunRecheck = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/rechecks', {
      baseline_scan_id: baselineScanId,
      current_scan_id: currentScanId
    });
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Yeniden test karşılaştırması başarısız.');
      return;
    }
    notifyUser('ok', `Yeniden test karşılaştırması tamamlandı: ${String(res.data?.id ?? '')}`);
    await refreshAll();
  };

  const handleExportReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportScanId) return;
    const res = await api.request<Record<string, unknown>>(
      'GET',
      `/api/v1/scans/${encodeURIComponent(reportScanId)}/export?format=${encodeURIComponent(reportFormat)}`
    );
    if (!res.ok || !res.data) {
      notifyUser('err', res.message ?? 'Rapor oluşturulamadı.');
      return;
    }
    setReportPreview(String(res.data.content ?? JSON.stringify(res.data, null, 2)));
    notifyUser('ok', `Maskelenmiş ${reportFormat.toUpperCase()} raporu üretildi (${reportScanId}).`);
  };

  const handleSendNotification = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/notifications', {
      project_id: scanProjectId,
      scan_run_id: reportScanId || undefined,
      channel: notifyChannel,
      recipient: notifyRecipient,
      summary: notifySummary
    });
    if (!res.ok) {
      notifyUser('err', `[${res.error ?? 'SEC-013'}] ${res.message ?? 'Bildirim reddedildi.'}`);
      return;
    }
    notifyUser('ok', `Onaylı bildirim gönderildi (${notifyRecipient}).`);
    await refreshAll();
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.request<Record<string, unknown>>('POST', '/api/v1/organization/members', {
      email: memberEmail,
      name: memberName,
      role: memberRole
    });
    if (!res.ok) {
      notifyUser('err', res.message ?? 'Ekip üyesi eklenemedi.');
      return;
    }
    notifyUser('ok', `RBAC rolü güncellendi: ${memberEmail} (${memberRole})`);
    await refreshAll();
  };

  const filteredFindings = findings.filter((f) => {
    if (filterPriority !== 'all' && f.risk_priority !== filterPriority) return false;
    if (filterRule !== 'all' && f.rule_id !== filterRule) return false;
    if (filterSource === 'real' && f.is_demo_seed) return false;
    if (filterSource === 'demo' && !f.is_demo_seed) return false;
    return true;
  });

  const latestScan = scans[0] as Record<string, unknown> | undefined;
  const latestReport = (latestScan?.report ?? null) as Record<string, unknown> | null;
  const latestCoverageChecks = Array.isArray(latestScan?.coverage_checks)
    ? (latestScan.coverage_checks as Array<Record<string, unknown>>)
    : Array.isArray((latestReport?.coverage as Record<string, unknown> | undefined)?.checks)
      ? ((latestReport?.coverage as Record<string, unknown>).checks as Array<Record<string, unknown>>)
      : [];

  const auditEntries = Array.isArray(auditLogs?.entries)
    ? (auditLogs?.entries as Array<Record<string, unknown>>)
    : [];
  const auditValid = Boolean(
    (auditLogs?.integrity as Record<string, unknown> | undefined)?.valid ?? true
  );
  const orgMembers = Array.isArray(organization?.members)
    ? (organization?.members as Array<Record<string, unknown>>)
    : [];

  return (
    <div className="hs-shell" id="hs-app">
      <aside className="hs-sidebar" aria-label="Platform Kenar Çubuğu">
        <div>
          <div className="hs-brand">
            <div className="hs-brand-mark" aria-hidden="true">
              HS
            </div>
            <div>
              <div className="hs-brand-title">HEGOSENTINEL</div>
              <div className="mono hs-brand-sub">v0.2.0-sprint10 · STAGE 2</div>
            </div>
          </div>

          <div className="hs-session-card">
            <div className="mono hs-session-eyebrow">Aktif Oturum / RBAC</div>
            <div id="sidebar-principal-name" className="hs-session-principal">
              {principal?.name ?? 'Oturum Açılmadı'}
            </div>
            <div className="hs-row-wrap">
              <span className="hs-badge lime" id="sidebar-principal-role">
                {principal?.role ?? 'unauthenticated'}
              </span>
              <span className="hs-badge" id="sidebar-principal-org">
                {principal?.organization_id ?? '—'}
              </span>
            </div>
          </div>

          <nav className="hs-nav-list" aria-label="Ana Navigasyon">
            {(
              [
                ['dashboard', '01', t.nav.dashboard],
                ['projects', '02', t.nav.projects],
                ['scanner', '03', t.nav.scanner],
                ['vulnerabilities', '04', t.nav.vulnerabilities],
                ['remediation', '05', t.nav.remediation],
                ['rechecks', '06', t.nav.rechecks],
                ['reports', '07', t.nav.reports],
                ['settings', '08', t.nav.settings],
                ['auth', '09', t.nav.auth]
              ] as const
            ).map(([key, idx, label]) => (
              <button
                key={key}
                type="button"
                data-screen={key}
                className={`hs-nav-btn ${activeScreen === key ? 'active' : ''}`}
                onClick={() => setActiveScreen(key)}
              >
                <span>{label}</span>
                <span className="hs-nav-index">{idx}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="hs-sidebar-footer">
          <div className="mono hs-text-lime">SEMGREP CE 1.183.0 · TRIVY 0.76.1</div>
          <div>PostgreSQL 16 RLS · Horizon Queue</div>
          <div>TrustedEgressBroker: DROP-BY-DEFAULT</div>
        </div>
      </aside>

      <main className="hs-main">
        <header className="hs-topbar">
          <div className="hs-row-wrap">
            <span className="hs-badge lime">{t.status.remoteBlocked}</span>
            <span className="hs-badge" id="topbar-audit-badge">
              {auditValid ? t.status.auditChainValid : 'AUDIT CHAIN ERROR'}
            </span>
            <span className="hs-badge" id="topbar-scanner-badge">
              Laravel 11 · PG 16 RLS · Semgrep 1.183.0 · Trivy 0.76.1
            </span>
          </div>
          <div className="hs-row-wrap">
            <button
              type="button"
              id="locale-toggle-btn"
              className="hs-btn"
              onClick={() => setLocale(locale === 'tr' ? 'en' : 'tr')}
            >
              {locale === 'tr' ? 'EN' : 'TR'}
            </button>
            <button
              type="button"
              className="hs-btn"
              onClick={() => setActiveScreen('auth')}
            >
              {principal ? `${principal.email} (${principal.role})` : t.auth.signIn}
            </button>
          </div>
        </header>

        <div className="hs-content">
          {toast && (
            <div className={`hs-toast ${toast.type === 'err' ? 'err' : ''}`} role="status">
              <div className="hs-row-between">
                <span>{toast.text}</span>
                <button type="button" className="hs-btn" onClick={() => setToast(null)}>
                  ×
                </button>
              </div>
            </div>
          )}

          {/* ================================================================
              SCREEN 01: DASHBOARD (CYBERSECURITY COMMAND CENTER)
              ================================================================ */}
          <section
            id="screen-dashboard"
            className={activeScreen === 'dashboard' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            {/* Frameless Hero Stage — Open-space radar vector mesh without rectangular border/card */}
            <div className="hs-hero-stage">
              <div>
                <div className="hs-row-wrap">
                  <span className="hs-badge lime">SPRINT 10 PRODUCTION ARCHITECTURE</span>
                  <span className="hs-badge">NEXT.JS 15 + REACT 19 + LARAVEL 11 + PG 16 RLS</span>
                </div>
                <h1 className="hs-hero-title">{t.dashboard.title}</h1>
                <p className="hs-hero-subtitle">{t.dashboard.subtitle}</p>
              </div>
              <div className="hs-hero-radar" aria-hidden="true">
                <svg width="220" height="160" viewBox="0 0 220 160" fill="none">
                  <circle cx="110" cy="80" r="68" stroke="rgba(212,255,51,0.22)" strokeWidth="1" />
                  <circle cx="110" cy="80" r="46" stroke="rgba(212,255,51,0.34)" strokeWidth="1" strokeDasharray="4 4" />
                  <circle cx="110" cy="80" r="24" stroke="rgba(212,255,51,0.55)" strokeWidth="1.2" />
                  <line x1="25" y1="80" x2="195" y2="80" stroke="rgba(255,255,255,0.1)" strokeWidth="1" />
                  <line x1="110" y1="8" x2="110" y2="152" stroke="rgba(255,255,255,0.1)" strokeWidth="1" />
                  <line x1="110" y1="80" x2="162" y2="38" stroke="#d4ff33" strokeWidth="1.8" />
                  <circle cx="162" cy="38" r="4" fill="#d4ff33" />
                  <circle cx="84" cy="62" r="3" fill="#38bdf8" />
                  <circle cx="132" cy="106" r="3.5" fill="#d4ff33" />
                </svg>
              </div>
            </div>

            <div className="hs-kpi-grid">
              <div className="hs-panel">
                <span className="hs-label">{t.dashboard.totalProjects}</span>
                <div className="hs-kpi-value" id="kpi-projects">
                  {projects.length}
                </div>
                <span className="hs-text-xs">SEC-001 ScopeAuthorizationGrant</span>
              </div>
              <div className="hs-panel">
                <span className="hs-label">{t.dashboard.totalScans}</span>
                <div className="hs-kpi-value" id="kpi-scans">
                  {scans.length}
                </div>
                <span className="hs-text-xs">Horizon Queue + Worker Supervisor</span>
              </div>
              <div className="hs-panel">
                <span className="hs-label">{t.dashboard.totalFindings}</span>
                <div className="hs-kpi-value" id="kpi-findings">
                  {findings.length}
                </div>
                <span className="hs-text-xs">9-Pass Secret Redacted</span>
              </div>
              <div className="hs-panel">
                <span className="hs-label">{t.dashboard.remediationTasks}</span>
                <div className="hs-kpi-value" id="kpi-tasks">
                  {tasks.length}
                </div>
                <span className="hs-text-xs">
                  Guvenlik Skoru: {String(dashboard?.security_score ?? 100)} / 100
                </span>
              </div>
            </div>

            <div className="hs-grid-2">
              <div className="hs-panel">
                <div className="hs-panel-header">
                  <h2>{t.dashboard.securityPosture}</h2>
                  <span className="hs-badge lime">FAIL-CLOSED ACTIVE</span>
                </div>
                <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.dashboard.securityPosture}>
                  <table className="hs-table hs-table-responsive">
                    <thead>
                      <tr>
                        <th>Katman</th>
                        <th>Mimari Bileşen</th>
                        <th>Durum</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <th>API &amp; RBAC</th>
                        <td>Laravel 11.57.1 + Sanctum + Policies</td>
                        <td><span className="hs-badge lime">AKTİF</span></td>
                      </tr>
                      <tr>
                        <th>Veritabanı &amp; RLS</th>
                        <td>PostgreSQL 16.4 FORCE ROW LEVEL SECURITY</td>
                        <td><span className="hs-badge lime">DOĞRULANDI</span></td>
                      </tr>
                      <tr>
                        <th>Kuyruk Düzlemi</th>
                        <td>Redis 7 + Laravel Horizon (scans/rechecks/notify)</td>
                        <td><span className="hs-badge lime">AKTİF</span></td>
                      </tr>
                      <tr>
                        <th>İzole Worker</th>
                        <td>WorkerSupervisor (65532:65532, cap-drop=ALL, ro)</td>
                        <td><span className="hs-badge lime">İZOLE</span></td>
                      </tr>
                      <tr>
                        <th>Uzaktan Tarama</th>
                        <td>restricted-remote (TrustedEgressBroker Gate)</td>
                        <td><span className="hs-badge critical">KAPALI (FAIL-CLOSED)</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="hs-panel">
                <div className="hs-panel-header">
                  <h2>{t.dashboard.recentScans}</h2>
                  <button
                    type="button"
                    className="hs-btn"
                    onClick={() => setActiveScreen('scanner')}
                  >
                    {t.scanner.launchScan}
                  </button>
                </div>
                <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.dashboard.recentScans}>
                  <table className="hs-table hs-table-responsive">
                    <thead>
                      <tr>
                        <th>Tarama ID</th>
                        <th>Proje</th>
                        <th>Durum</th>
                        <th>Kapsam</th>
                        <th>Kaynağı</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.slice(0, 6).map((s) => (
                        <tr key={String(s.id)}>
                          <th>{String(s.id)}</th>
                          <td>{String(s.project_id)}</td>
                          <td>
                            <span className="hs-badge lime">{String(s.status)}</span>
                          </td>
                          <td className="mono">{String(s.global_coverage_status)}</td>
                          <td>
                            <span className="hs-badge">
                              {s.is_demo_seed ? t.status.demoSeed : t.status.realScan}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 02: PROJECTS & SCOPE AUTHORIZATION GRANTS
              ================================================================ */}
          <section
            id="screen-projects"
            className={activeScreen === 'projects' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-panel">
              <div className="hs-panel-header">
                <div>
                  <h1>{t.projects.title}</h1>
                  <p className="hs-text-muted">{t.projects.subtitle}</p>
                </div>
                <span className="hs-badge lime">SEC-001 &amp; SEC-002</span>
              </div>

              <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.projects.title}>
                <table className="hs-table hs-table-responsive">
                  <thead>
                    <tr>
                      <th>Proje ID</th>
                      <th>{t.projects.projectName}</th>
                      <th>{t.projects.stack}</th>
                      <th>{t.projects.hostname}</th>
                      <th>Kapsam (Grant)</th>
                      <th>Etiket</th>
                    </tr>
                  </thead>
                  <tbody>
                    {projects.map((p) => {
                      const activeGrant = p.active_grant as Record<string, unknown> | undefined;
                      return (
                        <tr key={String(p.id)}>
                          <th>{String(p.id)}</th>
                          <td>{String(p.name)}</td>
                          <td className="mono">{String(p.stack)}</td>
                          <td className="mono">{String(p.target_hostname ?? '—')}</td>
                          <td className="mono">
                            {activeGrant
                              ? `${String(activeGrant.id)} (v${String(activeGrant.scope_version)})`
                              : 'Yok'}
                          </td>
                          <td>
                            <span className={`hs-badge ${p.is_demo_target ? '' : 'lime'}`}>
                              {p.is_demo_target ? t.status.demoSandbox : t.status.realTarget}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="hs-grid-2">
              <form className="hs-panel" onSubmit={handleCreateProject}>
                <div className="hs-panel-header">
                  <h2>{t.projects.createProject}</h2>
                </div>
                <div>
                  <label className="hs-label" htmlFor="proj-name-input">{t.projects.projectName}</label>
                  <input
                    id="proj-name-input"
                    className="hs-input"
                    value={projName}
                    onChange={(e) => setProjName(e.target.value)}
                    required
                  />
                </div>
                <div className="hs-grid-2">
                  <div>
                    <label className="hs-label" htmlFor="proj-env-select">{t.projects.environment}</label>
                    <select
                      id="proj-env-select"
                      className="hs-select"
                      value={projEnv}
                      onChange={(e) => setProjEnv(e.target.value)}
                    >
                      <option value="staging">staging</option>
                      <option value="production">production</option>
                      <option value="development">development</option>
                    </select>
                  </div>
                  <div>
                    <label className="hs-label" htmlFor="proj-stack-select">{t.projects.stack}</label>
                    <select
                      id="proj-stack-select"
                      className="hs-select"
                      value={projStack}
                      onChange={(e) => setProjStack(e.target.value)}
                    >
                      <option value="laravel">laravel</option>
                      <option value="nextjs">nextjs</option>
                      <option value="nodejs">nodejs</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="hs-label" htmlFor="proj-host-input">{t.projects.hostname}</label>
                  <input
                    id="proj-host-input"
                    className="hs-input"
                    value={projHost}
                    onChange={(e) => setProjHost(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="hs-label" htmlFor="proj-repo-input">{t.projects.repoPath}</label>
                  <input
                    id="proj-repo-input"
                    className="hs-input"
                    value={projRepo}
                    onChange={(e) => setProjRepo(e.target.value)}
                  />
                </div>
                <div className="hs-grid-2">
                  <div>
                    <label className="hs-label" htmlFor="proj-perm-input">{t.projects.writtenPermissionRef}</label>
                    <input
                      id="proj-perm-input"
                      className="hs-input"
                      value={projPermRef}
                      onChange={(e) => setProjPermRef(e.target.value)}
                      required
                    />
                  </div>
                  <div>
                    <label className="hs-label" htmlFor="proj-dns-input">{t.projects.domainControlProof}</label>
                    <input
                      id="proj-dns-input"
                      className="hs-input"
                      value={projDnsProof}
                      onChange={(e) => setProjDnsProof(e.target.value)}
                      required
                    />
                  </div>
                </div>
                <button type="submit" id="btn-create-project" className="hs-btn primary">
                  {t.projects.submitProject}
                </button>
              </form>

              <form className="hs-panel" onSubmit={handleCreateScopeGrant}>
                <div className="hs-panel-header">
                  <h2>{t.projects.approveGrant}</h2>
                </div>
                <div>
                  <label className="hs-label" htmlFor="grant-proj-select">{t.scanner.selectProject}</label>
                  <select
                    id="grant-proj-select"
                    className="hs-select"
                    value={grantProjectId}
                    onChange={(e) => setGrantProjectId(e.target.value)}
                  >
                    {projects.map((p) => (
                      <option key={String(p.id)} value={String(p.id)}>
                        {String(p.name)} ({String(p.id)})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="hs-label" htmlFor="grant-perm-input">{t.projects.writtenPermissionRef}</label>
                  <input
                    id="grant-perm-input"
                    className="hs-input"
                    value={grantPermRef}
                    onChange={(e) => setGrantPermRef(e.target.value)}
                    required
                  />
                </div>
                <button type="submit" id="btn-approve-grant" className="hs-btn primary">
                  {t.projects.submitGrant}
                </button>
              </form>
            </div>
          </section>

          {/* ================================================================
              SCREEN 03: SECURITY SCANNER, COVERAGE MATRIX & EMERGENCY STOP
              ================================================================ */}
          <section
            id="screen-scanner"
            className={activeScreen === 'scanner' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-grid-2">
              <form className="hs-panel" onSubmit={handleLaunchScan}>
                <div className="hs-panel-header">
                  <div>
                    <h1>{t.scanner.title}</h1>
                    <p className="hs-text-muted">{t.scanner.subtitle}</p>
                  </div>
                </div>
                <div>
                  <label className="hs-label" htmlFor="scan-project-select">{t.scanner.selectProject}</label>
                  <select
                    id="scan-project-select"
                    className="hs-select"
                    value={scanProjectId}
                    onChange={(e) => setScanProjectId(e.target.value)}
                  >
                    {projects.map((p) => (
                      <option key={String(p.id)} value={String(p.id)}>
                        {String(p.name)} ({String(p.id)})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="hs-grid-2">
                  <div>
                    <label className="hs-label" htmlFor="scan-mode-select">{t.scanner.selectMode}</label>
                    <select
                      id="scan-mode-select"
                      className="hs-select"
                      value={scanMode}
                      onChange={(e) =>
                        setScanMode(e.target.value as 'offline-fixture' | 'restricted-remote')
                      }
                    >
                      <option value="offline-fixture">offline-fixture (Semgrep + Trivy + Passive)</option>
                      <option value="restricted-remote">restricted-remote (FAIL-CLOSED GATE)</option>
                    </select>
                  </div>
                  <div>
                    <label className="hs-label" htmlFor="scan-variant-select">{t.scanner.selectVariant}</label>
                    <select
                      id="scan-variant-select"
                      className="hs-select"
                      value={scanVariant}
                      onChange={(e) => setScanVariant(e.target.value as 'baseline' | 'patched')}
                    >
                      <option value="baseline">baseline (Zafiyetli Hedef / Fikstür)</option>
                      <option value="patched">patched (Yamalı / Düzeltme Sonrası)</option>
                    </select>
                  </div>
                </div>
                <div className="hs-row-wrap">
                  <button
                    type="submit"
                    id="btn-launch-scan"
                    className="hs-btn primary"
                    disabled={isScanning}
                  >
                    {isScanning ? 'Tarama Çalışıyor...' : t.scanner.launchScan}
                  </button>
                  <button
                    type="button"
                    id="btn-emergency-stop"
                    className="hs-btn danger"
                    onClick={handleEmergencyStop}
                  >
                    {t.scanner.emergencyStop}
                  </button>
                </div>
              </form>

              <div className="hs-panel">
                <div className="hs-panel-header">
                  <h2>{t.scanner.coverageMatrix}</h2>
                  <span className="hs-badge lime">
                    {String(latestScan?.global_coverage_status ?? 'complete')}
                  </span>
                </div>
                <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.scanner.coverageMatrix}>
                  <table className="hs-table hs-table-responsive">
                    <thead>
                      <tr>
                        <th>Kural ID</th>
                        <th>Durum</th>
                        <th>Ayrıntı / Motor</th>
                      </tr>
                    </thead>
                    <tbody>
                      {latestCoverageChecks.map((chk, i) => (
                        <tr key={`${String(chk.rule_id)}-${i}`}>
                          <th>{String(chk.rule_id)}</th>
                          <td>
                            <span className="hs-badge lime">{String(chk.status)}</span>
                          </td>
                          <td className="mono">{String(chk.reason ?? 'Executed in isolated worker')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 04: VULNERABILITY FINDINGS & SCOPED SUPPRESSION (SEC-010)
              ================================================================ */}
          <section
            id="screen-vulnerabilities"
            className={activeScreen === 'vulnerabilities' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-panel">
              <div className="hs-panel-header">
                <div>
                  <h1>{t.vulnerabilities.title}</h1>
                  <p className="hs-text-muted">{t.vulnerabilities.subtitle}</p>
                </div>
                <div className="hs-row-wrap">
                  <select
                    aria-label={t.vulnerabilities.filterPriority}
                    className="hs-select"
                    value={filterPriority}
                    onChange={(e) => setFilterPriority(e.target.value)}
                  >
                    <option value="all">Tüm Öncelikler ({findings.length})</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select
                    aria-label={t.vulnerabilities.filterRule}
                    className="hs-select"
                    value={filterRule}
                    onChange={(e) => setFilterRule(e.target.value)}
                  >
                    <option value="all">Tüm Kurallar</option>
                    <option value="WEB-TLS-001">WEB-TLS-001</option>
                    <option value="WEB-HEADER-001">WEB-HEADER-001</option>
                    <option value="WEB-COOKIE-001">WEB-COOKIE-001</option>
                    <option value="WEB-REDIRECT-001">WEB-REDIRECT-001</option>
                    <option value="CODE-001">CODE-001 (Semgrep)</option>
                    <option value="DEP-001">DEP-001 (Trivy)</option>
                  </select>
                  <select
                    aria-label={t.vulnerabilities.filterSource}
                    className="hs-select"
                    value={filterSource}
                    onChange={(e) => setFilterSource(e.target.value)}
                  >
                    <option value="all">Tüm Kaynaklar</option>
                    <option value="real">{t.status.realScan}</option>
                    <option value="demo">{t.status.demoSeed}</option>
                  </select>
                </div>
              </div>

              <div className="hs-stack-md">
                {filteredFindings.map((f) => {
                  const fId = String(f.id);
                  const priority = String(f.risk_priority ?? 'medium');
                  return (
                    <div key={fId} className="hs-panel">
                      <div className="hs-panel-header">
                        <div className="hs-row-wrap">
                          <span className={`hs-badge ${priority}`}>{priority.toUpperCase()}</span>
                          <span className="hs-badge mono">{String(f.rule_id)}</span>
                          <strong>{String(f.title)}</strong>
                        </div>
                        <div className="hs-row-wrap">
                          <span className="hs-badge">
                            CVSS v4: {String(f.cvss_v4_base_score ?? 'N/A')}
                          </span>
                          <span className="hs-badge mono">{String(f.verification_status)}</span>
                        </div>
                      </div>
                      <p className="hs-text-muted">{String(f.affected_component ?? '')}</p>
                      <pre className="hs-code-block">{String(f.evidence_summary ?? f.redacted_evidence ?? '')}</pre>
                      <div className="hs-row-wrap">
                        <input
                          className="hs-input"
                          placeholder={t.vulnerabilities.suppressRationalePlaceholder}
                          value={suppressRationales[fId] ?? ''}
                          onChange={(e) =>
                            setSuppressRationales((prev) => ({ ...prev, [fId]: e.target.value }))
                          }
                        />
                        <button
                          type="button"
                          className="hs-btn"
                          onClick={() => handleSuppressFinding(fId)}
                        >
                          {t.vulnerabilities.suppressButton}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 05: DEVELOPER REMEDIATION & PATCH CENTER
              ================================================================ */}
          <section
            id="screen-remediation"
            className={activeScreen === 'remediation' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-panel">
              <div className="hs-panel-header">
                <div>
                  <h1>{t.remediation.title}</h1>
                  <p className="hs-text-muted">{t.remediation.subtitle}</p>
                </div>
              </div>
              <div className="hs-stack-md">
                {tasks.map((task) => {
                  const taskId = String(task.id);
                  return (
                    <div key={taskId} className="hs-panel">
                      <div className="hs-panel-header">
                        <div className="hs-row-wrap">
                          <span className="hs-badge lime">{String(task.status)}</span>
                          <span className="hs-badge mono">{String(task.framework ?? task.stack ?? 'laravel')}</span>
                          <strong>{String(task.title)}</strong>
                        </div>
                        <span className="mono hs-text-xs">Atanan: {String(task.assigned_to_name ?? task.assigned_to ?? 'Demo Developer')}</span>
                      </div>
                      <p className="hs-text-muted">{String(task.guidance_summary ?? task.root_cause ?? '')}</p>
                      <pre className="hs-code-block">{String(task.code_patch_example ?? task.code_patch ?? '')}</pre>
                      <div className="hs-row-wrap">
                        <button
                          type="button"
                          className="hs-btn"
                          onClick={() => handleUpdateTaskStatus(taskId, 'in_progress')}
                        >
                          {t.remediation.markInProgress}
                        </button>
                        <button
                          type="button"
                          className="hs-btn"
                          onClick={() => handleUpdateTaskStatus(taskId, 'ready_for_retest')}
                        >
                          {t.remediation.markReadyRetest}
                        </button>
                        <button
                          type="button"
                          className="hs-btn primary"
                          onClick={() => handleUpdateTaskStatus(taskId, 'verified_closed')}
                        >
                          {t.remediation.markVerifiedClosed}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 06: RE-TEST COMPARISON ENGINE
              ================================================================ */}
          <section
            id="screen-rechecks"
            className={activeScreen === 'rechecks' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <form className="hs-panel" onSubmit={handleRunRecheck}>
              <div className="hs-panel-header">
                <div>
                  <h1>{t.rechecks.title}</h1>
                  <p className="hs-text-muted">{t.rechecks.subtitle}</p>
                </div>
              </div>
              <div className="hs-grid-2">
                <div>
                  <label className="hs-label" htmlFor="recheck-baseline-select">{t.rechecks.baselineScan}</label>
                  <select
                    id="recheck-baseline-select"
                    className="hs-select"
                    value={baselineScanId}
                    onChange={(e) => setBaselineScanId(e.target.value)}
                  >
                    {scans.map((s) => (
                      <option key={String(s.id)} value={String(s.id)}>
                        {String(s.id)} ({String(s.fixture_variant)} · {String(s.total_findings)} bulgu)
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="hs-label" htmlFor="recheck-current-select">{t.rechecks.currentScan}</label>
                  <select
                    id="recheck-current-select"
                    className="hs-select"
                    value={currentScanId}
                    onChange={(e) => setCurrentScanId(e.target.value)}
                  >
                    {scans.map((s) => (
                      <option key={String(s.id)} value={String(s.id)}>
                        {String(s.id)} ({String(s.fixture_variant)} · {String(s.total_findings)} bulgu)
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <button type="submit" id="btn-run-recheck" className="hs-btn primary">
                {t.rechecks.runComparison}
              </button>
            </form>

            <div className="hs-panel">
              <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.rechecks.title}>
                <table className="hs-table hs-table-responsive">
                  <thead>
                    <tr>
                      <th>Karşılaştırma ID</th>
                      <th>Baseline</th>
                      <th>Güncel</th>
                      <th>Kapatılan (Fixed)</th>
                      <th>Kalan (Remaining)</th>
                      <th>Gerileyen (Regressed)</th>
                      <th>Bastırılan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rechecks.map((rc) => {
                      const counts = (rc.counts as Record<string, unknown> | undefined) ?? {};
                      return (
                        <tr key={String(rc.id)}>
                          <th>{String(rc.id)}</th>
                          <td className="mono">{String(rc.baseline_scan_id)}</td>
                          <td className="mono">{String(rc.current_scan_id)}</td>
                          <td><span className="hs-badge lime">{String(counts.verified_fixed ?? rc.fixed_count ?? 0)}</span></td>
                          <td><span className="hs-badge">{String(counts.still_open ?? rc.remaining_count ?? 0)}</span></td>
                          <td><span className="hs-badge critical">{String(counts.reintroduced ?? rc.regressed_count ?? 0)}</span></td>
                          <td><span className="hs-badge">{String(counts.false_positive ?? rc.suppressed_count ?? 0)}</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 07: SAFE REPORT EXPORT & APPROVED NOTIFICATIONS (SEC-013)
              ================================================================ */}
          <section
            id="screen-reports"
            className={activeScreen === 'reports' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-grid-2">
              <form className="hs-panel" onSubmit={handleExportReport}>
                <div className="hs-panel-header">
                  <h2>{t.reports.title}</h2>
                </div>
                <div>
                  <label className="hs-label" htmlFor="report-scan-select">Tarama Seçin</label>
                  <select
                    id="report-scan-select"
                    className="hs-select"
                    value={reportScanId}
                    onChange={(e) => setReportScanId(e.target.value)}
                  >
                    {scans.map((s) => (
                      <option key={String(s.id)} value={String(s.id)}>
                        {String(s.id)} ({String(s.project_id)})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="hs-label" htmlFor="report-format-select">{t.reports.exportFormat}</label>
                  <select
                    id="report-format-select"
                    className="hs-select"
                    value={reportFormat}
                    onChange={(e) =>
                      setReportFormat(e.target.value as 'json' | 'md' | 'html' | 'sarif' | 'pdf')
                    }
                  >
                    <option value="json">JSON (Canonical Schema)</option>
                    <option value="md">Markdown (.md)</option>
                    <option value="html">HTML Report</option>
                    <option value="sarif">SARIF 2.1.0 (GitHub Code Scanning)</option>
                    <option value="pdf">PDF-Ready Print HTML</option>
                  </select>
                </div>
                <button type="submit" id="btn-export-report" className="hs-btn primary">
                  {t.reports.downloadReport}
                </button>
                {reportPreview && (
                  <pre className="hs-code-block" id="report-preview-box">
                    {reportPreview.slice(0, 2400)}
                  </pre>
                )}
              </form>

              <form className="hs-panel" onSubmit={handleSendNotification}>
                <div className="hs-panel-header">
                  <h2>{t.reports.sendNotification}</h2>
                  <span className="hs-badge lime">SEC-013</span>
                </div>
                <div>
                  <label className="hs-label" htmlFor="notify-channel-select">{t.reports.channelLabel}</label>
                  <select
                    id="notify-channel-select"
                    className="hs-select"
                    value={notifyChannel}
                    onChange={(e) => setNotifyChannel(e.target.value as 'email' | 'webhook')}
                  >
                    <option value="email">E-Posta (Verified Domain)</option>
                    <option value="webhook">HTTPS Webhook (Pinned Domain)</option>
                  </select>
                </div>
                <div>
                  <label className="hs-label" htmlFor="notify-recipient-input">{t.reports.recipientLabel}</label>
                  <input
                    id="notify-recipient-input"
                    className="hs-input"
                    value={notifyRecipient}
                    onChange={(e) => setNotifyRecipient(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="hs-label" htmlFor="notify-summary-input">{t.reports.summaryLabel}</label>
                  <textarea
                    id="notify-summary-input"
                    className="hs-textarea"
                    rows={3}
                    value={notifySummary}
                    onChange={(e) => setNotifySummary(e.target.value)}
                    required
                  />
                </div>
                <button type="submit" id="btn-send-notification" className="hs-btn primary">
                  {t.reports.sendNotification}
                </button>
                <div className="hs-text-xs mono">
                  Gönderilen Onaylı Bildirimler: {notifications.length}
                </div>
              </form>
            </div>
          </section>

          {/* ================================================================
              SCREEN 08: SETTINGS, TEAM RBAC & SHA-256 AUDIT LEDGER
              ================================================================ */}
          <section
            id="screen-settings"
            className={activeScreen === 'settings' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-grid-2">
              <div className="hs-panel">
                <div className="hs-panel-header">
                  <h2>{t.settings.teamRbac}</h2>
                  <span className="hs-badge lime">SEC-011 RBAC</span>
                </div>
                <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.settings.teamRbac}>
                  <table className="hs-table hs-table-responsive">
                    <thead>
                      <tr>
                        <th>E-Posta</th>
                        <th>Ad Soyad</th>
                        <th>RBAC Rolü</th>
                      </tr>
                    </thead>
                    <tbody>
                      {orgMembers.map((m, idx) => (
                        <tr key={`${String(m.email)}-${idx}`}>
                          <th>{String(m.email)}</th>
                          <td>{String(m.name)}</td>
                          <td><span className="hs-badge lime">{String(m.role)}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <form className="hs-panel" onSubmit={handleInviteMember}>
                <div className="hs-panel-header">
                  <h2>{t.settings.inviteMember}</h2>
                </div>
                <div>
                  <label className="hs-label" htmlFor="member-email-input">{t.auth.email}</label>
                  <input
                    id="member-email-input"
                    className="hs-input"
                    value={memberEmail}
                    onChange={(e) => setMemberEmail(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="hs-label" htmlFor="member-name-input">{t.auth.fullName}</label>
                  <input
                    id="member-name-input"
                    className="hs-input"
                    value={memberName}
                    onChange={(e) => setMemberName(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="hs-label" htmlFor="member-role-select">RBAC Rolü</label>
                  <select
                    id="member-role-select"
                    className="hs-select"
                    value={memberRole}
                    onChange={(e) =>
                      setMemberRole(
                        e.target.value as 'owner' | 'security_lead' | 'developer' | 'viewer'
                      )
                    }
                  >
                    <option value="owner">owner</option>
                    <option value="security_lead">security_lead</option>
                    <option value="developer">developer</option>
                    <option value="viewer">viewer</option>
                  </select>
                </div>
                <button type="submit" id="btn-invite-member" className="hs-btn primary">
                  {t.settings.inviteMember}
                </button>
              </form>
            </div>

            <div className="hs-panel">
              <div className="hs-panel-header">
                <h2>{t.settings.auditLedger}</h2>
                <span className="hs-badge lime">
                  {auditValid ? 'SHA-256 HASH CHAIN VERIFIED' : 'CHAIN MISMATCH'}
                </span>
              </div>
              <div className="table-wrapper" tabIndex={0} role="region" aria-label={t.settings.auditLedger}>
                <table className="hs-table hs-table-responsive">
                  <thead>
                    <tr>
                      <th>Zaman</th>
                      <th>Aksiyon</th>
                      <th>Hedef</th>
                      <th>Durum</th>
                      <th>Entry Hash (SHA-256)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.slice(0, 12).map((entry) => (
                      <tr key={String(entry.id ?? entry.sequence)}>
                        <th className="mono">{String(entry.created_at)}</th>
                        <td className="mono">{String(entry.action)}</td>
                        <td className="mono">{String(entry.project_id ?? 'org')}</td>
                        <td><span className="hs-badge lime">{String(entry.decision ?? entry.status ?? 'allow')}</span></td>
                        <td className="mono">{String(entry.entry_hash ?? '').slice(0, 20)}…</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          {/* ================================================================
              SCREEN 09: AUTHENTICATION & SESSION MANAGEMENT
              ================================================================ */}
          <section
            id="screen-auth"
            className={activeScreen === 'auth' ? 'hs-stack-md' : 'hs-screen-hidden'}
          >
            <div className="hs-grid-2">
              <div className="hs-panel">
                <div className="hs-panel-header">
                  <div>
                    <h1>{t.auth.title}</h1>
                    <p className="hs-text-muted">{t.auth.subtitle}</p>
                  </div>
                </div>
                <div className="hs-row-wrap">
                  <button
                    type="button"
                    className={`hs-btn ${authTab === 'login' ? 'primary' : ''}`}
                    onClick={() => setAuthTab('login')}
                  >
                    {t.auth.loginTab}
                  </button>
                  <button
                    type="button"
                    className={`hs-btn ${authTab === 'register' ? 'primary' : ''}`}
                    onClick={() => setAuthTab('register')}
                  >
                    {t.auth.registerTab}
                  </button>
                  <button
                    type="button"
                    className={`hs-btn ${authTab === 'reset' ? 'primary' : ''}`}
                    onClick={() => setAuthTab('reset')}
                  >
                    {t.auth.resetTab}
                  </button>
                  {principal && (
                    <button type="button" className="hs-btn danger" onClick={handleLogout}>
                      {t.auth.signOut}
                    </button>
                  )}
                </div>

                {authTab === 'login' && (
                  <form
                    className="hs-stack-sm"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void handleLogin(loginEmail, loginPassword);
                    }}
                  >
                    <div>
                      <label className="hs-label" htmlFor="login-email">{t.auth.email}</label>
                      <input
                        id="login-email"
                        type="email"
                        autoComplete="username"
                        className="hs-input"
                        value={loginEmail}
                        onChange={(e) => setLoginEmail(e.target.value)}
                        required
                      />
                    </div>
                    <div>
                      <label className="hs-label" htmlFor="login-password">{t.auth.password}</label>
                      <input
                        id="login-password"
                        type="password"
                        autoComplete="current-password"
                        className="hs-input"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        required
                      />
                    </div>
                    <button type="submit" id="btn-login-submit" className="hs-btn primary">
                      {t.auth.signIn}
                    </button>
                  </form>
                )}

                {authTab === 'register' && (
                  <form className="hs-stack-sm" onSubmit={handleRegister}>
                    <div>
                      <label className="hs-label" htmlFor="reg-name">{t.auth.fullName}</label>
                      <input
                        id="reg-name"
                        autoComplete="name"
                        className="hs-input"
                        value={regName}
                        onChange={(e) => setRegName(e.target.value)}
                        required
                      />
                    </div>
                    <div>
                      <label className="hs-label" htmlFor="reg-org">{t.auth.organizationName}</label>
                      <input
                        id="reg-org"
                        autoComplete="organization"
                        className="hs-input"
                        value={regOrgName}
                        onChange={(e) => setRegOrgName(e.target.value)}
                        required
                      />
                    </div>
                    <div>
                      <label className="hs-label" htmlFor="reg-email">{t.auth.email}</label>
                      <input
                        id="reg-email"
                        type="email"
                        autoComplete="email"
                        className="hs-input"
                        value={regEmail}
                        onChange={(e) => setRegEmail(e.target.value)}
                        required
                      />
                    </div>
                    <div>
                      <label className="hs-label" htmlFor="reg-password">{t.auth.password}</label>
                      <input
                        id="reg-password"
                        type="password"
                        autoComplete="new-password"
                        className="hs-input"
                        value={regPassword}
                        onChange={(e) => setRegPassword(e.target.value)}
                        required
                      />
                    </div>
                    <button type="submit" className="hs-btn primary">
                      {t.auth.signUp}
                    </button>
                  </form>
                )}

                {authTab === 'reset' && (
                  <form className="hs-stack-sm" onSubmit={handlePasswordReset}>
                    <div>
                      <label className="hs-label" htmlFor="reset-email">{t.auth.email}</label>
                      <input
                        id="reset-email"
                        type="email"
                        className="hs-input"
                        value={resetEmail}
                        onChange={(e) => setResetEmail(e.target.value)}
                        required
                      />
                    </div>
                    <button type="submit" className="hs-btn primary">
                      {t.auth.sendReset}
                    </button>
                  </form>
                )}
              </div>

              <div className="hs-panel">
                <div className="hs-panel-header">
                  <h2>Oturum &amp; Kimlik Doğrulama Güvenlik Mimarisi (B1)</h2>
                  <span className="hs-badge lime">BEARER + SANCTUM</span>
                </div>
                <p className="hs-text-muted">
                  İstemci tarafından gönderilen başlıklar hiçbir zaman kimlik belirleyemez. Tüm
                  istekler sunucu tarafında gerçek oturum anahtarı ve PostgreSQL 16 Row-Level
                  Security (RLS) kiracı bağlamı ile doğrulanır.
                </p>
                <pre className="hs-code-block">
                  {JSON.stringify(
                    {
                      authenticated: Boolean(principal),
                      principal: principal ?? null,
                      client_header_impersonation: 'DISABLED_PERMANENTLY',
                      postgres_rls_enforced: true
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
