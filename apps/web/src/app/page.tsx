'use client';

import React, { useEffect, useState } from 'react';
import { PLATFORM_I18N, type SupportedLocale } from '../lib/i18n.ts';
import { HegoSentinelApiClient, type AuthenticatedPrincipal } from '../lib/api-client.ts';

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
  const [organization, setOrganization] = useState<Record<string, unknown> | null>(null);
  const [auditLogs, setAuditLogs] = useState<Record<string, unknown> | null>(null);
  const [toast, setToast] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const t = PLATFORM_I18N[locale];

  const refreshAll = async () => {
    const [dashRes, projRes, scanRes, findRes, taskRes, rechRes, orgRes, audRes] =
      await Promise.all([
        api.request<Record<string, unknown>>('GET', '/api/v1/dashboard'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/projects'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/scans'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/findings'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/remediation-tasks'),
        api.request<Array<Record<string, unknown>>>('GET', '/api/v1/rechecks'),
        api.request<Record<string, unknown>>('GET', '/api/v1/organization'),
        api.request<Record<string, unknown>>('GET', '/api/v1/audit-logs')
      ]);

    if (dashRes.ok && dashRes.data) {
      setDashboard(dashRes.data);
      setPrincipal((dashRes.data.principal as AuthenticatedPrincipal) ?? null);
    }
    if (projRes.ok && projRes.data) setProjects(projRes.data);
    if (scanRes.ok && scanRes.data) setScans(scanRes.data);
    if (findRes.ok && findRes.data) setFindings(findRes.data);
    if (taskRes.ok && taskRes.data) setTasks(taskRes.data);
    if (rechRes.ok && rechRes.data) setRechecks(rechRes.data);
    if (orgRes.ok && orgRes.data) setOrganization(orgRes.data);
    if (audRes.ok && audRes.data) setAuditLogs(audRes.data);
  };

  useEffect(() => {
    void refreshAll();
  }, []);

  return (
    <div className="hs-shell">
      <aside className="hs-sidebar">
        <div>
          <div className="hs-brand">
            <div className="hs-brand-mark">HS</div>
            <div>
              <div style={{ fontWeight: 700, letterSpacing: '-0.02em' }}>HEGOSENTINEL</div>
              <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--accent-lime)' }}>
                v0.1.0-alpha.4 · SEC-VERIFIED
              </div>
            </div>
          </div>
          <nav className="hs-nav-list" aria-label="Main Platform Navigation">
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
                className={`hs-nav-btn ${activeScreen === key ? 'active' : ''}`}
                onClick={() => setActiveScreen(key)}
              >
                <span>{label}</span>
                <span className="hs-nav-index">{idx}</span>
              </button>
            ))}
          </nav>
        </div>
      </aside>
      <main className="hs-main">
        <header className="hs-topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span className="hs-badge lime">{t.status.remoteBlocked}</span>
            <span className="hs-badge">{t.status.auditChainValid}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              className="hs-btn"
              onClick={() => setLocale(locale === 'tr' ? 'en' : 'tr')}
            >
              {locale === 'tr' ? 'EN' : 'TR'}
            </button>
          </div>
        </header>
        <div className="hs-content">
          {toast && (
            <div className="hs-panel" role="status">
              {toast.text}
            </div>
          )}
          <section className="hs-panel">
            <h1>{t.dashboard.title}</h1>
            <p>{t.dashboard.subtitle}</p>
            <div className="mono">
              Active Principal: {principal?.name ?? 'Loading...'} ({principal?.role ?? 'owner'}) —{' '}
              Score: {String(dashboard?.security_score ?? 100)} · Projects: {projects.length} ·
              Scans: {scans.length} · Findings: {findings.length} · Tasks: {tasks.length} ·
              Rechecks: {rechecks.length} · Org:{' '}
              {String(organization?.organization_name ?? '')} · Audit Verified:{' '}
              {String((auditLogs?.integrity as Record<string, unknown> | undefined)?.valid ?? true)}
            </div>
            <button
              type="button"
              className="hs-btn primary"
              onClick={() => setToast({ type: 'ok', text: 'Refreshed telemetry' })}
            >
              Refresh
            </button>
          </section>
        </div>
      </main>
    </div>
  );
}

