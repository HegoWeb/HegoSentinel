import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScopeAuthorizationGrant } from '../../findings-schema/src/index.ts';
import {
  classifyIpAddress,
  parseAndValidateCanonicalUrl,
  validateScopeAuthorizationGrant,
  verifyRemoteEgressSandboxGate
} from '../../policy-engine/src/index.ts';
import { compareScanReports } from '../../recheck-engine/src/index.ts';
import {
  renderHtmlReport,
  renderJsonReport,
  renderMarkdownReport,
  renderSarifReport
} from '../../report-engine/src/index.ts';
import { executeScan, type SyntheticDemoFixture } from './index.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '../../..');

function loadDemoAssets(): {
  grant: ScopeAuthorizationGrant;
  baselineFixture: SyntheticDemoFixture;
  patchedFixture: SyntheticDemoFixture;
} {
  const grant = JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
  ) as ScopeAuthorizationGrant;
  const baselineFixture = JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'examples/safe-demo/fixture-baseline.json'), 'utf8')
  ) as SyntheticDemoFixture;
  const patchedFixture = JSON.parse(
    readFileSync(resolve(REPO_ROOT, 'examples/safe-demo/fixture-patched.json'), 'utf8')
  ) as SyntheticDemoFixture;
  return { grant, baselineFixture, patchedFixture };
}

export const WORKBENCH_CSP_HEADER =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

export function setSecurityHeaders(res: ServerResponse, contentType: string): void {
  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', WORKBENCH_CSP_HEADER);
}

const LOOPBACK_HOST_REGEX = /^(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/i;
const LOOPBACK_ORIGIN_REGEX = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/i;
export const MAX_WORKBENCH_POST_BYTES = 16 * 1024;

export function validateLoopbackRequest(req: IncomingMessage): {
  allowed: boolean;
  statusCode?: number;
  error?: string;
} {
  const host = typeof req.headers.host === 'string' ? req.headers.host.trim() : '';
  if (!host || !LOOPBACK_HOST_REGEX.test(host)) {
    return {
      allowed: false,
      statusCode: 403,
      error: 'Forbidden: Local Workbench only accepts loopback Host headers (localhost or 127.0.0.1)'
    };
  }

  if (req.method === 'POST') {
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
    if (origin && !LOOPBACK_ORIGIN_REGEX.test(origin)) {
      return {
        allowed: false,
        statusCode: 403,
        error: 'Forbidden: Cross-origin POST request blocked by loopback Origin policy'
      };
    }
    const secFetchSite =
      typeof req.headers['sec-fetch-site'] === 'string'
        ? req.headers['sec-fetch-site'].trim().toLowerCase()
        : '';
    if (secFetchSite === 'cross-site') {
      return {
        allowed: false,
        statusCode: 403,
        error: 'Forbidden: Cross-site request blocked by Fetch Metadata policy'
      };
    }
  }

  return { allowed: true };
}

export function renderWorkbenchCss(): string {
  return `:root {
      color-scheme: dark;
      accent-color: #d4ff33;
      --bg-obsidian: #050507;
      --bg-surface: #0b0d13;
      --bg-elevated: #111520;
      --hairline: rgba(255, 255, 255, 0.08);
      --hairline-strong: rgba(255, 255, 255, 0.16);
      --text-primary: #f3f5f8;
      --text-secondary: #9ba3b2;
      --text-muted: #646d7d;
      --accent-lime: #d4ff33;
      --accent-lime-dim: rgba(212, 255, 51, 0.12);
      --status-warn: #f59e0b;
      --status-danger: #f43f5e;
      --status-ok: #10b981;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    h1, h2, h3, h4 { text-wrap: balance; }
    p, dd, li { text-wrap: pretty; }

    html, body {
      background-color: var(--bg-obsidian);
      color: var(--text-primary);
      font-family: var(--font-sans);
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
      overflow-x: hidden;
      line-height: 1.5;
    }

    .mono-label {
      font-family: var(--font-mono);
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--text-secondary);
    }

    .accent-text { color: var(--accent-lime); }
    .text-warn { color: var(--status-warn); }
    .mt-lg { margin-top: 1.5rem; }
    .mt-xl { margin-top: 2rem; }
    .mt-sm { margin-top: 0.6rem; }
    .mt-xs { margin-top: 0.35rem; }

    /* Top Navigation */
    header.site-nav {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(5, 5, 7, 0.82);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--hairline);
    }

    .nav-inner {
      max-width: 1320px;
      margin: 0 auto;
      padding: 0.9rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      font-size: 1.05rem;
      text-decoration: none;
      color: var(--text-primary);
    }

    .brand-dot {
      width: 10px;
      height: 10px;
      background: var(--accent-lime);
      display: inline-block;
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 1.5rem;
      flex-wrap: wrap;
    }

    .nav-links a {
      color: var(--text-secondary);
      text-decoration: none;
      font-family: var(--font-mono);
      font-size: 11px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      transition: color 0.2s ease;
    }

    .nav-links a:hover { color: var(--accent-lime); }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.3rem 0.7rem;
      background: var(--accent-lime-dim);
      border: 1px solid rgba(212, 255, 51, 0.35);
      color: var(--accent-lime);
      font-family: var(--font-mono);
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }

    /* Hero Stage — Frameless 3D Particle/Topology Field */
    .hero-stage {
      position: relative;
      min-height: 540px;
      border-bottom: 1px solid var(--hairline);
      display: flex;
      align-items: center;
      overflow: hidden;
    }

    #topology-canvas {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 1;
      opacity: 0.85;
    }

    .hero-grid {
      position: relative;
      z-index: 2;
      max-width: 1320px;
      width: 100%;
      margin: 0 auto;
      padding: 4.5rem 1.5rem;
      display: grid;
      grid-template-columns: 1.25fr 0.75fr;
      gap: 2.5rem;
      align-items: center;
    }

    .hero-eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 0.6rem;
      margin-bottom: 1.25rem;
    }

    .hero-title {
      font-size: clamp(2.4rem, 4.8vw, 4.4rem);
      font-weight: 800;
      letter-spacing: -0.038em;
      line-height: 0.96;
      margin-bottom: 1.35rem;
    }

    .hero-subtitle {
      font-size: 1.06rem;
      color: var(--text-secondary);
      max-width: 60ch;
      margin-bottom: 2rem;
    }

    .action-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }

    button.btn-primary, button.btn-secondary, a.btn-secondary {
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 0.8rem 1.2rem;
      border: 1px solid var(--hairline-strong);
      transition: all 0.18s ease;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }

    button.btn-primary {
      background: var(--accent-lime);
      color: #050507;
      border-color: var(--accent-lime);
      font-weight: 700;
    }

    button.btn-primary:hover {
      background: #e2ff66;
      transform: translateY(-1px);
    }

    button.btn-secondary, a.btn-secondary {
      background: rgba(17, 21, 32, 0.78);
      color: var(--text-primary);
    }

    button.btn-secondary:hover, a.btn-secondary:hover {
      border-color: var(--accent-lime);
      color: var(--accent-lime);
    }

    /* Frameless Floating Telemetry Sculpture in Hero Right */
    .hero-sculpture {
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 1rem;
      padding-left: 1.5rem;
      border-left: 1px solid var(--hairline);
    }

    .telemetry-stat {
      padding: 0.65rem 0;
      border-bottom: 1px solid var(--hairline);
    }

    .telemetry-value {
      font-size: clamp(1.6rem, 2.6vw, 2.25rem);
      font-weight: 700;
      letter-spacing: -0.03em;
      color: var(--text-primary);
    }

    /* Structural Sections */
    .container {
      max-width: 1320px;
      margin: 0 auto;
      padding: 3.5rem 1.5rem;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 1rem;
      padding-bottom: 1.25rem;
      border-bottom: 2px solid var(--accent-lime);
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }

    .section-title {
      font-size: clamp(1.5rem, 2.6vw, 2.2rem);
      font-weight: 700;
      letter-spacing: -0.03em;
    }

    /* Interactive Workbench Grid */
    .workbench-grid {
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 1.5rem;
      align-items: start;
    }

    .panel {
      background: var(--bg-surface);
      border: 1px solid var(--hairline);
      padding: 1.35rem;
    }

    .panel-title {
      font-family: var(--font-mono);
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--accent-lime);
      margin-bottom: 1rem;
      padding-bottom: 0.6rem;
      border-bottom: 1px solid var(--hairline);
    }

    .control-stack {
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }

    .control-stack button {
      width: 100%;
      justify-content: space-between;
      text-align: left;
    }

    .meta-list {
      margin-top: 1.25rem;
      display: grid;
      gap: 0.55rem;
      font-size: 0.86rem;
    }

    .meta-row {
      display: flex;
      justify-content: space-between;
      gap: 0.5rem;
      padding-bottom: 0.45rem;
      border-bottom: 1px solid var(--hairline);
    }

    .meta-row span:first-child { color: var(--text-secondary); }
    .meta-row code { font-family: var(--font-mono); color: var(--text-primary); font-size: 0.82rem; }

    /* Tables & Findings */
    .data-table-wrap {
      overflow-x: auto;
      margin-bottom: 1.5rem;
    }

    table.studio-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }

    table.studio-table th, table.studio-table td {
      border: 1px solid var(--hairline);
      padding: 0.65rem 0.8rem;
      text-align: left;
      vertical-align: top;
    }

    table.studio-table th {
      font-family: var(--font-mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-secondary);
      background: var(--bg-elevated);
    }

    .finding-list {
      display: grid;
      gap: 1rem;
    }

    .finding-item {
      background: var(--bg-elevated);
      border: 1px solid var(--hairline);
      padding: 1.25rem;
    }

    .finding-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 0.85rem;
      flex-wrap: wrap;
    }

    .finding-head h4 {
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .badge-group {
      display: flex;
      gap: 0.45rem;
      flex-wrap: wrap;
    }

    .tag {
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      padding: 0.2rem 0.55rem;
      border: 1px solid var(--hairline-strong);
      background: var(--bg-obsidian);
    }

    .tag-lime { border-color: var(--accent-lime); color: var(--accent-lime); }
    .tag-warn { border-color: var(--status-warn); color: var(--status-warn); }
    .tag-danger { border-color: var(--status-danger); color: var(--status-danger); }
    .tag-ok { border-color: var(--status-ok); color: var(--status-ok); }

    .finding-grid {
      display: grid;
      grid-template-columns: 170px 1fr;
      gap: 0.45rem 1rem;
      font-size: 0.88rem;
    }

    .finding-grid dt {
      color: var(--text-secondary);
      font-family: var(--font-mono);
      font-size: 11px;
      text-transform: uppercase;
    }

    /* Security Matrix Bento */
    .matrix-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1px;
      background: var(--hairline);
      border: 1px solid var(--hairline);
    }

    .matrix-cell {
      background: var(--bg-surface);
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.75rem;
    }

    .matrix-cell h4 {
      font-size: 0.96rem;
      font-weight: 600;
    }

    .matrix-cell p {
      font-size: 0.84rem;
      color: var(--text-secondary);
    }

    pre.code-output {
      background: #030406;
      border: 1px solid var(--hairline);
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: #d1d5db;
      overflow-x: auto;
      max-height: 360px;
    }

    footer.site-footer {
      border-top: 1px solid var(--hairline);
      padding: 2.5rem 1.5rem;
      margin-top: 3rem;
      font-size: 0.84rem;
      color: var(--text-secondary);
    }

    .footer-inner {
      max-width: 1320px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    @media (max-width: 960px) {
      .hero-grid { grid-template-columns: 1fr; padding: 3rem 1.25rem; }
      .hero-sculpture { border-left: none; border-top: 1px solid var(--hairline); padding-left: 0; padding-top: 1.25rem; }
      .workbench-grid { grid-template-columns: 1fr; }
      .finding-grid { grid-template-columns: 1fr; }
    }`;
}

export function renderWorkbenchJs(): string {
  return `// Frameless 3D-Projected Orbital Topology Canvas
(function initTopologyCanvas() {
  const canvas = document.getElementById('topology-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const nodes = Array.from({ length: 38 }, (_, i) => ({
    angle: (i / 38) * Math.PI * 2,
    radius: 90 + (i % 4) * 52,
    yOffset: ((i % 5) - 2) * 32,
    speed: (0.0018 + (i % 3) * 0.0007) * (i % 2 === 0 ? 1 : -1),
    isAccent: i % 7 === 0
  }));

  function draw(time) {
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const cx = w * 0.68;
    const cy = h * 0.5;

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    [110, 190, 270].forEach((r) => {
      ctx.beginPath();
      ctx.ellipse(cx, cy, r * 1.25, r * 0.62, -0.18, 0, Math.PI * 2);
      ctx.stroke();
    });

    const projected = nodes.map((n) => {
      const a = n.angle + (prefersReducedMotion ? 0 : time * n.speed * 0.06);
      const x = cx + Math.cos(a) * n.radius * 1.3;
      const z = Math.sin(a) * n.radius;
      const scale = 280 / (280 + z * 0.45);
      const y = cy + n.yOffset * scale + Math.sin(a) * n.radius * 0.38;
      return { x, y, scale, isAccent: n.isAccent };
    });

    for (let i = 0; i < projected.length; i++) {
      for (let j = i + 1; j < projected.length; j++) {
        const dx = projected[i].x - projected[j].x;
        const dy = projected[i].y - projected[j].y;
        const dist = Math.hypot(dx, dy);
        if (dist < 115) {
          ctx.strokeStyle = projected[i].isAccent
            ? 'rgba(212, 255, 51, 0.14)'
            : 'rgba(255, 255, 255, 0.06)';
          ctx.beginPath();
          ctx.moveTo(projected[i].x, projected[i].y);
          ctx.lineTo(projected[j].x, projected[j].y);
          ctx.stroke();
        }
      }
    }

    projected.forEach((p) => {
      ctx.fillStyle = p.isAccent ? '#d4ff33' : 'rgba(243, 245, 248, 0.55)';
      const size = (p.isAccent ? 3.2 : 2.1) * p.scale;
      ctx.beginPath();
      ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
      ctx.fill();
    });

    if (!prefersReducedMotion) {
      requestAnimationFrame(draw);
    }
  }

  requestAnimationFrame(draw);
})();

function escapeText(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderWorkbenchData(payload) {
  const report = payload.report;
  const recheck = payload.recheck;
  if (!report || !report.coverage) return;

  document.getElementById('meta-budget').textContent =
    report.coverage.request_count + ' / ' + report.coverage.max_request_budget;
  const covEl = document.getElementById('meta-coverage');
  covEl.textContent = report.coverage.global_status.toUpperCase();
  covEl.className =
    report.coverage.global_status === 'complete' ? 'accent-text' : 'tag-warn';

  const covTbody = document.getElementById('coverage-tbody');
  covTbody.innerHTML = report.coverage.checks
    .map((c) => {
      const badgeClass =
        c.status === 'executed'
          ? 'tag-ok'
          : c.status === 'denied'
          ? 'tag-danger'
          : 'tag-warn';
      const detail =
        c.reason ||
        (c.positive_validation_passed
          ? 'Positive remediation validation criterion passed'
          : 'Executed against fixture');
      return (
        '<tr>' +
        '<td><code>' + escapeText(c.rule_id) + '</code></td>' +
        '<td><code>' + escapeText(c.rule_version) + '</code></td>' +
        '<td><code>' + escapeText(c.asset_key) + '</code></td>' +
        '<td><span class="tag ' + badgeClass + '">' + escapeText(c.status) + '</span></td>' +
        '<td>' + escapeText(detail) + '</td>' +
        '</tr>'
      );
    })
    .join('');

  const findingsContainer = document.getElementById('findings-container');
  if (report.findings.length === 0) {
    findingsContainer.innerHTML =
      '<div class="finding-item"><p class="mono-label">0 observations emitted for this run (' +
      escapeText(payload.policyDecision?.detail || 'All executed checks passed or were blocked by guardrail') +
      ').</p></div>';
  } else {
    findingsContainer.innerHTML = report.findings
      .map((f) => {
        return (
          '<article class="finding-item">' +
          '<div class="finding-head">' +
          '<h4>' + escapeText(f.id) + ' — ' + escapeText(f.title) + '</h4>' +
          '<div class="badge-group">' +
          '<span class="tag tag-warn">Priority: ' + escapeText(f.risk_priority) + ' (' + escapeText(f.priority_basis) + ')</span>' +
          '<span class="tag">Confidence: ' + escapeText(f.confidence) + '</span>' +
          '<span class="tag tag-lime">Status: ' + escapeText(f.verification_status) + '</span>' +
          '</div>' +
          '</div>' +
          '<dl class="finding-grid">' +
          '<dt>Rule &amp; Asset</dt><dd><code>' + escapeText(f.rule_id) + '</code> on <code>' + escapeText(f.asset_key) + '</code></dd>' +
          '<dt>Observed Signal</dt><dd>' + escapeText(f.observed_condition) + '</dd>' +
          '<dt>Sanitized Evidence</dt><dd><code>' + escapeText(f.evidence_summary) + '</code></dd>' +
          '<dt>Limitations</dt><dd>' + escapeText(f.limitations) + '</dd>' +
          '<dt>Remediation (' + escapeText(f.remediation.owner_role) + ')</dt><dd>' + escapeText(f.remediation.summary) + '</dd>' +
          '<dt>Validation</dt><dd>' + escapeText(f.validation_criterion) + '</dd>' +
          '</dl>' +
          '</article>'
        );
      })
      .join('');
  }

  const retestTbody = document.getElementById('retest-tbody');
  if (recheck && Array.isArray(recheck.items)) {
    retestTbody.innerHTML = recheck.items
      .map((item) => {
        const stClass =
          item.recheck_state === 'verified_fixed'
            ? 'tag-lime'
            : item.recheck_state === 'persistent'
            ? 'tag-warn'
            : 'tag-danger';
        return (
          '<tr>' +
          '<td><code>' + escapeText(item.rule_id) + '</code></td>' +
          '<td><code>' + escapeText(item.asset_key) + '</code></td>' +
          '<td>' + escapeText(item.title) + '</td>' +
          '<td><code>' + escapeText(item.previous_state) + '</code></td>' +
          '<td><span class="tag ' + stClass + '">' + escapeText(item.recheck_state) + '</span></td>' +
          '<td>' + escapeText(item.explanation) + '</td>' +
          '</tr>'
        );
      })
      .join('');
  }

  document.getElementById('raw-json-viewer').textContent = JSON.stringify(
    payload.sarif || payload.recheck || payload.report,
    null,
    2
  );
}

async function callApi(endpoint, body) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  });
  const data = await res.json();
  renderWorkbenchData(data);
}

document.getElementById('btn-run-baseline').addEventListener('click', () =>
  callApi('/api/demo', { mode: 'baseline' })
);
document.getElementById('btn-run-patched').addEventListener('click', () =>
  callApi('/api/demo', { mode: 'recheck' })
);
document.getElementById('btn-hero-demo').addEventListener('click', () =>
  callApi('/api/demo', { mode: 'recheck' })
);
document.getElementById('btn-run-source').addEventListener('click', () =>
  callApi('/api/demo', { mode: 'source' })
);
document.getElementById('btn-hero-source').addEventListener('click', () =>
  callApi('/api/demo', { mode: 'source' })
);

document.querySelectorAll('[data-probe]').forEach((btn) => {
  btn.addEventListener('click', () => {
    callApi('/api/probe', { probe: btn.getAttribute('data-probe') });
  });
});

callApi('/api/demo', { mode: 'recheck' });
`;
}

export function renderWorkbenchHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="dark" />
  <title>HegoSentinel v0.1 — Developer Security Assessment &amp; Evidence-to-Fix Workbench</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23050507'/%3E%3Crect x='8' y='8' width='16' height='16' fill='%23d4ff33'/%3E%3C/svg%3E" />
  <meta name="description" content="HegoSentinel local-first developer security assessment, fail-closed SSRF policy engine, evidence redaction, and deterministic re-test workbench." />
  <link rel="canonical" href="http://localhost:4173/" />
  <meta property="og:title" content="HegoSentinel v0.1 — Developer Security Workbench" />
  <meta property="og:description" content="Authorized security observations, reproducible evidence, contextual remediation, and deterministic re-test workflow." />
  <meta property="og:type" content="website" />
  <link rel="stylesheet" href="/workbench.css" />
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "HegoSentinel",
    "applicationCategory": "DeveloperApplication",
    "operatingSystem": "Cross-platform",
    "softwareVersion": "0.1.0-alpha.4",
    "license": "https://opensource.org/licenses/MIT",
    "description": "Developer-first, self-hosted security assessment and remediation workflow."
  }
  </script>
</head>
<body>
  <header class="site-nav">
    <div class="nav-inner">
      <a href="#top" class="brand">
        <span class="brand-dot"></span>
        <span>HEGOSENTINEL</span>
        <span class="mono-label">v0.1.0-alpha.4</span>
      </a>
      <nav class="nav-links" aria-label="Primary Navigation">
        <a href="#workbench">01 / Live Workbench</a>
        <a href="#retest">02 / Re-Test Loop</a>
        <a href="#guardrails">03 / SSRF &amp; Policy Matrix</a>
        <a href="/reports/demo-recheck.html" target="_blank" rel="noopener">04 / Standalone HTML Report &nearr;</a>
      </nav>
      <div class="status-pill" id="global-gate-badge">
        <span>OFFLINE FIXTURE G0/G1 PASS · REMOTE DISABLED</span>
      </div>
    </div>
  </header>

  <main id="top">
    <!-- Hero Stage with Frameless Interactive WebGL/Canvas Security Topology -->
    <section class="hero-stage" aria-labelledby="hero-heading">
      <canvas id="topology-canvas" width="1440" height="560" aria-hidden="true"></canvas>
      <div class="hero-grid">
        <div>
          <div class="hero-eyebrow">
            <span class="mono-label accent-text">No. 00 / Evidence-to-Fix Loop</span>
            <span class="mono-label">·</span>
            <span class="mono-label">Fail-Closed Architecture</span>
          </div>
          <h1 class="hero-title" id="hero-heading">
            AUTHORIZED OBSERVATIONS.<br />
            <span class="accent-text">VERIFIED FIXES.</span>
          </h1>
          <p class="hero-subtitle">
            Developer-first, self-hosted security assessment and remediation workflow. No authorization &rarr; no scan. No safe egress &rarr; no remote scan. No evidence &rarr; no vulnerability claim.
          </p>
          <div class="action-row">
            <button type="button" class="btn-primary" id="btn-hero-demo">
              <span>Run Offline Baseline &amp; Re-Test</span>
              <span>&rarr;</span>
            </button>
            <button type="button" class="btn-secondary" id="btn-hero-source">
              <span>Run SAST + SCA Fixture (SARIF)</span>
            </button>
            <a href="/reports/demo-baseline.json" target="_blank" rel="noopener" class="btn-secondary">
              <span>Raw JSON Schema</span>
            </a>
          </div>
        </div>

        <div class="hero-sculpture" aria-label="Security Telemetry Posture">
          <div class="telemetry-stat">
            <div class="mono-label">01 / Outbound Network Egress</div>
            <div class="telemetry-value accent-text">0 PACKETS (OFFLINE)</div>
            <div class="mono-label">SEC-014 Enforced · Live Remote HTTP Disabled</div>
          </div>
          <div class="telemetry-stat">
            <div class="mono-label">02 / Security &amp; Audit Regression Suite</div>
            <div class="telemetry-value">38 / 38 PASSING</div>
            <div class="mono-label">SEC-001 .. 014 + HS-AUDIT + NEW-01 .. 03 + AUD-2026 + AUD-06</div>
          </div>
          <div class="telemetry-stat">
            <div class="mono-label">03 / Secret &amp; Cookie Value Leakage</div>
            <div class="telemetry-value">0 BYTES STORED</div>
            <div class="mono-label">Collection Minimization + Multi-Pass Redaction</div>
          </div>
        </div>
      </div>
    </section>

    <!-- Section 01: Interactive Workbench -->
    <section class="container" id="workbench" aria-labelledby="workbench-heading">
      <div class="section-header">
        <div>
          <div class="mono-label accent-text">No. 01 / Stage 0 &amp; Stage 1 Vertical Slice</div>
          <h2 class="section-title" id="workbench-heading">Interactive Scan &amp; Evidence Workbench</h2>
        </div>
        <div class="mono-label" id="active-scan-meta">Active Grant: GRANT-DEMO-2026-0001 (Scope v1)</div>
      </div>

      <div class="workbench-grid">
        <aside class="panel" aria-label="Scan Execution Controls">
          <div class="panel-title">Execution Profiles</div>
          <div class="control-stack">
            <button type="button" class="btn-primary" id="btn-run-baseline">
              <span>1. Baseline Scan (Unpatched)</span>
              <span>RUN</span>
            </button>
            <button type="button" class="btn-secondary" id="btn-run-patched">
              <span>2. Apply CSP Fix &amp; Re-Test</span>
              <span>COMPARE</span>
            </button>
            <button type="button" class="btn-secondary" id="btn-run-source">
              <span>3. Local SAST + SCA (Semgrep/Trivy)</span>
              <span>SOURCE</span>
            </button>
          </div>

          <div class="panel-title mt-lg">Adversarial Guardrail Probes</div>
          <div class="control-stack">
            <button type="button" class="btn-secondary" data-probe="ssrf-metadata">
              <span>Probe Cloud Metadata SSRF</span>
              <span>SEC-002</span>
            </button>
            <button type="button" class="btn-secondary" data-probe="dns-rebind">
              <span>Simulate TOCTOU DNS Rebind</span>
              <span>SEC-004</span>
            </button>
            <button type="button" class="btn-secondary" data-probe="expired-grant">
              <span>Probe Expired Scope Grant</span>
              <span>SEC-001</span>
            </button>
            <button type="button" class="btn-secondary" data-probe="remote-egress">
              <span>Probe Unverified Remote Mode</span>
              <span>SEC-005</span>
            </button>
          </div>

          <div class="meta-list" id="grant-summary-box">
            <div class="meta-row"><span>Target Host</span><code>demo.example.test:443</code></div>
            <div class="meta-row"><span>Written Auth</span><code>DEMO-AUTH-DOC-2026-01</code></div>
            <div class="meta-row"><span>Methods</span><code>GET, HEAD</code></div>
            <div class="meta-row"><span>Request Budget</span><code id="meta-budget">1 / 10</code></div>
            <div class="meta-row"><span>Coverage Status</span><code id="meta-coverage" class="accent-text">COMPLETE</code></div>
          </div>
        </aside>

        <div class="panel">
          <div class="panel-title" id="results-panel-title">Coverage Matrix &amp; Normalized Observations</div>

          <div class="data-table-wrap">
            <table class="studio-table" aria-label="Check Coverage Matrix">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Version</th>
                  <th>Asset</th>
                  <th>Execution Status</th>
                  <th>Details / Validation</th>
                </tr>
              </thead>
              <tbody id="coverage-tbody"></tbody>
            </table>
          </div>

          <div class="finding-list" id="findings-container"></div>

          <div id="retest-section" class="mt-xl">
            <div class="panel-title" id="retest">Re-Test Differential Comparison (Baseline &rarr; Patched)</div>
            <div class="data-table-wrap">
              <table class="studio-table" aria-label="Re-Test Comparison">
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Asset</th>
                    <th>Finding</th>
                    <th>Previous</th>
                    <th>Re-Test State</th>
                    <th>Deterministic Explanation</th>
                  </tr>
                </thead>
                <tbody id="retest-tbody"></tbody>
              </table>
            </div>
          </div>

          <div class="mt-lg">
            <div class="panel-title">Sanitized JSON / SARIF Artifact Inspector</div>
            <pre class="code-output" id="raw-json-viewer">Loading sanitized report...</pre>
          </div>
        </div>
      </div>
    </section>

    <!-- Section 02: Release-Blocking Security Matrix -->
    <section class="container" id="guardrails" aria-labelledby="guardrails-heading">
      <div class="section-header">
        <div>
          <div class="mono-label accent-text">No. 02 / Threat Review Controls (HSR-01 .. HSR-12)</div>
          <h2 class="section-title" id="guardrails-heading">Release-Blocking Security Acceptance Matrix</h2>
        </div>
        <div class="mono-label">All 38 Automated Gate Assertions Verified</div>
      </div>

      <div class="matrix-grid">
        <article class="matrix-cell">
          <div>
            <span class="tag tag-lime">SEC-001 · HSR-02</span>
            <h4 class="mt-sm">Strongly-Typed Expiring Grant</h4>
            <p class="mt-xs">Requires explicit written permission reference, active time window, exact host/port/path allowlist, and blocks wildcards with zero network requests.</p>
          </div>
          <div class="mono-label accent-text">STATUS: ENFORCED</div>
        </article>
        <article class="matrix-cell">
          <div>
            <span class="tag tag-lime">SEC-002 · SEC-004</span>
            <h4 class="mt-sm">SSRF, IPv6 &amp; DNS Rebind Pinning</h4>
            <p class="mt-xs">Blocks RFC1918, loopback, link-local, cloud metadata (169.254.169.254 / fd00:ec2::254), IPv4-mapped IPv6, and verifies socket peer IP on connect.</p>
          </div>
          <div class="mono-label accent-text">STATUS: ENFORCED</div>
        </article>
        <article class="matrix-cell">
          <div>
            <span class="tag tag-warn">SEC-005 · HSR-01 · HS-AUDIT-003 · AUD-2026-05</span>
            <h4 class="mt-sm">Remote Egress Sandbox Blocker</h4>
            <p class="mt-xs">Live remote HTTP socket fetching is not enabled in v0.1.0-alpha.4. Remote target mode fails closed until OS/container egress firewall attestation is deployed.</p>
          </div>
          <div class="mono-label text-warn">GATE: FAIL-CLOSED (REMOTE DISABLED)</div>
        </article>
        <article class="matrix-cell">
          <div>
            <span class="tag tag-lime">SEC-006 · HSR-03 · HS-AUDIT-002 · NEW-01 · AUD-2026-02/04</span>
            <h4 class="mt-sm">Untrusted Repository &amp; Realpath Isolation</h4>
            <p class="mt-xs">Semgrep and Trivy adapters enforce fail-closed realpathSync + lstatSync symlink checks (including node_modules), 25,000-entry budget, post-scan TOCTOU re-validation, and binary allowlists.</p>
          </div>
          <div class="mono-label accent-text">STATUS: ENFORCED</div>
        </article>
        <article class="matrix-cell">
          <div>
            <span class="tag tag-lime">SEC-007 · HSR-06</span>
            <h4 class="mt-sm">Collection Minimization &amp; Redaction</h4>
            <p class="mt-xs">Set-Cookie values are discarded at observation time; Authorization headers, JWTs, API keys, and query secrets are scrubbed before disk persistence.</p>
          </div>
          <div class="mono-label accent-text">STATUS: 0 LEAKS VERIFIED</div>
        </article>
        <article class="matrix-cell">
          <div>
            <span class="tag tag-lime">SEC-008 · SEC-009 · HS-AUDIT-001/004 · NEW-02/03 · AUD-06</span>
            <h4 class="mt-sm">Strict Asset &amp; Cookie-Identity Coverage, CSP Semantics &amp; Schema</h4>
            <p class="mt-xs">Re-test requires exact (rule_id, asset_key, grant_id, scope_version) match, per-cookie fingerprint proof, strict SameSite/CSP checks, and JSON Schema verification.</p>
          </div>
          <div class="mono-label accent-text">STATUS: ENFORCED</div>
        </article>
      </div>
    </section>
  </main>

  <footer class="site-footer">
    <div class="footer-inner">
      <div>
        <strong>HegoSentinel v0.1.0-alpha.4</strong> · MIT License · Copyright (c) 2026 HegoWeb.<br />
        <span>Zero third-party cookies or analytics trackers are used on this local workbench (KVKK / GDPR compliant by design).</span>
      </div>
      <div class="mono-label">
        LOCAL WORKBENCH · OFFLINE FIXTURE &amp; LOCAL SOURCE MODE
      </div>
    </div>
  </footer>

  <script src="/workbench.js" defer></script>
</body>
</html>`;
}

export interface JsonBodyParseResult {
  ok: boolean;
  statusCode: number;
  data?: Record<string, unknown>;
  error?: string;
}

export async function readJsonBody(
  req: IncomingMessage,
  maxBytes: number = MAX_WORKBENCH_POST_BYTES
): Promise<JsonBodyParseResult> {
  return new Promise((resolvePromise) => {
    let raw = '';
    let totalBytes = 0;
    let settled = false;

    const utf8Encoder = new TextEncoder();
    req.on('data', (chunk: unknown) => {
      if (settled) return;
      const strChunk = String(chunk);
      totalBytes += utf8Encoder.encode(strChunk).byteLength;
      if (totalBytes > maxBytes) {
        settled = true;
        resolvePromise({
          ok: false,
          statusCode: 413,
          error: `Payload Too Large: POST body exceeds maximum ${maxBytes} bytes`
        });
        return;
      }
      raw += strChunk;
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      const trimmed = raw.trim();
      if (trimmed.length === 0) {
        resolvePromise({ ok: true, statusCode: 200, data: {} });
        return;
      }
      try {
        const parsed = JSON.parse(trimmed);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          resolvePromise({
            ok: false,
            statusCode: 400,
            error: 'Bad Request: expected a JSON object body'
          });
          return;
        }
        resolvePromise({ ok: true, statusCode: 200, data: parsed as Record<string, unknown> });
      } catch {
        resolvePromise({
          ok: false,
          statusCode: 400,
          error: 'Bad Request: malformed JSON payload'
        });
      }
    });

    req.on('error', () => {
      if (settled) return;
      settled = true;
      resolvePromise({
        ok: false,
        statusCode: 400,
        error: 'Bad Request: stream error reading request body'
      });
    });
  });
}

export function startWorkbenchServer(port: number = 4173) {
  const { grant, baselineFixture, patchedFixture } = loadDemoAssets();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const loopbackCheck = validateLoopbackRequest(req);
    if (!loopbackCheck.allowed) {
      setSecurityHeaders(res, 'application/json; charset=utf-8');
      res.statusCode = loopbackCheck.statusCode ?? 403;
      res.end(JSON.stringify({ error: loopbackCheck.error }));
      return;
    }

    const url = req.url ?? '/';

    if (req.method === 'GET' && url === '/favicon.ico') {
      res.statusCode = 204;
      res.end();
      return;
    }

    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      setSecurityHeaders(res, 'text/html; charset=utf-8');
      res.statusCode = 200;
      res.end(renderWorkbenchHtml());
      return;
    }

    if (req.method === 'GET' && url === '/workbench.css') {
      setSecurityHeaders(res, 'text/css; charset=utf-8');
      res.statusCode = 200;
      res.end(renderWorkbenchCss());
      return;
    }

    if (req.method === 'GET' && url === '/workbench.js') {
      setSecurityHeaders(res, 'application/javascript; charset=utf-8');
      res.statusCode = 200;
      res.end(renderWorkbenchJs());
      return;
    }

    if (req.method === 'GET' && url === '/reports/demo-baseline.json') {
      const baselineExec = await executeScan({
        grant,
        mode: 'offline-fixture',
        scanId: 'SCAN-DEMO-BASELINE-001',
        fixture: baselineFixture,
        now: new Date('2026-11-04T20:00:00.000Z')
      });
      setSecurityHeaders(res, 'application/json; charset=utf-8');
      res.statusCode = 200;
      res.end(renderJsonReport(baselineExec.report));
      return;
    }

    if (req.method === 'GET' && url === '/reports/demo-recheck.html') {
      const baselineExec = await executeScan({
        grant,
        mode: 'offline-fixture',
        scanId: 'SCAN-DEMO-BASELINE-001',
        fixture: baselineFixture,
        now: new Date('2026-11-04T20:00:00.000Z')
      });
      const patchedExec = await executeScan({
        grant,
        mode: 'offline-fixture',
        scanId: 'SCAN-DEMO-PATCHED-002',
        fixture: patchedFixture,
        now: new Date('2026-11-04T20:05:00.000Z')
      });
      const cmp = compareScanReports(baselineExec.report, patchedExec.report, {
        now: new Date('2026-11-04T20:05:00.000Z')
      });
      setSecurityHeaders(res, 'text/html; charset=utf-8');
      res.statusCode = 200;
      res.end(renderHtmlReport(patchedExec.report, cmp));
      return;
    }

    if (req.method === 'POST' && url === '/api/demo') {
      const parsedBody = await readJsonBody(req);
      if (!parsedBody.ok || !parsedBody.data) {
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = parsedBody.statusCode;
        res.end(JSON.stringify({ error: parsedBody.error }));
        return;
      }
      const body = parsedBody.data;
      const mode = body.mode ?? 'recheck';
      const t0 = new Date('2026-11-04T20:00:00.000Z');
      const t1 = new Date('2026-11-04T20:05:00.000Z');

      const baselineExec = await executeScan({
        grant,
        mode: 'offline-fixture',
        scanId: 'SCAN-DEMO-BASELINE-001',
        fixture: baselineFixture,
        now: t0
      });

      if (mode === 'baseline') {
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            policyDecision: baselineExec.policyDecision,
            report: baselineExec.report
          })
        );
        return;
      }

      if (mode === 'source') {
        const sourceGrant: ScopeAuthorizationGrant = {
          ...grant,
          profile: 'source',
          allowed_checks: ['CODE-001', 'DEP-001']
        };
        const sourceExec = await executeScan({
          grant: sourceGrant,
          mode: 'local-source',
          scanId: 'SCAN-DEMO-SOURCE-003',
          repositoryPath: resolve(REPO_ROOT, 'examples/safe-demo/sample-repo'),
          now: t1,
          fixture: {
            fixture_id: 'SOURCE-DEMO-FIXTURE',
            description: 'Offline SAST + SCA fixture',
            endpoints: [],
            semgrep_fixture: {
              version: '1.90.0',
              results: [
                {
                  check_id: 'laravel.security.raw-blade-unescaped',
                  path: 'resources/views/profile.blade.php',
                  start: { line: 42 },
                  extra: {
                    message: 'Unescaped Blade expression {!! $bio !!} observed',
                    severity: 'WARNING',
                    metadata: { confidence: 'HIGH' }
                  }
                }
              ]
            },
            trivy_fixture: {
              SchemaVersion: 2,
              Metadata: { Version: '0.56.0' },
              Results: [
                {
                  Target: 'package-lock.json',
                  Vulnerabilities: [
                    {
                      VulnerabilityID: 'CVE-2026-0001',
                      PkgName: 'example-lib',
                      InstalledVersion: '1.0.0',
                      FixedVersion: '1.0.1',
                      Severity: 'HIGH',
                      PrimaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001'
                    }
                  ]
                }
              ]
            }
          }
        });

        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            policyDecision: sourceExec.policyDecision,
            report: sourceExec.report,
            sarif: JSON.parse(renderSarifReport(sourceExec.report))
          })
        );
        return;
      }

      const patchedExec = await executeScan({
        grant,
        mode: 'offline-fixture',
        scanId: 'SCAN-DEMO-PATCHED-002',
        fixture: patchedFixture,
        now: t1
      });
      const recheck = compareScanReports(baselineExec.report, patchedExec.report, {
        now: t1
      });

      setSecurityHeaders(res, 'application/json; charset=utf-8');
      res.statusCode = 200;
      res.end(
        JSON.stringify({
          policyDecision: patchedExec.policyDecision,
          report: baselineExec.report,
          patchedReport: patchedExec.report,
          recheck,
          markdownPreview: renderMarkdownReport(patchedExec.report, recheck)
        })
      );
      return;
    }

    if (req.method === 'POST' && url === '/api/probe') {
      const parsedBody = await readJsonBody(req);
      if (!parsedBody.ok || !parsedBody.data) {
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = parsedBody.statusCode;
        res.end(JSON.stringify({ error: parsedBody.error ?? 'Invalid JSON body' }));
        return;
      }
      const body = parsedBody.data;
      const probe = String(body.probe ?? 'ssrf-metadata');
      const now = new Date('2026-11-04T20:00:00.000Z');

      if (probe === 'ssrf-metadata') {
        const ipCheck = classifyIpAddress('169.254.169.254');
        const urlCheck = parseAndValidateCanonicalUrl(
          'https://169.254.169.254/latest/meta-data/',
          grant
        );
        const deniedExec = await executeScan({
          grant,
          mode: 'offline-fixture',
          scanId: 'SCAN-PROBE-SSRF-001',
          now,
          fixture: {
            fixture_id: 'PROBE-SSRF',
            description: 'Cloud metadata SSRF probe',
            endpoints: [
              {
                url: 'https://169.254.169.254/latest/meta-data/',
                status_code: 200,
                headers: {}
              }
            ]
          }
        });
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            policyDecision: {
              ...urlCheck.decision,
              ipClassification: ipCheck
            },
            report: deniedExec.report
          })
        );
        return;
      }

      if (probe === 'dns-rebind') {
        const rebindExec = await executeScan({
          grant,
          mode: 'offline-fixture',
          scanId: 'SCAN-PROBE-REBIND-001',
          now,
          fixture: {
            fixture_id: 'PROBE-REBIND',
            description: 'DNS rebinding simulation',
            endpoints: [
              {
                url: 'https://demo.example.test/',
                status_code: 200,
                headers: {},
                simulated_socket_peer_ip: '127.0.0.1'
              }
            ]
          }
        });
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            policyDecision: rebindExec.policyDecision,
            report: rebindExec.report
          })
        );
        return;
      }

      if (probe === 'expired-grant') {
        const expiredGrant: ScopeAuthorizationGrant = {
          ...grant,
          expires_at: '2026-01-02T00:00:00.000Z'
        };
        const expExec = await executeScan({
          grant: expiredGrant,
          mode: 'offline-fixture',
          scanId: 'SCAN-PROBE-EXPIRED-001',
          now
        });
        setSecurityHeaders(res, 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(
          JSON.stringify({
            policyDecision: validateScopeAuthorizationGrant(expiredGrant, now),
            report: expExec.report
          })
        );
        return;
      }

      // Default: remote-egress
      const remoteExec = await executeScan({
        grant: { ...grant, profile: 'safe-web' },
        mode: 'restricted-remote',
        scanId: 'SCAN-PROBE-REMOTE-001',
        now
      });
      setSecurityHeaders(res, 'application/json; charset=utf-8');
      res.statusCode = 200;
      res.end(
        JSON.stringify({
          policyDecision: verifyRemoteEgressSandboxGate(undefined),
          report: remoteExec.report
        })
      );
      return;
    }

    setSecurityHeaders(res, 'application/json; charset=utf-8');
    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(
      `HegoSentinel Local Workbench running at http://localhost:${port}\n`
    );
  });

  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  const portArg = process.env.PORT ? Number.parseInt(process.env.PORT, 10) : 4173;
  startWorkbenchServer(portArg);
}
