import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { dirname, extname, isAbsolute, relative, resolve } from 'node:path';
import {
  computeEvidenceHash,
  type NormalizedFinding,
  type RecheckComparisonReport,
  type ScanReport
} from '../../findings-schema/src/index.ts';

/**
 * Defense-in-depth redaction of sensitive tokens, cookies, Authorization headers, JWTs,
 * PEM private keys, database connection URIs, framework secrets (Laravel APP_KEY, Next.js NEXTAUTH_SECRET),
 * query credentials, and personal emails from any text before disk persistence (S1-04 / HSR-06 / SEC-007).
 */
export function redactSensitiveText(input: string): string {
  if (!input) return '';

  // 1. Strip control characters except newline/tab
  let out = input.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');

  // 1b. Redact PEM / OpenSSH private key blocks
  out = out.replace(
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    '[REDACTED_PRIVATE_KEY]'
  );

  // 1c. Redact database / cache / broker connection URIs with embedded credentials
  out = out.replace(
    /\b((?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^:\s/@"']+: )?((?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/(?:[^:\s/@"']+)?:[^@\s/"']+@[^\s"']+)/gi,
    '[REDACTED_DB_URI]'
  );

  // 2. Redact Authorization header values
  out = out.replace(
    /(Authorization\s*:\s*)(Bearer\s+[^\s,;]+|Basic\s+[^\s,;]+|Token\s+[^\s,;]+|[^\r\n,;]+)/gi,
    '$1[REDACTED]'
  );

  // 3. Redact Cookie request headers completely
  out = out.replace(/(^|\b)(Cookie\s*:\s*)([^\r\n]+)/gi, '$1$2[REDACTED]');

  // 4. Redact Set-Cookie values while keeping cookie name and attribute flags
  out = out.replace(
    /(Set-Cookie\s*:\s*[^=;\s]+=)([^;\r\n]*)/gi,
    '$1[REDACTED]'
  );

  // 5. Redact JWT tokens (header.payload.signature)
  out = out.replace(
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    '[REDACTED_JWT]'
  );

  // 6. Redact known API key formats (GitHub, OpenAI/Stripe-like sk-, AWS AKIA, Slack xox, Google AIza)
  out = out.replace(
    /\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g,
    '[REDACTED_SECRET]'
  );

  // 6b. Redact Laravel APP_KEY=base64:..., Next.js NEXTAUTH_SECRET, AWS_SECRET_ACCESS_KEY, DB_PASSWORD
  out = out.replace(
    /\b(APP_KEY|NEXTAUTH_SECRET|NEXT_PUBLIC_INTERNAL_API_SECRET|JWT_SECRET|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET_KEY)(\s*[:=]\s*["']?)([^"',;\s\r\n}]+)(["']?)/gi,
    '$1$2[REDACTED]$4'
  );

  // 7. Redact sensitive URL query parameters
  out = out.replace(
    /([?&](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|pwd|session|session_id|sid|phpsessid|laravel_session|auth|code|signature|sig)=)([^&#\s]+)/gi,
    '$1[REDACTED]'
  );

  // 8. Redact inline key=value or JSON "password": "..." / "secret": "..." patterns
  out = out.replace(
    /((?:["']?(?:password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|private_key|session_token|cookie_value)["']?)\s*[:=]\s*["']?)([^"',;\s\r\n}]+)(["']?)/gi,
    '$1[REDACTED]$3'
  );

  // 9. Redact email addresses in evidence strings
  out = out.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    '[REDACTED_EMAIL]'
  );

  return out;
}

const ALLOWED_REPORT_EXTENSIONS = new Set(['.json', '.md', '.html', '.sarif']);

/**
 * Validates that a report export destination path stays strictly inside the authorized output directory,
 * has an approved report extension (.json, .md, .html, .sarif), and is not a symlink escape (Sprint 7).
 */
export function validateSafeReportOutputPath(
  outputPath: string,
  allowedOutputRoot: string
): { allowed: boolean; resolvedPath?: string; reason?: string } {
  if (!outputPath || typeof outputPath !== 'string' || outputPath.includes('\0')) {
    return { allowed: false, reason: 'Invalid or null-byte report output path' };
  }

  const rootResolved = resolve(allowedOutputRoot);
  const candidateResolved = resolve(rootResolved, outputPath);
  const rel = relative(rootResolved, candidateResolved);

  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
    return {
      allowed: false,
      reason: `Report output path "${outputPath}" escapes authorized output root "${rootResolved}"`
    };
  }

  const ext = extname(candidateResolved).toLowerCase();
  if (!ALLOWED_REPORT_EXTENSIONS.has(ext)) {
    return {
      allowed: false,
      reason: `Disallowed report file extension "${ext}"; allowed: .json, .md, .html, .sarif`
    };
  }

  if (existsSync(rootResolved)) {
    try {
      const realRoot = realpathSync(rootResolved);
      const parentDir = dirname(candidateResolved);
      if (existsSync(parentDir)) {
        const parentStat = lstatSync(parentDir);
        if (parentStat.isSymbolicLink()) {
          return {
            allowed: false,
            reason: `Report output directory "${parentDir}" is a symbolic link; blocked for symlink safety`
          };
        }
        const realParent = realpathSync(parentDir);
        const realRel = relative(realRoot, realParent);
        if (realRel.startsWith('..') || isAbsolute(realRel)) {
          return {
            allowed: false,
            reason: `Physical parent path "${realParent}" escapes authorized output root "${realRoot}" via symlink`
          };
        }
      }
      if (existsSync(candidateResolved) && lstatSync(candidateResolved).isSymbolicLink()) {
        return {
          allowed: false,
          reason: `Target report file "${candidateResolved}" is an existing symbolic link; refusing to overwrite`
        };
      }
    } catch (err) {
      return {
        allowed: false,
        reason: `Failed to verify physical report output path safety: ${(err as Error).message}`
      };
    }
  }

  return { allowed: true, resolvedPath: candidateResolved };
}

/**
 * Applies allowlist serialization and redaction to a finding (HSR-06).
 */
export function sanitizeFindingForReport(finding: NormalizedFinding): NormalizedFinding {
  const safeAssetKey = redactSensitiveText(finding.asset_key);
  const safeObservedCondition = redactSensitiveText(finding.observed_condition);
  const safeEvidenceSummary = redactSensitiveText(finding.evidence_summary);
  const safeInferredRisk = redactSensitiveText(finding.inferred_risk);
  const safeLimitations = redactSensitiveText(finding.limitations);

  return {
    schema_version: finding.schema_version,
    id: finding.id,
    rule_id: finding.rule_id,
    rule_version: finding.rule_version,
    organization_id: finding.organization_id,
    project_id: finding.project_id,
    asset_key: safeAssetKey,
    fingerprint: finding.fingerprint,
    title: redactSensitiveText(finding.title),
    observed_condition: safeObservedCondition,
    evidence_summary: safeEvidenceSummary,
    evidence_hash: computeEvidenceHash(safeEvidenceSummary),
    inferred_risk: safeInferredRisk,
    limitations: safeLimitations,
    confidence: finding.confidence,
    risk_priority: finding.risk_priority,
    priority_basis: finding.priority_basis,
    ...(finding.cvss_v4_vector ? { cvss_v4_vector: finding.cvss_v4_vector } : {}),
    ...(finding.cvss_v4_score !== undefined ? { cvss_v4_score: finding.cvss_v4_score } : {}),
    verification_status: finding.verification_status,
    scanner_version: finding.scanner_version,
    observed_at: finding.observed_at,
    standards: {
      cwe: [...finding.standards.cwe],
      owasp_asvs_5_0: [...finding.standards.owasp_asvs_5_0],
      owasp_wstg_4_2: [...finding.standards.owasp_wstg_4_2],
      references: [...finding.standards.references]
    },
    remediation: {
      summary: redactSensitiveText(finding.remediation.summary),
      owner_role: redactSensitiveText(finding.remediation.owner_role),
      framework_guides: finding.remediation.framework_guides.map((g) => ({
        framework: g.framework,
        prerequisites: redactSensitiveText(g.prerequisites),
        steps: g.steps.map((s) => redactSensitiveText(s)),
        side_effects: redactSensitiveText(g.side_effects)
      }))
    },
    validation_criterion: redactSensitiveText(finding.validation_criterion)
  };
}

export function sanitizeReport(report: ScanReport): ScanReport {
  return {
    ...report,
    findings: report.findings.map((f) => sanitizeFindingForReport(f)),
    informational_notes: report.informational_notes.map((n) => ({
      rule_id: n.rule_id,
      asset_key: redactSensitiveText(n.asset_key),
      note: redactSensitiveText(n.note)
    })),
    coverage: {
      ...report.coverage,
      checks: report.coverage.checks.map((c) => ({
        ...c,
        asset_key: redactSensitiveText(c.asset_key),
        ...(c.reason ? { reason: redactSensitiveText(c.reason) } : {})
      }))
    }
  };
}

function escapeMarkdownInline(text: string): string {
  return redactSensitiveText(text).replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeHtml(text: string): string {
  return redactSensitiveText(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderJsonReport(report: ScanReport): string {
  const safe = sanitizeReport(report);
  return `${JSON.stringify(safe, null, 2)}\n`;
}

export function renderMarkdownReport(
  report: ScanReport,
  recheck?: RecheckComparisonReport
): string {
  const safe = sanitizeReport(report);
  const lines: string[] = [];

  lines.push(`# HegoSentinel Developer Security Report`);
  lines.push('');
  lines.push(`> **Notice:** ${escapeMarkdownInline(safe.disclaimer)}`);
  lines.push('');
  lines.push(`## 1. Executive & Engagement Summary`);
  lines.push('');
  lines.push(`- **Scan ID:** \`${escapeMarkdownInline(safe.scan_id)}\``);
  lines.push(`- **Organization / Project:** \`${escapeMarkdownInline(safe.organization_id)}\` / \`${escapeMarkdownInline(safe.project_id)}\` (${escapeMarkdownInline(safe.project_name)})`);
  lines.push(`- **Authorization Grant:** \`${escapeMarkdownInline(safe.grant_id)}\` (Scope v${safe.scope_version})`);
  lines.push(`- **Profile / Mode:** \`${safe.profile}\` / \`${safe.mode}\``);
  lines.push(`- **Scanner Version:** \`${escapeMarkdownInline(safe.scanner_version)}\``);
  lines.push(`- **Window:** \`${safe.started_at}\` → \`${safe.finished_at}\``);
  lines.push(`- **Global Coverage Status:** **\`${safe.coverage.global_status.toUpperCase()}\`** (${safe.coverage.request_count}/${safe.coverage.max_request_budget} requests used)`);
  lines.push(`- **Findings Summary:** ${safe.summary.total_findings} observation(s), ${safe.summary.informational_count} informational note(s)`);
  lines.push('');

  if (safe.coverage.global_status !== 'complete') {
    lines.push(
      `> [!WARNING]\n> **Incomplete Scan Coverage (\`${safe.coverage.global_status}\`):** One or more checks were skipped, denied, or failed. Do **not** interpret zero findings in skipped checks as proof of security.`
    );
    lines.push('');
  }

  lines.push(`### 1.1 Check Coverage Matrix`);
  lines.push('');
  lines.push(`| Rule ID | Version | Asset | Status | Details / Tool Version |`);
  lines.push(`| --- | --- | --- | --- | --- |`);
  for (const check of safe.coverage.checks) {
    const details = [check.reason, check.tool_version ? `tool: ${check.tool_version}` : '']
      .filter(Boolean)
      .join(' · ') || 'Completed normally';
    lines.push(
      `| \`${check.rule_id}\` | \`${check.rule_version}\` | \`${escapeMarkdownInline(check.asset_key)}\` | **\`${check.status}\`** | ${escapeMarkdownInline(details)} |`
    );
  }
  lines.push('');

  lines.push(`## 2. Developer Findings & Remediation Guidance`);
  lines.push('');

  if (safe.findings.length === 0) {
    lines.push(`_No security observations were recorded for the executed checks._`);
    lines.push('');
  } else {
    for (const f of safe.findings) {
      const priorityLabel =
        f.priority_basis === 'cvss_v4' && f.cvss_v4_vector
          ? `${f.risk_priority.toUpperCase()} (CVSS v4.0: ${f.cvss_v4_score} · \`${f.cvss_v4_vector}\`)`
          : `${f.risk_priority.toUpperCase()} (Internal Priority — not a CVSS score)`;

      lines.push(`### ${escapeMarkdownInline(f.id)} — ${escapeMarkdownInline(f.title)}`);
      lines.push('');
      lines.push(`- **Rule:** \`${f.rule_id}\` (v${f.rule_version})`);
      lines.push(`- **Priority:** ${priorityLabel}`);
      lines.push(`- **Confidence:** \`${f.confidence}\``);
      lines.push(`- **Verification Status:** \`${f.verification_status}\``);
      lines.push(`- **Asset:** \`${escapeMarkdownInline(f.asset_key)}\``);
      lines.push(`- **Fingerprint:** \`${f.fingerprint}\``);
      lines.push(`- **Observed Condition:** ${escapeMarkdownInline(f.observed_condition)}`);
      lines.push(`- **Sanitized Evidence:** ${escapeMarkdownInline(f.evidence_summary)} (Hash: \`${f.evidence_hash.slice(0, 16)}…\`)`);
      lines.push(`- **Why It Matters (Inferred Risk):** ${escapeMarkdownInline(f.inferred_risk)}`);
      lines.push(`- **Limitations / False-Positive Caveat:** ${escapeMarkdownInline(f.limitations)}`);
      lines.push(`- **Owner Role:** ${escapeMarkdownInline(f.remediation.owner_role)}`);
      lines.push(`- **Suggested Action:** ${escapeMarkdownInline(f.remediation.summary)}`);
      lines.push(`- **Re-test Validation Criterion:** ${escapeMarkdownInline(f.validation_criterion)}`);
      lines.push(
        `- **Standards Mapping:** CWE: ${f.standards.cwe.join(', ')} · OWASP ASVS 5.0: ${f.standards.owasp_asvs_5_0.join(', ')} · OWASP WSTG v4.2: ${f.standards.owasp_wstg_4_2.join(', ')}`
      );
      lines.push('');

      for (const guide of f.remediation.framework_guides) {
        lines.push(`#### Framework Guidance: \`${guide.framework}\``);
        lines.push(`- **Prerequisites:** ${escapeMarkdownInline(guide.prerequisites)}`);
        lines.push(`- **Implementation Steps:**`);
        for (const step of guide.steps) {
          lines.push(`  1. ${escapeMarkdownInline(step)}`);
        }
        lines.push(`- **Potential Side Effects:** ${escapeMarkdownInline(guide.side_effects)}`);
        lines.push('');
      }
    }
  }

  if (safe.informational_notes.length > 0) {
    lines.push(`## 3. Informational Notes`);
    lines.push('');
    for (const note of safe.informational_notes) {
      lines.push(`- **\`${note.rule_id}\`** (\`${escapeMarkdownInline(note.asset_key)}\`): ${escapeMarkdownInline(note.note)}`);
    }
    lines.push('');
  }

  if (recheck) {
    lines.push(`## 4. Re-Test Comparison (\`${escapeMarkdownInline(recheck.baseline_scan_id)}\` → \`${escapeMarkdownInline(recheck.current_scan_id)}\`)`);
    lines.push('');
    lines.push(`- **Comparable Runs:** \`${recheck.comparable}\``);
    if (recheck.incomparability_reasons.length > 0) {
      lines.push(`- **Incomparability Reasons:** ${recheck.incomparability_reasons.map(escapeMarkdownInline).join('; ')}`);
    }
    lines.push('');
    lines.push(`| Rule ID | Asset | Title | Previous State | Re-test State | Explanation |`);
    lines.push(`| --- | --- | --- | --- | --- | --- |`);
    for (const item of recheck.items) {
      lines.push(
        `| \`${item.rule_id}\` | \`${escapeMarkdownInline(item.asset_key)}\` | ${escapeMarkdownInline(item.title)} | \`${item.previous_state}\` | **\`${item.recheck_state}\`** | ${escapeMarkdownInline(item.explanation)} |`
      );
    }
    lines.push('');
    lines.push(
      `> _Note: \`no_longer_observed\` or \`verified_fixed\` applies only to the specific tested check and endpoint. It is not a blanket guarantee that the entire application is secure._`
    );
    lines.push('');
  }

  return lines.join('\n');
}

export function renderHtmlReport(
  report: ScanReport,
  recheck?: RecheckComparisonReport
): string {
  const safe = sanitizeReport(report);

  const coverageRows = safe.coverage.checks
    .map(
      (c) => `
      <tr>
        <td><code>${escapeHtml(c.rule_id)}</code></td>
        <td><code>${escapeHtml(c.rule_version)}</code></td>
        <td><code>${escapeHtml(c.asset_key)}</code></td>
        <td><span class="badge status-${escapeHtml(c.status)}">${escapeHtml(c.status)}</span></td>
        <td>${escapeHtml(c.reason ?? 'Completed normally')}</td>
      </tr>`
    )
    .join('');

  const findingCards =
    safe.findings.length === 0
      ? `<p class="muted">No security observations recorded for the executed checks.</p>`
      : safe.findings
          .map(
            (f) => `
      <article class="finding-card">
        <header>
          <h3>${escapeHtml(f.id)} — ${escapeHtml(f.title)}</h3>
          <div class="badges">
            <span class="badge priority-${escapeHtml(f.risk_priority)}">Priority: ${escapeHtml(f.risk_priority.toUpperCase())} (${escapeHtml(f.priority_basis)})</span>
            <span class="badge">Confidence: ${escapeHtml(f.confidence)}</span>
            <span class="badge verification-${escapeHtml(f.verification_status)}">Status: ${escapeHtml(f.verification_status)}</span>
          </div>
        </header>
        <dl>
          <dt>Asset</dt><dd><code>${escapeHtml(f.asset_key)}</code></dd>
          <dt>Rule</dt><dd><code>${escapeHtml(f.rule_id)}</code> (v${escapeHtml(f.rule_version)})</dd>
          <dt>Observed Condition</dt><dd>${escapeHtml(f.observed_condition)}</dd>
          <dt>Sanitized Evidence</dt><dd><code>${escapeHtml(f.evidence_summary)}</code></dd>
          <dt>Inferred Risk</dt><dd>${escapeHtml(f.inferred_risk)}</dd>
          <dt>Limitations</dt><dd>${escapeHtml(f.limitations)}</dd>
          <dt>Remediation (${escapeHtml(f.remediation.owner_role)})</dt><dd>${escapeHtml(f.remediation.summary)}</dd>
          <dt>Re-test Validation</dt><dd>${escapeHtml(f.validation_criterion)}</dd>
          <dt>Standards</dt><dd>${escapeHtml([...f.standards.cwe, ...f.standards.owasp_asvs_5_0, ...f.standards.owasp_wstg_4_2].join(' · '))}</dd>
        </dl>
      </article>`
          )
          .join('');

  const recheckSection = recheck
    ? `
    <section>
      <h2>Re-Test Comparison (<code>${escapeHtml(recheck.baseline_scan_id)}</code> &rarr; <code>${escapeHtml(recheck.current_scan_id)}</code>)</h2>
      <p>Comparable: <strong>${recheck.comparable ? 'Yes' : 'No'}</strong></p>
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Asset</th>
            <th>Title</th>
            <th>Previous</th>
            <th>Re-test State</th>
            <th>Explanation</th>
          </tr>
        </thead>
        <tbody>
          ${recheck.items
            .map(
              (item) => `
            <tr>
              <td><code>${escapeHtml(item.rule_id)}</code></td>
              <td><code>${escapeHtml(item.asset_key)}</code></td>
              <td>${escapeHtml(item.title)}</td>
              <td><code>${escapeHtml(item.previous_state)}</code></td>
              <td><strong><code>${escapeHtml(item.recheck_state)}</code></strong></td>
              <td>${escapeHtml(item.explanation)}</td>
            </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </section>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="dark" />
  <meta name="description" content="HegoSentinel sanitized developer security assessment, evidence normalization, remediation guidance, and re-test report." />
  <link rel="canonical" href="https://demo.example.test/reports/${escapeHtml(safe.scan_id)}" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';" />
  <title>HegoSentinel Report — ${escapeHtml(safe.project_name)}</title>
  <style>
    :root { color-scheme: dark; --bg: #0b0d12; --card: #131720; --border: #252b3b; --text: #e6edf3; --muted: #9da7b3; --accent: #38bdf8; }
    body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }
    main { max-width: 1080px; margin: 0 auto; }
    h1, h2, h3 { margin-top: 0; text-wrap: balance; }
    p, dd, li { text-wrap: pretty; }
    .disclaimer { background: #1e2433; border-left: 4px solid var(--accent); padding: 0.85rem 1rem; margin-bottom: 1.5rem; font-size: 0.92rem; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
    .meta-box { background: var(--card); border: 1px solid var(--border); padding: 0.75rem; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; background: var(--card); }
    th, td { border: 1px solid var(--border); padding: 0.6rem 0.75rem; text-align: left; font-size: 0.9rem; }
    .finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
    .badges { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0 1rem; }
    .badge { background: #1f2937; border: 1px solid var(--border); padding: 0.2rem 0.55rem; border-radius: 4px; font-size: 0.8rem; }
    dl { display: grid; grid-template-columns: 180px 1fr; gap: 0.4rem 1rem; margin: 0; }
    dt { color: var(--muted); font-weight: 600; }
    dd { margin: 0; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86em; }
  </style>
</head>
<body>
  <main>
    <h1>HegoSentinel Developer Security Report</h1>
    <div class="disclaimer">${escapeHtml(safe.disclaimer)}</div>
    <div class="meta-grid">
      <div class="meta-box"><strong>Project:</strong><br/>${escapeHtml(safe.project_name)} (<code>${escapeHtml(safe.project_id)}</code>)</div>
      <div class="meta-box"><strong>Grant / Scope:</strong><br/><code>${escapeHtml(safe.grant_id)}</code> (v${safe.scope_version})</div>
      <div class="meta-box"><strong>Coverage Status:</strong><br/><code>${escapeHtml(safe.coverage.global_status.toUpperCase())}</code></div>
      <div class="meta-box"><strong>Requests Used:</strong><br/>${safe.coverage.request_count} / ${safe.coverage.max_request_budget}</div>
    </div>
    <section>
      <h2>1. Coverage Matrix</h2>
      <table>
        <thead>
          <tr><th>Rule ID</th><th>Version</th><th>Asset</th><th>Status</th><th>Details</th></tr>
        </thead>
        <tbody>${coverageRows}</tbody>
      </table>
    </section>
    <section>
      <h2>2. Findings (${safe.findings.length})</h2>
      ${findingCards}
    </section>
    ${recheckSection}
  </main>
</body>
</html>\n`;
}

/**
 * Exports OASIS SARIF 2.1.0 only for source/dependency findings with genuine file locations (S1-04).
 */
export function renderSarifReport(report: ScanReport): string {
  const safe = sanitizeReport(report);
  const sourceFindings = safe.findings.filter(
    (f) => f.rule_id === 'CODE-001' || f.rule_id === 'DEP-001'
  );

  const sarif = {
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'HegoSentinel',
            version: safe.scanner_version,
            informationUri: 'https://github.com/hegoweb/hegosentinel'
          }
        },
        results: sourceFindings.map((f) => {
          const [filePart, linePart] = f.asset_key.split(':');
          const startLine = linePart && /^\d+$/.test(linePart) ? Number.parseInt(linePart, 10) : 1;
          return {
            ruleId: f.rule_id,
            level: f.risk_priority === 'critical' || f.risk_priority === 'high' ? 'error' : 'warning',
            message: {
              text: `${f.title}: ${f.observed_condition} (${f.remediation.summary})`
            },
            fingerprints: {
              hegosentinelFingerprintV1: f.fingerprint
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: filePart
                  },
                  region: {
                    startLine
                  }
                }
              }
            ]
          };
        })
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

