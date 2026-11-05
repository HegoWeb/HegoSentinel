# Reference Architecture

> Proposed design, not a running system.

## MVP: local-first

```
Authorized config + approved target/repository
                   |
             Scan CLI / Worker
                   |
     +-------------+-------------+
     |             |             |
 Passive HTTP   SAST adapter  SCA adapter
 checks         (Semgrep CE)  (Trivy)
     |             |             |
     +-------------+-------------+
                   |
          Normalization pipeline
                   |
       Confidence + deduplication
                   |
     JSON + Markdown/HTML reports
                   |
         Optional local re-test
```

For v0.1, a CLI-first implementation minimizes deployment complexity and allows an open-source contributor to run a demo on a laptop.

## Full platform (future)

- **Web UI:** Next.js + TypeScript, accessible project and finding views.
- **API:** Laravel + PHP, project management, scope approvals, report retrieval, auth/RBAC.
- **Database:** PostgreSQL for projects, scans, findings, status history, approvals, and audit logs.
- **Queue:** Redis and Laravel Horizon to schedule controlled jobs.
- **Workers:** Isolated, unprivileged containers with resource caps, read-only root filesystem where possible, and no host Docker socket.
- **Storage:** Encrypted private object storage for sanitized report artifacts; short retention by default.
- **Adapters:** HTTP checks, Semgrep CE, Trivy, and later ZAP Automation Framework.
- **Integrations:** Opt-in SMTP, GitHub Issues, or generic signed webhooks; least-privilege credentials.

```
Next.js UI --> Laravel API --> PostgreSQL
                  |
               Redis Queue
                  |
         Isolated Scan Workers
          /        |        \
      Web checks  SAST      SCA     [ZAP later]
          \        |        /
             Findings API
                  |
          Report + Re-test
                  |
         Approved notifications
```

## Proposed entities

- `projects`: id, owner_id, name, stack, created_at
- `authorized_scopes`: project_id, target, scope_type, verification_method, approval_id, expires_at
- `approvals`: owner, authorization_statement, allowed_tests, time_window, terms_ack_at
- `scans`: id, project_id, profile, status, started_at, finished_at
- `scan_runs`: scan_id, adapter, version, execution_status
- `findings`: id, project_id, rule_id, asset, severity, confidence, verification_status, first_seen, last_seen
- `finding_evidence`: finding_id, sanitized_summary, reference, encrypted_artifact_ref
- `remediations`: finding_id, title, steps, references, framework_tag
- `notifications`: scan_id, channel, recipient, authorized_by, status
- `audit_events`: actor, action, project_id, occurred_at

## Proposed finding schema

```json
{
  "id": "HS-0001",
  "rule_id": "WEB-HEADER-001",
  "title": "Missing Content-Security-Policy header",
  "asset": "https://demo.example.test/",
  "severity": "medium",
  "confidence": "high",
  "verification_status": "observed",
  "evidence": "Response header not observed on tested endpoint",
  "impact": "Browser-side content restrictions may be weaker",
  "remediation": "Define and test a suitable Content-Security-Policy for the application",
  "validation": "Re-run the header check and validate the policy against the app",
  "references": ["https://owasp.org/www-project-secure-headers/"]
}
```

Example is synthetic, and a missing header alone is not proof of exploitable XSS.

## Security boundaries

1. Written authorization plus explicit allowlist precede every remote scan.
2. Server-side URL validation prevents SSRF; reject internal/cloud metadata IP ranges and revalidate DNS/IP and every redirect. Use egress network isolation as a second defense.
3. Conservative timeouts, rate limits, concurrency caps, and controlled scan windows.
4. Default passive-only remote checks; active tests require separate permission, scoped staging, and safeguards in a later release.
5. Separate worker identities and short-lived credentials; no cross-tenant credentials or accessible secrets in logs.
6. Stop jobs that drift outside scope, fail target validation, or exceed resource limits.
7. Restrict artifacts to project members, redact sensitive evidence, and enforce defined retention/deletion policies.

## Suggested repo layout

```
hegosentinel/
  README.md
  README.tr.md
  LICENSE
  SECURITY.md
  CONTRIBUTING.md
  docs/
    PRODUCT_REQUIREMENTS.md
    ARCHITECTURE.md
    TEST_CATALOG.md
    REPORT_SAMPLE.md
    ROADMAP.md
  apps/
    api/              # Laravel (future)
    web/              # Next.js (future)
  packages/
    scanner-core/     # local-first checks and normalization
    report-engine/    # sanitized exports
  integrations/
    semgrep/          # scanner adapter (future)
    trivy/            # scanner adapter (future)
    zap/              # controlled dynamic scanning (future)
  examples/
    safe-demo/        # intentionally controlled demo fixture
  tests/
```
