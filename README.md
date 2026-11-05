# HegoSentinel

**Developer-first, self-hosted security assessment and remediation workflow.** Authorized scans → normalized evidence → remediation tasks → comparable re-test.

> [!WARNING]
> **Experimental / Alpha / Not Production Ready.** `v0.1.0-alpha.4` + unreleased Sprint 7–9 security hardening. Several controls are verified only on a single Windows host or only in-process; **real Linux Docker isolation (`WKR-001..005`) and real network-namespace isolation (`EGR-LINUX-NETNS-RUNTIME`) have NOT been verified yet**. Live remote scanning (`restricted-remote`) is intentionally disabled. See [Known limitations](#known-limitations), [PROJECT_STATUS.md](PROJECT_STATUS.md), and [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md).

## What actually works today

| Area | State | Plain-language summary |
| --- | --- | --- |
| Authorization & policy engine (`packages/policy-engine`) | **implemented · tested** | Scope grants with written permission, time windows, `GET`/`HEAD` only, wildcard/IP-literal rejection, SSRF IPv4/IPv6 classification, DNS-rebinding pinning, redirect validation. |
| Evidence pipeline (`packages/scanner-core`, `findings-schema`, `report-engine`, `recheck-engine`) | **implemented · tested** | Web observers (headers, cookies, TLS, redirects) on offline fixtures, 9-pass secret redaction, JSON/Markdown/HTML/SARIF 2.1.0 export, deterministic re-test (`verified_fixed` only with identical asset/grant/scope and positive proof). |
| Semgrep CE & Trivy adapters (`integrations/*`) | **implemented · tested** | `shell:false`, binary allowlist, timeouts, symlink/TOCTOU protection. **Real binaries verified on Windows 10 / Node 24.19.0 with Semgrep CE `1.183.0` and Trivy `0.76.1`** (SAST on synthetic Laravel/Next.js/Node targets, dependency CVEs, misconfigurations). **Not yet verified on Linux CI.** |
| Trusted Egress Broker (`apps/egress-broker`) | **implemented · tested in-process / loopback** | Deny-by-default policy, signed single-use short-lived grants, SSRF/rebinding/redirect drops, **outbound header allow-list, URL/secret masking before the first audit record, broker-side clock (a worker cannot back-date a grant)**. Network enforcement is **simulated**; it is **not wired** into the API and not proven to be the worker's only path out. |
| Platform API (`apps/api`) | **implemented (prototype) · tested** | A custom **PHP 8.2 service layer on SQLite** exposing 14 modules (auth, organizations/RBAC, projects, grants, scans, findings, tasks, re-test, notifications, emergency stop, audit). **It is not a Laravel application** (no framework is installed) and PostgreSQL, Redis and Horizon are **not used** (configuration files only). |
| Web UI (`apps/web`) | **implemented (prototype) · tested** | A dependency-free **Node HTTP server rendering an embedded HTML/JS single page** (9 screens, TR/EN). **It is not a Next.js build** — the `src/app/*.tsx` files are an unused skeleton. |
| `restricted-remote` live scanning | **blocked (by design)** | Fail-closed until independent network isolation is verified. |
| Real Docker worker isolation (`WKR-001/002/003/005`) | **unverified** | Argument builder and policy are tested; the live-container checks are `SKIP` because no Docker Engine was available. |
| Real Linux network-namespace isolation (`EGR-LINUX-NETNS-RUNTIME`) | **unverified** | Script exists; never executed. |
| GitHub Actions CI | **unverified** | Workflow exists; it has never run. |

Legend — **implemented**: code exists · **tested**: automated tests pass on the stated host · **simulated**: in-process model, no OS/kernel enforcement · **blocked**: intentionally disabled · **unverified**: artifacts exist but were never executed in the real environment · **planned**: not built.

## Security model of the platform API (Sprint 9)

* Identity comes **only** from a server-issued `Authorization: Bearer <session token>`. There is no header-based identity (the former `X-Demo-Principal` impersonation path was removed).
* Self-registration always creates a **new** organization owned by the caller; clients cannot choose organization or role.
* Server-side tenant/project/RBAC checks on every object access; audit trail readable only by `owner`/`security_lead`; a task can only become `verified_closed` through a verified re-test.
* Repository paths are confined to a workspace root and must belong to the project (no path traversal, no cross-project scanning).
* Failed-login throttling (5 failures / 15 min per account), project-wide emergency stop that holds new scans.
* **Demo mode** (known demo users and a known password) exists **only** when the operator sets `HEGOSENTINEL_DEMO_MODE=1`, and is hard-disabled when `APP_ENV=production`.

## Quickstart

Requires **Node.js 22.16+ / 24.x**. PHP 8.2+ is needed only for the platform API and its tests.

```bash
npm run lint
npm run typecheck
npm test                 # TypeScript suites (security, integration, e2e)
npm run test:api         # PHP API suites (36 module tests + 50 security regression tests)
npm run docs:links       # verifies relative Markdown links
npm run demo             # offline CLI demo
npm run verify:gates     # unified security gates (PASS / FAIL / SKIP)
npm run verify:release-gate   # exits BLOCKED while any gate is SKIP/FAIL (expected today)
```

### Run the demo platform locally

```powershell
# PowerShell
$env:HEGOSENTINEL_DEMO_MODE = "1"      # explicit, local-only opt-in
npm run start:api                      # http://127.0.0.1:8000
npm run start:web                      # http://127.0.0.1:3000
```

```bash
# bash
HEGOSENTINEL_DEMO_MODE=1 npm run start:api
HEGOSENTINEL_DEMO_MODE=1 npm run start:web
```

Without the variable both services start **empty and locked**: register an account through the UI/API, then sign in. Never set the variable on a reachable deployment.

Real Semgrep/Trivy runs expect the binaries on `PATH` or under `.tools/` (see `scripts/install-local-scanners.ps1`; `.tools/` is not committed).

## Known limitations

1. **No real Linux Docker/netns verification.** The five container checks and the netns/broker end-to-end check are `SKIP`; nothing in this repository claims they pass.
2. **The platform API is not Laravel and does not use PostgreSQL/Redis/Horizon.** SQLite + a database table stand in for them. Migrating is planned, not done.
3. **The web UI is not Next.js.** A real Next.js app is planned.
4. **Scans started by the API run as a host `node` subprocess**, not inside the worker container, and the API does not call the egress broker.
5. Domain-ownership proof and notification-domain verification are **recorded, not cryptographically verified** (no DNS challenge). E-mail "delivery" is a database record; there is no SMTP code.
6. Broker nonces, budgets and audit log live **in memory** (lost on restart); the audit log is hash-chained but not stored in append-only external storage.
7. No MFA enforcement (the flag is stored only); no password-reset confirmation endpoint.
8. No dedicated secret scanner (`gitleaks`) has been run; repository secret checks were pattern-based.
9. Not independently penetration-tested.

## Documentation

* [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) — independent public alpha security & release audit
* [GITHUB_RELEASE_PREPARATION.md](GITHUB_RELEASE_PREPARATION.md) — private/public GitHub release preparation, CI checklist & `v0.1.0-alpha.4` release notes
* [PROJECT_STATUS.md](PROJECT_STATUS.md) — module-by-module status with evidence
* [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md) — private / public-alpha / production decisions
* [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md) — findings, fixes, before/after proof
* [docs/ROADMAP.md](docs/ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)
* Historical audits and sprint briefs: [docs/archive/](docs/archive/)

## Safety policy

**No scanning of third-party assets without their owner's explicit authorization.** A domain ownership proof is not a substitute for a written testing authorization and scope. No brute force, denial-of-service, destructive checks, broad internet scanning, or uncontrolled active testing. See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Dependencies remain under their own licenses.
