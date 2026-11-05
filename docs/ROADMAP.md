# HegoSentinel — Engineering Roadmap v2.0 & Implementation Matrix

> **Current Release:** `v0.1.0-alpha.4` + Sprint 8/9 Security Hardening (`84` TypeScript Tests: `79 PASS`, `5 SKIP — NOT VERIFIED` on Windows host without Docker/Linux kernel, `0 FAIL`; `86` PHP API Assertions: `86 PASS`, `0 FAIL`; `32` Unified Security Gates: `27 PASS` including real `semgrep@1.183.0` & `trivy@0.76.1` binary execution, `5 SKIP — NOT VERIFIED` for Linux Docker/netns runtime, `0 FAIL`; Remote Network Socket Mode Fail-Closed).  
> **Revision:** 2026-11-05 · **Owner:** HegoWeb · **Target:** open-source, local-first security assessment and developer remediation workflow.  
> **Principle:** **No authorization → no scan; no safe egress → no remote scan; no evidence → no vulnerability claim.**

---

## 0. Current Implementation Status Matrix (`v0.1.0-alpha.4` + Sprint 9)

To ensure complete transparency between architectural goals and current executable code (`HS-AUDIT-003` / `HS-AUDIT-009` / Sprint 9 `B3`), the table below classifies every subsystem as **Implemented & Verified**, **Prototype Implemented & Tested**, **Mocked (Synthetic Fixture)**, or **Planned / Fail-Closed**:

| Subsystem / Capability | Status in `v0.1.0-alpha.4` (Sprint 9) | Implementation & Verification Reference |
| --- | --- | --- |
| **Scope Authorization & Written Permission Gate (`S0-01`)** | **Implemented & Verified** | [`packages/policy-engine/src/index.ts`](../packages/policy-engine/src/index.ts) (`SEC-001`) |
| **SSRF IPv4/IPv6 Classification, DNS Pinning & Socket Peer Verification (`S0-02`)** | **Implemented & Verified** | [`packages/policy-engine/src/index.ts`](../packages/policy-engine/src/index.ts) (`SEC-002`, `SEC-003`, `SEC-004`) |
| **Trusted Egress Broker (`EGR-001..006` + Sprint 9 `B2` Hardening)** | **Implemented & Verified (User-Space / HTTP Daemon)** | [`apps/egress-broker/src/index.ts`](../apps/egress-broker/src/index.ts), [`tests/security/broker-b2-regression.test.ts`](../tests/security/broker-b2-regression.test.ts) |
| **Web Observers (`WEB-TLS-001`, `WEB-HEADER-001`, `WEB-COOKIE-001`, `WEB-REDIRECT-001`)** | **Implemented (Evaluated on Offline Fixtures)** | [`packages/scanner-core/src/index.ts`](../packages/scanner-core/src/index.ts) (`S1-01`, `HSR-04`) |
| **Live Outbound HTTP/TLS Network Socket Fetching (`restricted-remote`)** | **Fail-Closed / Blocked** | Denied by [`verifyRemoteEgressSandboxGate`](../packages/policy-engine/src/index.ts) (`SEC-005`) until Linux netns + container egress firewall attestation is verified |
| **Local Semgrep (`CODE-001`) & Trivy (`DEP-001`) Subprocess Adapters (`S1-02`)** | **Implemented & Verified (`semgrep 1.183.0` + `trivy 0.76.1`)** | [`integrations/semgrep/src/index.ts`](../integrations/semgrep/src/index.ts), [`integrations/trivy/src/index.ts`](../integrations/trivy/src/index.ts) (`SEC-006`, `HS-AUDIT-002`) |
| **Docker Worker (`WKR-001..005`) & Linux Network Namespace Isolation** | **Verified on Ubuntu 24.04 CI (`PASS`) / `SKIP` on Windows Host** | [`apps/worker/src/index.ts`](../apps/worker/src/index.ts), [`scripts/linux-docker-verify.sh`](../scripts/linux-docker-verify.sh), [`scripts/linux-netns-egress-verify.sh`](../scripts/linux-netns-egress-verify.sh) — verified on GitHub Actions `ubuntu-24.04` (`WKR-001..005` & `EGR-LINUX-NETNS-RUNTIME`) |
| **Collection Minimization & Multi-Pass Secret Redaction (`S1-04`)** | **Implemented & Verified** | [`packages/report-engine/src/index.ts`](../packages/report-engine/src/index.ts) (`SEC-007`) |
| **JSON, Markdown, Offline HTML & OASIS SARIF 2.1.0 Exporters + Runtime Validators** | **Implemented & Verified** | [`packages/report-engine/src/index.ts`](../packages/report-engine/src/index.ts), [`packages/findings-schema/src/index.ts`](../packages/findings-schema/src/index.ts) (`HS-AUDIT-008`) |
| **Deterministic Re-Test Engine (`S1-05`) with Per-Asset & Grant Equivalence** | **Implemented & Verified** | [`packages/recheck-engine/src/index.ts`](../packages/recheck-engine/src/index.ts) (`SEC-009`, `SEC-010`, `HS-AUDIT-001`, `HS-AUDIT-004`, `HS-AUDIT-007`) |
| **REST Backend (`apps/api`) & Multi-Page Web UI (`apps/web`)** | **Prototype Implemented & Tested (`86` PHP assertions + E2E)** | Custom PHP 8.4 + SQLite API ([`apps/api`](../apps/api)) and Node.js `node:http` SSR UI ([`apps/web`](../apps/web)), hardened in Sprint 9 (`B1`, `S9-01..11`) |
| **Full Laravel 11 Framework, PostgreSQL, Redis, Horizon & Next.js App Router (`Stage 2`)** | **Planned (Not Implemented)** | Current `apps/api` and `apps/web` are lightweight zero-dependency prototypes |
| **ZAP Automation & Controlled Staging DAST (`Stage 3 / v0.3`)** | **Planned (Not Implemented)** | Deferred to Stage 3 (`G3`) |

---

## 1. Executive decision

HegoSentinel is **not** a generic autonomous penetration-testing product. It is a developer-first platform connecting **authorized security observations → reproducible evidence → contextual remediation → re-test**. Its first release uses deterministic, non-destructive checks. Full dynamic application testing is a later, independently gated capability.

**Differentiator — Evidence-to-Fix Loop:** every finding carries the responsible component, observation method, confidence, limitations, fix guidance for its framework, reviewer decision and comparable re-test status. Scanner integrations are replaceable; the workflow and evidence model are the product.

### 1.1 Changes from the original plan

| Original assumption | Revised engineering decision | Why |
|---|---|---|
| “Passive” includes direct HTTP/TLS requests | Call these **non-invasive web checks**; reserve “passive analysis” for already captured traffic | HTTP/TLS still generates requests to an asset |
| URL allowlist is sufficient for SSRF | Validate input, DNS and actual network destination; deny internal egress in a separate sandbox | Redirects and DNS rebinds can bypass application checks |
| All issues have a severity and are confirmed by scanner | Model **observation, risk, confidence and verification** separately | Missing header ≠ proven exploit |
| Not seen in re-test = fixed | Distinguish **no_longer_observed** from **verified_fixed** | Target coverage or scanner version may have changed |
| CLI, platform, PDF, email and DAST in one sprint | Deliver safe demo → local CLI → integrations → platform → controlled DAST | Scope control; demonstrable quality |
| Tenant support deferred to UI | Enforce ownership/isolation in data structures and API from the outset | Prevent cross-project leakage when platform arrives |
| Third-party scanners run as ordinary subprocesses | Process allowlist, timeouts, resource limits, physical `realpathSync` validation, isolated worker | Repositories and tool output are untrusted |
| AI explanations are part of the main pipeline | Deterministic findings first; optional local AI after redaction + human review | Accuracy and privacy |

## 2. Stage 0 — Security foundations / Sprint 0 (Completed for Offline/Local Mode)

### S0-01. Scope and authorization policy [P0]
- [x] Define JSON Schema for owner, approved asset hostname(s), scheme, port, precise path boundary, testing time window, permitted checks, authorization record and emergency stop contact.
- [x] Reject wildcards and unspecified destinations in v0.1; reject expired, ambiguous or malformed scope records.
- [x] Treat domain ownership proof and written permission as different evidence; keep consent receipt and scope version.
- [x] Build one explicit `local-demo` profile locked to `demo.example.test`.
- [x] Record when/why a check was skipped (`unauthorized`, `scope_expired`, `blocked_destination`, `outside_window`).

### S0-02. SSRF and network containment [P0]
- [x] Parse URLs canonically; restrict to HTTP/HTTPS; reject embedded credentials, non-approved ports, IP literals by default, confusing encodings.
- [x] Resolve A/AAAA and validate each candidate address; pin selected destination per connection; verify socket peer.
- [x] Block non-global/reserved IPv4 and IPv6, cloud metadata, internal DNS and rebinding destinations via policy.
- [x] Enforce fail-closed `verifyRemoteEgressSandboxGate` so remote scanning cannot run without OS/container egress firewall attestation.

### S0-03. Reproducible demo and CI [P0]
- [x] Create synthetic fixture endpoints with missing/present headers and cookie attributes; no real third-party systems.
- [x] Add unit tests, real TypeScript `tsc --noEmit` typecheck, lint, security matrix (`SEC-001`..`SEC-014`), and audit regression suite (`HS-AUDIT-001`..`HS-AUDIT-008`).

## 3. Stage 1 — v0.1 Core CLI and Evidence-to-Fix loop

### S1-01. Safe web observation engine [P0]
- [x] `WEB-TLS-001`, `WEB-HEADER-001`, `WEB-COOKIE-001`, `WEB-REDIRECT-001` implemented and verified against offline fixtures.
- [ ] Live outbound HTTP/TLS socket client behind container egress firewall (planned for Stage 1.1 / Stage 2 worker).

### S1-02. Local static analysis and dependency adapters [P1]
- [x] `CODE-001` (Semgrep CE) and `DEP-001` (Trivy) subprocess adapters with `shell: false`, binary allowlist, and physical `realpathSync`/`lstatSync` symlink escape protection (`HS-AUDIT-002`).
- [ ] Containerized read-only filesystem sandbox for untrusted repository execution.

### S1-03 & S1-04. Findings schema, redaction, and report engine [P0]
- [x] Versioned `ScanReport`, `RecheckComparisonReport`, and `SarifReport` schemas + runtime validators (`HS-AUDIT-008`).
- [x] Collection minimization (cookie values discarded at parse time) + 9-pass secret redaction (`SEC-007`).

### S1-05. Re-test and remediation [P0]
- [x] Strict equivalence matching across `organization_id`, `project_id`, `grant_id`, `scope_version`, `profile`, `rule_id`, `rule_version`, and exact `asset_key` (`HS-AUDIT-001`, `HS-AUDIT-004`, `HS-AUDIT-007`).
- [x] Framework-specific remediation guides for `laravel`, `nextjs`, and `generic-web`.

## 3.1 alpha.4 — Independent correctness gate (verified locally)

- [x] `AUD-06-A`: Per-cookie positive fix proof is tied to the original finding fingerprint. Another safe cookie cannot automatically resolve the baseline finding.
- [x] `AUD-06-B`: `SameSite` only accepts `Lax` / `Strict` / `None` for a valid attribute; invalid values remain reportable.
- [x] `AUD-06-C`: Duplicate CSP directives and a permissive `script-src-elem` override cannot yield `verified_fixed`.
- [x] Runtime report schema includes optional, identity-bound `positive_validation_fingerprints` evidence; older reports remain readable but without per-cookie proof cannot claim verified remediation.
- [x] **Sprint 7 — Real Security Verification & Full Integration:**
  - `WKR-001..005`: Added `analyzeDockerRunOutcome` (rejecting Docker CLI exit codes `125`/`126`/`127` so failed commands are never interpreted as security passes) and `scripts/linux-docker-verify.sh` on `ubuntu-24.04`.
  - `CODE-001` & `DEP-001`: Added synthetic Laravel, Next.js, and Node.js targets (`examples/synthetic-targets/`), local Semgrep ruleset (`semgrep-rules.yml`), Trivy misconfiguration + lockfile normalization, `scripts/install-local-scanners.ps1` (verified locally with real `semgrep@1.183.0` finding 6 SAST issues and `trivy@0.76.1` finding 61 dependency issues), and `scripts/linux-scanner-verify.sh` on `ubuntu-24.04`.
  - `EGR-001..006`: Completed out-of-worker `TrustedEgressBroker` + `createTrustedEgressBrokerServer` HTTP daemon (`apps/egress-broker/`) and `scripts/linux-netns-egress-verify.sh` on an isolated Docker `--internal` network.
  - `SEC-001..014` & Production Hardening: Added `authorizeReportTenantAccess`, `TamperEvidentAuditLog`, extended `redactSensitiveText` (PEM private keys, DB URIs, `APP_KEY`, `NEXTAUTH_SECRET`), `validateSafeReportOutputPath`, `scripts/verify-all-security-gates.ts`, and `scripts/release-gate-check.ts` (`npm run verify:release-gate`).
  - 64 automated tests (`59 PASS`, `5 SKIP — NOT VERIFIED` on Windows host without Docker/Linux kernel, `0 FAIL`).

**Remaining release blockers (do not unlock remote scanning):**

1. **P0 / Network containment:** implement a dedicated sandboxed runner with OS/firewall-enforced outbound restrictions, DNS/connected-peer checks, scope authorization revalidation at request time and adversarial network tests. Keep `restricted-remote` disabled until verified.
2. **P0 / Filesystem containment:** run untrusted Semgrep/Trivy scans in separate non-root read-only filesystem isolation; check symbolic links and mount escape under actual scanner execution. No untrusted build/package-manager hooks.
3. **P1 / Evidence quality:** full CSP semantics and browser-version differences cannot be certified by a small deterministic observer. Treat rule conclusions as limited observations; validate via safe staging fixtures and independent review.
4. **P1 / Integration:** test pinned installed Semgrep/Trivy binaries and vulnerability-database freshness on deliberate local fixtures. Current adapter tests alone do not establish full installed-tool compatibility.
5. **P1 / Reports:** test schema migration compatibility, unsafe inputs for exporters, report storage encryption and retention when a multi-user backend arrives.
6. **P1 / Local Workbench security:** bound JSON POST payload sizes, validate Host/Origin for loopback service and remove unsafe-inline CSP when UI assets are split.
7. **P2 / Product:** Laravel API + PostgreSQL tenant isolation, worker cancellation and rate limits, Next.js UI, owner-approved delivery, then human-gated staging-only ZAP.

## 4. Stage 2 — v0.2 Team platform (Planned)

- [ ] `S2-01`: Laravel API / PostgreSQL / multi-tenancy (`organizations`, `projects`, `authorization_grants`, RBAC).
- [ ] `S2-02`: Queue/worker control plane with container network egress firewall.
- [ ] `S2-03`: Next.js developer interface.
- [ ] `S2-04`: Owner-approved SMTP/webhook notifications and CI integration.

## 5. Stage 3 — v0.3 Controlled dynamic validation (Planned after G2)

- [ ] `ZAP-PASSIVE-001` & `DAST-CONTROLLED-001` staging-only workflows with kill switch.

---

## 6. Sprint 10 — Transition to Full Production-Grade Architecture (Post-Public-Alpha `v0.1.0-alpha.4`)

Following the `v0.1.0-alpha.4` Public Alpha release, Sprint 10 transitions `apps/api`, `apps/web`, and `apps/worker` from lightweight zero-dependency local prototypes into a containerized, multi-tenant production stack **while preserving the verified TypeScript security core (`packages/*`, `integrations/*`, `apps/egress-broker`) and keeping `restricted-remote` disabled until all Sprint 10 production gates pass**:

| Workstream | Current State (`v0.1.0-alpha.4`) | Sprint 10 Target Architecture | Mandatory Security Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| **1. `S10-01` — Real Laravel 11 API & Sanctum Auth (`apps/api`)** | Custom zero-dependency PHP 8.2+ router + `SecurityPlatformService.php` (`PROTOTYPE`) | Real **Laravel 11** application (`vendor/`, Eloquent ORM, FormRequest validation, Sanctum token/cookie auth, strict rate-limiting middleware, Policy/Gate classes) | All 50 Sprint 9 `B1` regression tests (`run-security-regression-tests.php`) must pass against the real Laravel 11 HTTP kernel with zero client-header identity trust (`X-Demo-Principal` permanently banned). |
| **2. `S10-02` — PostgreSQL 16 + Row-Level Security (RLS)** | Local file-backed SQLite PDO (`apps/api/database/*.sqlite`) | **PostgreSQL 16** with explicit `organization_id` foreign keys, database migrations, and enforced PostgreSQL **Row-Level Security (`ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`)** bound to `app.current_organization_id` per transaction | Cross-tenant read/write attempts must fail at BOTH the Laravel Policy layer AND the PostgreSQL RLS layer (`SEC-011` database-level proof). |
| **3. `S10-03` — Asynchronous Redis + Laravel Horizon Queue Plane** | Synchronous `proc_open` execution inside `ExecuteAuthorizedScanJob.php`; `artisan horizon` is a stub | Real **Redis 7 + Laravel Horizon** supervisor pools (`hegosentinel-scans`, `hegosentinel-rechecks`, `hegosentinel-notifications`) with job retries, timeouts, and real-time job state transitions (`queued` -> `running` -> `completed`/`failed`/`cancelled`) | Emergency Stop (`POST /api/v1/emergency-stop`) must immediately revoke queued Redis jobs and dispatch `SIGTERM -> SIGKILL` to active worker containers within `< 2s` (`SEC-012`). |
| **4. `S10-04` — Ephemeral Containerized Worker Dispatch (`apps/worker`)** | `ExecuteAuthorizedScanJob` runs `scripts/api-worker-bridge.ts` as a host subprocess | Worker supervisor launches ephemeral, single-run **Docker containers** (`hegosentinel-worker` with `--user=65532:65532`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `seccomp-profile.json`, `--network=none` for `source-offline`) | Host filesystem is never exposed except the single read-only target mount (`/workspace/target-repo:ro`) and bounded `tmpfs` scratch (`WKR-001..005` enforced on every scan job). |
| **5. `S10-05` — Real Next.js 15 App Router Frontend (`apps/web`)** | Custom Node.js `node:http` SSR + vanilla JS SPA (`apps/web/src/server.ts`) | Real **Next.js 15 App Router + React 19 + TypeScript** application with server components, strict CSP nonces (eliminating `unsafe-inline`), typed API client, and real-time scan/recheck status polling | Zero `unsafe-inline` in production `Content-Security-Policy`; explicit visual badges distinguishing `real_scan` vs `demo_seed`; full Playwright E2E coverage across all 9 workflows. |
| **6. `S10-06` — Live Remote Scanning (`restricted-remote`) Gate** | **Strictly Disabled / Fail-Closed (`SEC-005`)** | Remains **DISABLED (`fail-closed`)** by default throughout Sprint 10 development; may only be evaluated in an isolated staging environment after `S10-01..S10-05`, cryptographic worker attestation, and Linux netns + `TrustedEgressBroker` enforcement are independently audited | `executeScan({ mode: 'restricted-remote' })` continues to fail closed unless signed supervisor capability attestation and isolated broker network namespace are cryptographically verified. |

