# HegoSentinel — Next engineering sprint (after alpha.4)

**Goal:** Verified isolated scanner runner, without enabling unrestricted remote scans.

## Rules
- Treat README/ROADMAP alpha.4 code as the starting point; never rewrite the architecture from scratch.
- `restricted-remote` stays disabled until a real OS/container egress firewall is built, independently tested and an authorization scope is active.
- Implement security-sensitive work against deliberately controlled staging/fixtures, not third-party targets.
- Private customer source code is never committed or uploaded.

## Sprint 1 — containment (P0)
1. Create `apps/worker/` as a separate unprivileged scanner workload (not the API container) with no host Docker socket, no privileged mode, read-only root filesystem, CPU/memory/process/time limits and disabled default networking.
2. Add an explicit per-run network policy: deny private/loopback/link-local/metadata/internal planes; allow only written approved host+port; ensure DNS answers and actual connected peers are within the policy at each connection, including redirects.
3. Validate policy in integration tests using controlled DNS/HTTP/IPv6 fixtures and redirect/rebinding cases; demonstrate zero prohibited outbound connections in network namespace logs. Application-level allowlists alone are insufficient.
4. Introduce an explicit, independently attested worker capability. Never make a caller-provided boolean sufficient to authorize remote mode.
5. Ensure live requests have strict GET/HEAD limits, bounded body/time/retries and cancellation; keep dynamic payloads/active tests out of this sprint.

## Sprint 2 — scanner & evidence verification (P1)
1. Run installed pinned Semgrep CE and Trivy against intentionally safe local test repos under the worker sandbox, capturing version, exit, timeout, database freshness, rulepack, stdout/stderr limits and no script execution.
2. Expand CSP/cookie correctness fixtures (multiple CSP policies, browser enforcement caveats, duplicate attributes, Cookie prefixes, SameSite cases). Do not call a mere nonappearance `verified_fixed` without identity-specific positive evidence.
3. Perform negative tests for report leakage, HTML sanitization, JSON-Schema validation, coverage gaps and failure results. Add release-blocking CI tests and documented commands.

## Local Workbench hardening (P1)
- Limit POST request body size, reject malformed JSON with proper status codes, and restrict browser requests using explicit loopback Host and Origin checks.
- Move inline JavaScript/style to controlled assets and tighten CSP; run local-only browser regression tests.

## Sprint 3 — developer workflow (P2)
1. Only after G1/G2 security gates: Laravel API, org/project RBAC + PostgreSQL, auditable grant versions, isolated queues, cancellation and encrypted artifacts.
2. Next.js UI, scanned findings, developer remediation and human-approved notifications. Do not auto-post security weaknesses to public GitHub issues.

## Report required at completion
Return exact changed file list, real test log, scans executed, network isolation proof, known limitations and features not yet implemented. Do not claim production readiness or professional pentest certification.
