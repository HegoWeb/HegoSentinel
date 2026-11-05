# HegoSentinel — Antigravity IDE Continuation Brief (Code-First)

> Current repository: **implemented TypeScript alpha.3 local/offline vertical slice + independent audit hotfix working tree**. **DO NOT recreate the monorepo or overwrite existing modules.** This is NOT a production pentesting platform. Remote transport is intentionally disabled. Code audit on 2026-11-04: 26/26 current automated tests pass on Node.js 22.16.

## What to do first

1. Inspect `docs/SECURITY_AUDIT_2026-11-04.md`, `docs/ROADMAP.md`, `SECURITY.md`, current source modules, and `tests/security/independent-boundary-audit.test.ts`.
2. Run `npm ci --ignore-scripts`, `npm run lint`, `npm run typecheck`, `npm test`, `npm run demo` and report actual results. Do not claim pass without running.
3. Preserve the safeguards added in `AUD-2026-01` through `AUD-2026-05` (CSP comparable re-test, repository symlinks / inspection budget, scope-bound false-positive decisions, never enabling unimplemented remote mode).
4. Add adversarial and integration tests for next release gates without using third-party production targets.

## Immediate next engineering tasks (priority order)

### P0 — Enforced execution boundaries
- Design and demonstrate **separate OS/container-enforced** read-only worker isolation for local-source scans. No privileged mode, Docker socket, writable host mounts, unrestricted network or access to runtime secrets.
- Demonstrate worker filesystem access restrictions and resource budgets (CPU, memory, process lifetime, file count). Do not merely simulate a sandbox with boolean flags.
- Implement a bounded HTTP/TLS transport **only after** an independently testable egress firewall/proxy, exact destination scope, timeout, body caps, connection peer checks, redirect re-authorization and cancellation have test evidence. Until then keep `restricted-remote` fail-closed.

### P1 — Finding accuracy and tool validation
- Test Semgrep/Trivy with real pinned binaries and fixture repositories inside the worker. Distinguish unavailable scanner/database from a clean result; preserve version and vulnerability database freshness.
- Replace the project's limited hand-rolled JSON Schema keyword validator with a maintained, standards-conforming schema validator if full Draft 2020-12 compliance is advertised; validate emitted SARIF against official SARIF schema.
- Review CSP source expression semantics and account for report-only, redirect statuses, and divergent content types without claiming an exploit or verified fix.
- Define verification of authorization evidence, signed/immutable grant revisions, and safe operator approval.
- Update README and docs only for features independently demonstrated by executable tests.

### P2 — Self-hosted developer workflow
- After hardening CLI and workers, add Laravel multi-tenant API, Postgres RBAC/ownership, queue cancellation and encrypted artifacts; then Next.js dashboard, email (approved recipient), and explicit-private GitHub issue workflows.
- Controlled staging-only DAST/ZAP requires a second consent gate, health checks and instant kill switch. Never default to internet-wide scans.

## Completion / reporting criteria

Return a table of changed files, test output, denied/out-of-scope evidence, coverage limitations, and the features that remain disabled. Reject any proposal that equates `21/21` or `26/26` unit tests to a penetration-test certification. Never ingest client source code into external AI services without separate consent.
