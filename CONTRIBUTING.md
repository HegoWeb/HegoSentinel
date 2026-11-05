# Contributing to HegoSentinel

> **Status: Experimental / Alpha / Not Production Ready (`v0.1.0-alpha.4`)**

HegoSentinel provides an open-source, local-first TypeScript security assessment CLI, policy engine, report generator, deterministic re-test workflow, an out-of-worker Trusted Egress Broker (`apps/egress-broker`), and working prototypes of the REST API (`apps/api`, custom PHP 8.2+ / SQLite) and Web UI (`apps/web`, custom Node.js `node:http` SSR). Production remote scanning (`restricted-remote`) and active penetration testing are **intentionally disabled (fail-closed)**.

## Local development

Use Node.js 22.16+ or Node.js 24 (plus PHP 8.2+ with `pdo_sqlite` for `apps/api`) and install toolchain dependencies with `npm ci --ignore-scripts`.

```bash
npm run lint
npm run typecheck
npm run docs:links
npm test
npm run test:api
npm run demo
npm run verify:gates
```

Only the **offline synthetic demo** and authorized local repository checks run by default. Optional local Semgrep CE (`1.183.0`) and Trivy (`0.76.1`) integrations require their pinned binaries; missing binaries or unavailable Docker Engine must always produce `SKIP (not verified)` or `completed_with_gaps`, never a false `PASS`.

## Safe contribution principles

- Work only with synthetic or explicitly authorized targets and sanitized test fixtures.
- Do not introduce default production scanning, broad crawling, brute force, exploit execution, code execution via scanned repositories or secret disclosure.
- Never allow client-supplied HTTP headers (such as the removed `X-Demo-Principal`) to determine user or tenant identity.
- Add at least one positive and one negative regression test for every security boundary or detection rule.
- Keep `restricted-remote` denied until independently verified OS-level network namespace isolation and bounded broker transport are verified in CI.
- Document confidence, validation criteria, known false positives and re-test incomparability.
- Keep third-party scanner licenses and notices intact. No client sources, credentials, personal data, or private URLs in PRs.

## Pull request checklist

- [ ] Scope and behavior documented (with honest `IMPLEMENTED` / `PROTOTYPE` / `SIMULATED` / `SKIP` / `PLANNED` labels)
- [ ] Security regression tests included (`tests/security/*` and/or `apps/api/tests/run-security-regression-tests.php`)
- [ ] `npm run lint`, `npm run typecheck`, `npm run docs:links`, `npm test`, `npm run test:api`, and `npm run demo` passed
- [ ] No unapproved network behavior or unmasked evidence in logs/reports
- [ ] Fail-closed denial paths tested
- [ ] Roadmap and README updated to match actual capabilities

For the latest independent security and release audits, see [FINAL_RELEASE_AUDIT.md](FINAL_RELEASE_AUDIT.md) and [docs/security/SPRINT9_SECURITY_REAUDIT.md](docs/security/SPRINT9_SECURITY_REAUDIT.md).
