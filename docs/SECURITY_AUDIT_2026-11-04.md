# HegoSentinel alpha.3 — Independent Code Audit and Implementation Plan

**Date:** 2026-11-04  
**Baseline:** user-supplied `HegoSentinel_Project_Documentation (4).zip` (`0.1.0-alpha.3`)  
**Output:** patched local working tree (not an upstream release/tag)  
**Review scope:** source review, offline synthetic negative tests, Node.js 22.16 lint, TypeScript compiler, unit/security/integration/E2E tests and synthetic demo. No live external target testing, independent container penetration test, or installed Semgrep/Trivy binary integration verification.

## Executive verdict

The project has working TypeScript packages, a local Workbench, synthetic web checks, optional local scanner adapters, report export and a deterministic re-test prototype. The baseline's own 21 automated tests passed, but additional adversarial test cases demonstrated **four independent trust/correctness failures** and an unbounded repository inspection risk. All five new test cases now pass after fixes (26 total tests). It remains an **alpha local/offline security-assessment workflow**, not a certified penetration test or remote scanning platform.

## Baseline feature inventory (source verified; operating claims carefully scoped)

| Component | Code present | Exercised here | Production ready? |
|---|---|---|---|
| Authorization, URL and simulated DNS/peer safety policy | Yes | Unit/security tests | No, owner authorization evidence is not independently verified |
| HTTP header / CSP / cookie / TLS / redirect observers | Yes | Synthetic fixture demo | No real network response data |
| Local Semgrep and Trivy adapters | Yes | Mocked fixture tests | Real pinned scanner binaries not tested here; no OS sandbox |
| Sanitized JSON/Markdown/HTML/SARIF exports | Yes | Offline tests | External schema conformance audit not performed |
| Re-test / suppression / comparability | Yes | Unit and added adversarial tests | More semantic/coverage tests needed |
| Local web Workbench | Yes | Source reviewed, not browser E2E tested in this audit | Not a Next.js multi-user dashboard |
| True isolated remote HTTP/TLS worker | No | Fail-closed tested | **Disabled** |
| Laravel API, Postgres, RBAC, notification, ZAP | No | No | Planned only |

## Independent negative findings and completed code patches

### AUD-2026-01 — P0: Invalid `verified_fixed` after endpoint response changed

- **Proof before patch:** baseline `GET /` served HTML without CSP; current `GET /` returned JSON without CSP. The WEB-HEADER-001 observer marked the non-HTML check `positive_validation_passed: true`; re-test emitted `verified_fixed` even though the original HTML document was not retested.
- A current 404 response with an enforcing CSP header also did not prove remediation of the original successful HTML page.
- **Fix:** `scanner-core` records `not_applicable` reason and `positive_validation_passed: false` for non-HTML or non-2xx header observations. `recheck-engine` marks these cases `not_comparable` instead of claiming a verified fix.
- **Evidence:** `tests/security/independent-boundary-audit.test.ts`, `AUD-2026-01` (tests both cases).

### AUD-2026-02 — P1: Unchecked symlinks inside `node_modules`

- **Proof before patch:** `validateAuthorizedRepositoryPath(approvedRoot)` returned `allowed: true` despite a symlink under `approvedRoot/node_modules/` targeting an outside directory. This demonstrates a policy-preflight gap, **not** proof that an installed scanner followed the link to read the outside file.
- **Fix:** removed the special-case bypass. Inspect symlink boundaries in `node_modules` as well, failing closed on escapes. Added a 25,000-entry bound to prevent endless/unbounded policy inspection (`AUD-2026-04`).
- **Caveat:** large projects may now be rejected until a purpose-built read-only sandbox and explicit scanner exclusion policy replace recursive full-tree preflight. This must be tested with npm/pnpm/yarn real-world fixtures.

### AUD-2026-03 — P1: Stale false-positive suppression accepted

- **Proof before patch:** a suppression record with a different `scope_version` marked a still-present WEB-HEADER-001 finding as `false_positive`.
- **Fix:** reviewer suppression must match the current `scope_version` as well as fingerprint, tenant, project, expiry and reviewed reason.
- **Evidence:** `AUD-2026-03` regression test.

### AUD-2026-05 — P0: Self-asserted sandbox flags enabled an unimplemented remote mode

- **Proof before patch:** `executeScan({mode:'restricted-remote', egressAttestation:{sandboxActive:true,...}})` returned `policyDecision.allowed: true` for fixture-backed data although no real egress or HTTP transport was implemented. This is a false capability/attestation signal; not proof of live network access.
- **Fix:** `restricted-remote` always fails closed in this alpha, including when user-provided attestation flags are true. It can only be enabled in a future implementation with separately testable OS-enforced egress controls and real bounded transport.
- **Evidence:** `AUD-2026-05` regression test.

## Verification

| Check | Original ZIP | Patched working tree |
|---|---:|---:|
| `npm run lint` | PASS | PASS |
| `npm run typecheck` | PASS | PASS |
| `npm test` | **21/21** | **26/26** |
| `npm run demo` | PASS (synthetic only) | PASS (synthetic only) |
| New adversarial tests | 4 failures across 5 cases (1 budget case introduced with fix) | All pass |

The tests were run on Node.js v22.16.0. Node.js 24 compatibility and CI in GitHub-hosted runners were not independently tested.

## Still open: next work prioritized by release gates

### G0/G1 security boundaries — P0 before enabling any new remote feature
1. Create real isolated scanner workers: non-root, read-only repository mount, no Docker socket, bounded CPU/memory/time, no access to the API/database/host secrets. Prove the restrictions with adversarial fixtures.
2. Build egress-denied-by-default network namespace/proxy/firewall, verifiable outside caller-controlled booleans. Test DNS rebind, redirects, network peer addresses, cancellation, rate and response size limits.
3. Use exact, short-lived, signed owner authorization and grants with human approval. A mere `written_permission_ref` string is not independently authenticated consent.
4. Keep `restricted-remote` completely disabled until the above are independently tested. No real customer or arbitrary remote-target scan in this current alpha.

### G1 correctness and interoperability — P1
5. Execute local Semgrep/Trivy pinned **real binaries** against safe test repositories inside the worker; check exit codes, database freshness, license/telemetry and negative examples.
6. Validate SARIF and JSON Schema against maintained standard validators if advertising full compliance. Current in-house implementation only supports a subset of Draft 2020-12 keywords used by its bundled schemas.
7. Expand CSP/cookie/TLS rule tests around statuses, content types, report-only policies, redirects, duplicated headers, missing certificates and trust context. Never represent an observation as exploit confirmation.
8. Add deterministic re-test comparisons for changes in coverage/rules/scan profile and source vulnerability database versions. Treat incomplete checks as incomplete, not clean.
9. Add performance budgets / exclude policies for large node_modules trees without weakening symlink containment.
10. Add CI with `npm ci --ignore-scripts`, code coverage, test artifacts and independent threat-case reviews; verify releases on Node 22.16 and 24.

### G2/G3 product milestones — P2 once isolated CLI is stable
11. Laravel + PostgreSQL ownership/RBAC/project/scope/event store; separate workers, queue cancellation, encrypted evidence, tenant tests.
12. Next.js developer UI, findings triage, security guidance, verified recipients and approved issue/email routing.
13. Separate staging-only DAST/ZAP activation with second signed authorization, health budgets and emergency stop; manual validation before high-impact conclusions.

## Files updated

- `packages/scanner-core/src/index.ts`: non-HTML/status semantics; enforced alpha remote-denial.
- `packages/recheck-engine/src/index.ts`: non-applicability and scope-matched false positive logic.
- `integrations/semgrep/src/index.ts`: symlink path policy including node_modules, maxEntries fail-closed.
- `tests/security/independent-boundary-audit.test.ts`: 5 new executable negative/regression cases.
- `package.json`: include the new test group in security/all tests.
- `.github/workflows/ci.yml`: deterministic `npm ci --ignore-scripts` install.
- `packages/findings-schema/src/index.ts`: precise comments about supported JSON Schema keyword subset.
- `README.md`, `README.tr.md`, `docs/ROADMAP.md`, `roadmap.md`, `CHANGELOG.md`, `AGENT_IMPLEMENTATION_BRIEF.md`, `CONTRIBUTING.md`, `.gitignore`: accuracy, version and work-continuation improvements.

**Release conclusion:** Suitable for public open-source development with an accurate alpha label, synthetic examples and strong safety disclaimers. Not suitable for unattended customer scans or a production pentest product.
