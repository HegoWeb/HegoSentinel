# HegoSentinel — Independent-Style Architecture & Threat Review

**Review date:** 2026-11-04  
**Inputs:** provided Antigravity IDE roadmap screenshots and pasted sections; earlier proposed README, ARCHITECTURE, PRODUCT_REQUIREMENTS, TEST_CATALOG and SECURITY documentation.  
**Limit:** **design review, NOT a source-code audit, runtime penetration test, reverse engineering of binaries, or independent security certification.** No application implementation or network behavior was available to verify.

## 1. Summary verdict

**Design maturity:** promising concept / pre-implementation. **Production security readiness:** NOT demonstrated. **Recommendation:** proceed with a scope-restricted CLI demo **only after Gate G0**, then deliver a trustworthy finding/evidence model before pursuing a web dashboard or active DAST.

**What is good:** local-first orientation; explicit authorization, defensive SSRF intentions, known scanner adapters, clear separate static/dynamic stages, redaction, human-controlled notifications and a re-test loop. These are valuable foundations.

**What changes the outcome:** implementation details of egress isolation, scanner process sandbox, evidence correctness, coverage semantics and per-tenant boundaries. In a scanning service, these details are security controls, not secondary enhancements.

## 2. Findings (prioritized)

### HSR-01 · Critical · Remote-scan network boundary is underspecified

- **Condition:** application allowlist + DNS validation is a useful first line, but not complete network isolation. IPv6, DNS rebinding, redirects, alternate address formats, system proxies and actual peer-IP selection could bypass an application-only check.
- **Failure mode:** user-influenced URL causes server-side calls to cloud metadata, RFC1918 services or management interfaces.
- **Decision:** `policy-engine` and **outbound network enforcement** are independent layers. Pin/verify connected destination and recheck after redirects. Remote scan workers must have no internal-plane connectivity.
- **Verification:** fake DNS/redirect tests plus network-policy integration test; **zero** unauthorized outbound connections in fixtures.

### HSR-02 · Critical · Authorization is not a strongly typed, expiring capability

- **Condition:** `authorized_scopes + approvals` exist conceptually but the precise allowed test methods, expiration, owner, asset and purpose are not encoded as an immutable versioned grant.
- **Failure mode:** a stale or overly broad authorization permits another target, method or time window.
- **Decision:** versioned authorization grants, exact allowlist, max-request budget, allowed methods, explicit host/port/path rules and expiry. Domain challenge demonstrates control, **not blanket permission** for active tests.
- **Verification:** incomplete/expired/scope-expanded grants fail closed; queued jobs recheck permission before actual execution.

### HSR-03 · Critical · Scanner execution trust boundary is too broad

- **Condition:** running Semgrep, Trivy, ZAP or a repository-associated process on the main host can lead to tool parsing risks, supply-chain execution, filesystem exposure or lateral movement.
- **Decision:** read-only mounts, non-root isolation, no Docker socket, restricted filesystem and egress, binary/version allowlist, bounded CPU/RAM/process time and no shell string interpolation. Never run project `npm install`, `composer install`, git hooks or build scripts in scanner work.
- **Verification:** adversarial local repository fixture cannot execute a marker script or access fake service secrets.

### HSR-04 · High · Security finding semantics risk false claims

- **Condition:** observing a missing CSP or cookie attribute is not necessarily proof of an exploitable weakness. Severity and confidence can be conflated.
- **Decision:** separate **observed condition**, **impact hypothesis**, **confidence**, **internal priority/CVSS**, and **verification status**. Every finding includes clear limitations and contextual remediation.
- **Verification:** negative fixtures (legitimate public cookie, non-HTML asset, CSP report-only rollout) do not produce overstated critical findings.

### HSR-05 · High · Re-test may falsely declare fixes

- **Condition:** fingerprint-based comparison alone does not establish that scan coverage, profile and rule interpretation remained equivalent.
- **Decision:** compare scope, asset, rule version, scanner coverage, profile and reachability. `no_longer_observed` is distinct from `verified_fixed`; partial scans are `not_comparable`.
- **Verification:** failed scan, changed redirect, moved endpoint and updated rule do **not** silently become `fixed`.

### HSR-06 · High · Redaction after collection is late for some channels

- **Condition:** sensitive response data can leak before report generation via HTTP debug logs, child stdout/stderr, crash dumps, temp files, analytics and alert payloads.
- **Decision:** collection minimization, allowlisted evidence serialization and no raw response storage first; redaction second; isolated temp storage, safe logging and artifact retention policies third.
- **Verification:** planted JWT, API key, cookie and personal-data fixture never appears in generated outputs or debug logs.

### HSR-07 · High · Coverage is not modeled as a first-class security result

- **Condition:** a failed Trivy invocation or TLS connection could otherwise produce an empty finding list that UI interprets as “secure”.
- **Decision:** `coverage_status`, `scanner_status`, exclusions and reasons must be explicit, displayed and machine-readable. The global result can be `completed_with_gaps`.
- **Verification:** missing tools, blocked targets and timeouts cannot result in a green/clean final status.

### HSR-08 · High · Multi-tenant data separation is underdeveloped

- **Condition:** a project ID-only model will not be sufficient once multiple organizations use the Laravel API and artifacts.
- **Decision:** membership and organization boundaries in database, policies, artifacts, search endpoints and report exports; authorize every query and job command. Use a separate worker identity.
- **Verification:** request with tenant A credentials to tenant B scan, findings, exports or signed storage URLs is denied.

### HSR-09 · Medium · Delivery scope is not realistically phased

- **Condition:** safe egress, scanner adapters, three export formats, email, re-test and all tests are too many critical-path tasks for a 1-day release.
- **Decision:** 1–2-day offline CLI spike, then hardened v0.1. SMTP and SARIF after canonical JSON/Markdown work. Laravel/Next.js UI follows a stable engine, not vice versa.
- **Verification:** publish only demonstrated features in README/release notes.

### HSR-10 · Medium · Scanner provenance and ruleset stability need controls

- **Condition:** third-party binaries, vulnerability databases and rulepacks change. An identical target can produce different results on different days.
- **Decision:** capture tool/rule/db versions and database freshness, pin compatible versions, preserve license notices, sign releases, document offline mode and mark drift-driven comparisons as uncertain.
- **Verification:** test fixtures and normalized outputs can be reproduced with documented versions.

### HSR-11 · Medium · Default automatic external disclosure would be risky

- **Condition:** mailing a full issue list or creating a GitHub issue can expose customer topology and security details.
- **Decision:** sanitized summaries, recipient verification, human confirmation, private-by-default integrations and full audit history. No auto-posting to a public issue tracker.
- **Verification:** unauthorized recipients and public repo sinks are denied in integration tests.

### HSR-12 · Medium · “Pentest” and “AI-fix” terms can overpromise

- **Condition:** automated config checks, SAST and SCA do not replicate a manual penetration test; generated fixes may break security/business logic.
- **Decision:** explain coverage, limitations and review status. Distinguish **assessment**, **controlled validation** and a professionally scoped penetration test. AI narratives are optional and do not certify results.
- **Verification:** UX and report disclaimers; suggestion preview and reviewer approval.

## 3. Reverse-engineering-inspired engineering method

**Treat every finding as a hypothesis requiring traceable proof, not a scanner assertion.**

1. **Identify attack surface:** inventory trust boundaries, network flows, data sinks, executable adapters and privilege transitions.
2. **Trace data provenance:** target input → canonical URL → DNS resolution → network connection → response observation → redaction → rule match → finding → developer notification.
3. **Test invariants:** no unauthorized packet; no secret leaves scanner; no vulnerability “confirmation” without evidence; failed coverage never appears clean.
4. **Adversarial test cases:** malformed URLs and redirects; changing DNS; malicious repository hooks; oversized stdout; embedded secrets; inconsistent scan results; cross-tenant identifiers.
5. **Proof-of-correction:** failing security test before change, passing test after change, reviewer sign-off and clear residual risk statement.

These are security engineering and adversarial validation practices. Actual reverse engineering of a running implementation becomes possible only once source/binaries/runtime are provided.

## 4. Precise product positioning

Recommended: **“HegoSentinel — Open-source developer security assessment, evidence, remediation and re-test workflow.”**

Avoid: “automatically discovers all vulnerabilities,” “zero false positives,” “certified penetration test,” “guaranteed secure” or “AI fixes everything.”

## 5. Go / no-go release gates

| Gate | Go when | No-go when |
|---|---|---|
| G0 | Scope and outbound boundaries pass negative tests; offline demo reproducible | Any unauthorized request or reachable internal resource |
| G1 | Validated normalized reports, redaction, positive fixtures, re-test correctness | Missing tool silently treated as clean; secrets in outputs |
| G2 | Tenant isolation, worker containment, canceled jobs and notification authorization verified | Cross-tenant read, unbounded worker or uncontrolled integration |
| G3 | Separate staging consent + rate limits + kill switch + human validation | Production default or unrestricted active scan |

## 6. Standards and external references

- [OWASP ASVS 5.0.0](https://asvs.owasp.org/) — stable requirements.
- [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide) — v4.2 stable; v5 under development.
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [FIRST CVSS 4.0](https://www.first.org/cvss/v4.0/specification-document) — complete vector with any published numeric score.
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/).
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/).
- [Trivy repository scanning](https://www.trivy.dev/docs/latest/guide/target/repository/), [Semgrep CE](https://semgrep.dev/products/community-edition/).
