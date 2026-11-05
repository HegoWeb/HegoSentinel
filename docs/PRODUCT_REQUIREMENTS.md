# Product Requirements Document (PRD)

Version: Draft 0.1 · Product: HegoSentinel · License plan: MIT

## Vision

Help developers go from a trustworthy security finding to a verified fix, without forcing them to operate several security tools or expose sensitive application code to cloud AI services.

## Target users

1. Independent Laravel/Next.js developers maintaining their own applications.
2. Small development agencies with authorization to test client systems.
3. DevSecOps contributors integrating security checks into CI.

## User stories

- As an owner, I want to define exactly which hostnames and repositories may be examined.
- As a developer, I want a short, evidence-backed description with a concrete fix and re-test conditions.
- As a reviewer, I want to distinguish an observed signal from a confirmed vulnerability.
- As a maintainer, I want to compare findings before and after a release.
- As a team lead, I want to export a sanitized report or explicitly approve an issue submission.

## MVP acceptance criteria

1. No scan starts without scope authorization in the local project configuration.
2. Target checks reject loopback, link-local, private, metadata, and out-of-scope addresses in hosted/remote modes; validate DNS and redirects throughout. Local intentional scanning uses a separate isolated demo profile.
3. Passive HTTP/TLS/header/cookie checks yield normalized, evidence-backed findings with timestamps.
4. Optional source/dependency scanning operates only on selected, locally accessible/approved repositories.
5. Every finding includes title, affected asset, severity, confidence, status, short evidence, fix suggestion, source reference, and verification guidance.
6. Export JSON and readable Markdown/HTML reports, redacting tokens, secrets, query credentials, and personal data.
7. Re-test compares a project's previous and new results, distinguishing newly detected, persistent, and no-longer-observed conditions.
8. The owner can explicitly opt in to sending a sanitized report to a nominated developer by SMTP; there is no automatic third-party disclosure.
9. Automated tests cover allowlist behavior, redirect/DNS checks, result normalization, redaction, and re-test state transitions.
10. A clearly labeled test/demo project ships with anonymized synthetic findings.

## Non-goals for MVP

- No full autonomous penetration testing, exploit chaining, password attacks, denial-of-service, mass asset discovery, or arbitrary script execution.
- No claim of compliance certification or complete security coverage.
- No automatic source modifications, PR merging, or unapproved external notifications.
- No sending private repository content to an external AI service.

## Success measures

- A new user can analyze a permitted example project and view a report.
- 100% of emitted findings have a reproducible check identifier and a verification status.
- Demo reports contain no secrets or session identifiers.
- A second scan reliably shows new/resolved/persistent issues for a fixture application.
- Documented false-positive feedback path exists.

## UX screens (v0.2)

- Projects / authorized scope
- Scan creation and safe profiles
- Scan timeline
- Findings table and detail page
- Developer remediation guidance
- Compare / re-test
- Report export and integrations
- Access control and audit log

## Decision log

- Start with developer workflows and non-destructive checks rather than inventing new exploit techniques.
- Use existing reputable scanners as replaceable adapters.
- Keep AI explanations optional; core checks and rules must work without an AI model.
