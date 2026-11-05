# Security Test Catalog (Proposed)

Tests will be derived from applicable OWASP ASVS 5.0 requirements and WSTG methodologies, with original check IDs and clear versioned references. These are **planned checks**, not implemented tests.

| Check ID | Area | Example assessment | Execution | Phase |
| --- | --- | --- | --- | --- |
| WEB-TLS-001 | Transport | TLS certificate and protocol posture | Passive / controlled connection | v0.1 |
| WEB-HEADER-001 | HTTP | Security headers observed in responses | Passive | v0.1 |
| WEB-COOKIE-001 | Session | `Secure`, `HttpOnly`, and applicable `SameSite` attributes | Passive | v0.1 |
| WEB-REDIRECT-001 | Transport | Unexpected HTTP downgrade | Passive | v0.1 |
| CODE-001 | SAST | Known unsafe source-code patterns | Local, consented code scan | v0.1 |
| DEP-001 | SCA | Dependencies with known published advisories | Local, consented dependency scan | v0.1 |
| WEB-ZAP-PASSIVE-001 | Web | ZAP passive findings mapped to common format | Passive | v0.2 |
| API-AUTHZ-001 | API | Intended permission boundaries using test accounts | Human-gated staging test | v0.3+ |
| DAST-CONTROLLED-001 | DAST | Limited, authorized active checks | Explicit opt-in, staging only | v0.3+ |

## Finding evidence rules

Every result must specify:

- **Signal**: what was directly observed (not what might be true).
- **Asset and timestamp**: which authorized endpoint/revision was checked and when.
- **Reproduction conditions**: non-sensitive, repeatable check method.
- **Confidence**: `low`, `medium`, `high`.
- **Verification**: `observed`, `needs_review`, `confirmed`, `false_positive`, `fixed`, `reopened`.
- **Impact**: calibrated, not sensationalized; do not infer complete compromise from a configuration issue.
- **Remediation**: practical next action for the relevant framework.
- **References**: source documentation, CWE/ASVS/WSTG where applicable.

## Severity

CVSS 4.0 may be used when a full and appropriate vector can actually be scored. Otherwise use clearly labeled internal priority (`critical`, `high`, `medium`, `low`, `info`) without implying it is a CVSS result. Severity is distinct from detection confidence.

## AI-assisted explanations (future, optional)

- Only elaborate on findings already produced by deterministic tools or human reviewers.
- Show the original observation and separate model suggestions from validated facts.
- Avoid uploading secrets, access tokens, complete private source files, or personally identifying evidence to third-party models.
- Require developer review of suggested patches and never auto-deploy or auto-merge.
