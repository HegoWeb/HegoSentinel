# Sample Developer Security Report

> **SYNTHETIC EXAMPLE ONLY — not a real scan or verified vulnerability report.**

## Engagement overview

- Project: Sample Laravel + Next.js application
- Authorized target: `https://demo.example.test`
- Date: Example date
- Profile: Passive web checks + optional local source/dependency review
- Scope authorization: Demonstration fixture only
- Result: 2 observations, 1 informational note; 0 manually confirmed vulnerabilities

## Finding HS-0001 — Content-Security-Policy not observed

- **Priority**: Medium (internal priority, not a calculated CVSS score)
- **Confidence**: High that the header was absent on the tested response
- **Verification status**: Observed; security impact needs application-specific review
- **Asset**: `https://demo.example.test/`
- **Evidence**: The response headers in the controlled example did not include Content-Security-Policy.
- **Why it matters**: An effective policy adds a browser-enforced control that can limit some script execution risks. Its absence alone does not prove an XSS vulnerability.
- **Suggested action**: Design a context-appropriate Content-Security-Policy, test in report-only mode, and then enforce it after checking application compatibility.
- **Re-test**: Confirm the policy is emitted on the relevant endpoints and verify that it behaves as intended.
- **Owner**: Frontend / web platform engineer
- **Status**: Awaiting developer review

## Finding HS-0002 — Session cookie attributes need review

- **Priority**: Medium (internal)
- **Confidence**: Medium; whether each attribute is required depends on deployment context
- **Verification status**: Needs review
- **Evidence**: A controlled fixture session cookie lacks a desired attribute in the example response.
- **Suggested action**: Check whether `Secure`, `HttpOnly`, and `SameSite` settings are appropriate for the application’s session and cross-origin authentication design.
- **Re-test**: Validate the cookie attributes and application login flow over HTTPS.
- **Owner**: Backend / authentication engineer

## Suggested developer delivery

1. One-page manager summary (risk categories, affected systems, scope limits).
2. Developer findings with redacted evidence and remediation steps.
3. Acknowledgment/ownership and re-test status per finding.
4. Appendices: used tools and versions, scope, scan timings, limitations.

### Re-test comparison (illustration)

| ID | First run | After change |
| --- | --- | --- |
| HS-0001 | Observed | No longer observed (pending review) |
| HS-0002 | Needs review | Still observed |

A condition no longer being observed is **not** a blanket proof that the entire application is secure.
