<!-- generated from reports/security-gates-verification.json (generated_at=2026-11-05T00:55:51.686Z, host=win32/10.0.26200 (Node v24.19.0)) -->
| Gate | Katman | Sonuç | Kod referansı | Yeniden üretme |
|---|---|---|---|---|
| WKR-001-MANIFEST | Host (deterministik test) | **PASS** | apps/worker/src/index.ts#analyzeDockerRunOutcome | `node --experimental-strip-types --test ./tests/security/work` |
| WKR-001-RUNTIME | Gerçek Linux Docker | **SKIP** | scripts/linux-docker-verify.sh | `bash ./scripts/linux-docker-verify.sh` |
| WKR-002-RUNTIME | Gerçek Linux Docker | **SKIP** | apps/worker/src/index.ts#buildDockerRunArgsForSourceOffline | `bash ./scripts/linux-docker-verify.sh` |
| WKR-003-RUNTIME | Gerçek Linux Docker | **SKIP** | apps/worker/source-offline-manifest.json | `bash ./scripts/linux-docker-verify.sh` |
| WKR-004-SYMLINK | Host (deterministik test) | **PASS** | integrations/semgrep/src/index.ts#validateAuthorizedRepositoryPath | `node --experimental-strip-types --test ./tests/security/audi` |
| WKR-005-RUNTIME | Gerçek Linux Docker | **SKIP** | apps/worker/source-offline-manifest.json | `bash ./scripts/linux-docker-verify.sh` |
| WKR-006-LIFECYCLE | Host (deterministik test) | **PASS** | integrations/semgrep/src/index.ts#runSemgrepAdapter | `node --experimental-strip-types --test ./tests/security/work` |
| CODE-001-ADAPTER | Host (deterministik test) | **PASS** | integrations/semgrep/src/index.ts#normalizeSemgrepOutput | `node --experimental-strip-types --test ./tests/integration/a` |
| CODE-001-BINARY | Gerçek ikili (Semgrep/Trivy) | **PASS** | scripts/linux-scanner-verify.sh | `bash ./scripts/linux-scanner-verify.sh` |
| DEP-001-ADAPTER | Host (deterministik test) | **PASS** | integrations/trivy/src/index.ts#normalizeTrivyOutput | `node --experimental-strip-types --test ./tests/integration/a` |
| DEP-001-BINARY | Gerçek ikili (Semgrep/Trivy) | **PASS** | scripts/linux-scanner-verify.sh | `bash ./scripts/linux-scanner-verify.sh` |
| SEC-001 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#validateScopeAuthorizationGrant | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-002 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#classifyIpAddress | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-003 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#validateRedirectTransition | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-004 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#verifyConnectedSocketPeer | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-005 | Host (deterministik test) | **PASS** | packages/scanner-core/src/index.ts#executeScan | `node --experimental-strip-types --test ./tests/security/inde` |
| SEC-006 | Host (deterministik test) | **PASS** | integrations/semgrep/src/index.ts#runSemgrepAdapter | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-007 | Host (deterministik test) | **PASS** | packages/report-engine/src/index.ts#redactSensitiveText | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-008 | Host (deterministik test) | **PASS** | packages/scanner-core/src/index.ts#computeGlobalCoverageStatus | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-009 | Host (deterministik test) | **PASS** | packages/recheck-engine/src/index.ts#compareScanReports | `node --experimental-strip-types --test ./tests/security/cook` |
| SEC-010 | Host (deterministik test) | **PASS** | packages/recheck-engine/src/index.ts#compareScanReports | `node --experimental-strip-types --test ./tests/security/inde` |
| SEC-011 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#authorizeReportTenantAccess | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-012 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#EmergencyStopRegistry | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-013 | Host (deterministik test) | **PASS** | packages/policy-engine/src/index.ts#validateExternalNotificationReques | `node --experimental-strip-types --test ./tests/security/secu` |
| SEC-014 | Host (deterministik test) | **PASS** | packages/scanner-core/src/cli.ts | `npm run demo` |
| EGR-001 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#TrustedEgressBroker | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-002 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#TrustedEgressBroker | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-003 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#TrustedEgressBroker | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-004 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#TrustedEgressBroker | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-005 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#TrustedEgressBroker | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-006 | Host (deterministik test) | **PASS** | apps/egress-broker/src/index.ts#createTrustedEgressBrokerServer | `node --experimental-strip-types --test ./tests/security/work` |
| EGR-LINUX-NETNS-RUNTIME | Gerçek Linux netns | **SKIP** | scripts/linux-netns-egress-verify.sh | `bash ./scripts/linux-netns-egress-verify.sh` |
