import {
  SCHEMA_VERSION,
  type CheckCoverageRecord,
  type FalsePositiveSuppression,
  type NormalizedFinding,
  type RecheckComparisonItem,
  type RecheckComparisonReport,
  type RecheckState,
  type ScanReport
} from '../../findings-schema/src/index.ts';

export interface CompareOptions {
  suppressions?: FalsePositiveSuppression[];
  previouslyResolvedFingerprints?: string[];
  now?: Date;
}

function createEmptyCounts(): Record<RecheckState, number> {
  return {
    new: 0,
    persistent: 0,
    no_longer_observed: 0,
    verified_fixed: 0,
    reopened: 0,
    not_comparable: 0,
    skipped: 0,
    false_positive: 0
  };
}

function findMatchingCoverageCheck(
  report: ScanReport,
  counterpartReport: ScanReport,
  ruleId: string,
  assetKey: string
): CheckCoverageRecord | undefined {
  const exactMatch = report.coverage.checks.find(
    (c) => c.rule_id === ruleId && c.asset_key === assetKey
  );
  if (exactMatch) {
    return exactMatch;
  }

  // Web rules (WEB-*) must NEVER fall back to a coverage record from a different endpoint/asset_key (HS-AUDIT-001).
  if (ruleId !== 'CODE-001' && ruleId !== 'DEP-001') {
    return undefined;
  }

  // For repository-level rules (CODE-001 / DEP-001), only match when both baseline and current
  // evaluated the exact same repository root asset_key.
  const reportRepoChecks = report.coverage.checks.filter((c) => c.rule_id === ruleId);
  const counterpartRepoChecks = counterpartReport.coverage.checks.filter(
    (c) => c.rule_id === ruleId
  );
  if (
    reportRepoChecks.length === 1 &&
    counterpartRepoChecks.length === 1 &&
    reportRepoChecks[0].asset_key === counterpartRepoChecks[0].asset_key
  ) {
    return reportRepoChecks[0];
  }

  return undefined;
}

/**
 * Compares baseline and current ScanReports while strictly enforcing scope, tenant, grant,
 * scope_version, profile, rule-version, and per-asset coverage equivalence
 * (S1-05 / HSR-05 / SEC-009 / SEC-010 / HS-AUDIT-001 / HS-AUDIT-004).
 */
export function compareScanReports(
  baseline: ScanReport,
  current: ScanReport,
  options: CompareOptions = {}
): RecheckComparisonReport {
  const now = options.now ?? new Date();
  const suppressions = options.suppressions ?? [];
  const previouslyResolved = new Set<string>(options.previouslyResolvedFingerprints ?? []);

  const incomparabilityReasons: string[] = [];

  if (baseline.organization_id !== current.organization_id) {
    incomparabilityReasons.push(
      `Organization mismatch (${baseline.organization_id} vs ${current.organization_id})`
    );
  }
  if (baseline.project_id !== current.project_id) {
    incomparabilityReasons.push(
      `Project mismatch (${baseline.project_id} vs ${current.project_id})`
    );
  }
  if (baseline.grant_id !== current.grant_id) {
    incomparabilityReasons.push(
      `Authorization grant mismatch (${baseline.grant_id} vs ${current.grant_id})`
    );
  }
  if (baseline.scope_version !== current.scope_version) {
    incomparabilityReasons.push(
      `Scope version changed (v${baseline.scope_version} vs v${current.scope_version})`
    );
  }
  if (baseline.profile !== current.profile) {
    incomparabilityReasons.push(
      `Scan profile changed (${baseline.profile} vs ${current.profile})`
    );
  }
  if (baseline.coverage.global_status === 'denied' || current.coverage.global_status === 'denied') {
    incomparabilityReasons.push('One or both scans were denied by scope policy');
  }
  if (baseline.coverage.global_status === 'failed' || current.coverage.global_status === 'failed') {
    incomparabilityReasons.push('One or both scans failed globally');
  }

  const counts = createEmptyCounts();
  const items: RecheckComparisonItem[] = [];

  const baselineMap = new Map<string, NormalizedFinding>();
  for (const f of baseline.findings) {
    baselineMap.set(f.fingerprint, f);
  }

  const currentMap = new Map<string, NormalizedFinding>();
  for (const f of current.findings) {
    currentMap.set(f.fingerprint, f);
  }

  const allFingerprints = new Set<string>([
    ...baselineMap.keys(),
    ...currentMap.keys()
  ]);

  // Global incomparability short-circuit: never claim fixed when runs are not comparable (SEC-009)
  if (incomparabilityReasons.length > 0) {
    for (const fp of allFingerprints) {
      const bf = baselineMap.get(fp);
      const cf = currentMap.get(fp);
      const ref = cf ?? bf!;
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Runs are not comparable: ${incomparabilityReasons.join('; ')}`
      });
    }

    return {
      schema_version: SCHEMA_VERSION,
      baseline_scan_id: baseline.scan_id,
      current_scan_id: current.scan_id,
      organization_id: current.organization_id,
      project_id: current.project_id,
      comparable: false,
      incomparability_reasons: incomparabilityReasons,
      compared_at: now.toISOString(),
      counts,
      items
    };
  }

  for (const fp of allFingerprints) {
    const bf = baselineMap.get(fp);
    const cf = currentMap.get(fp);
    const ref = cf ?? bf!;

    // 1. Check project-scoped reviewed false_positive suppression (SEC-010)
    const activeSuppression = suppressions.find((s) => {
      const expiresMs = Date.parse(s.expires_at);
      return (
        s.fingerprint === fp &&
        s.organization_id === current.organization_id &&
        s.project_id === current.project_id &&
        s.scope_version === current.scope_version &&
        !Number.isNaN(expiresMs) &&
        expiresMs > now.getTime() &&
        s.reviewer.trim().length > 0 &&
        s.reason.trim().length > 0
      );
    });

    if (activeSuppression) {
      counts.false_positive += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'false_positive',
        explanation: `Suppressed as reviewed false_positive by ${activeSuppression.reviewer} until ${activeSuppression.expires_at}: ${activeSuppression.reason}`,
        suppression: {
          reviewer: activeSuppression.reviewer,
          reason: activeSuppression.reason,
          expires_at: activeSuppression.expires_at
        }
      });
      continue;
    }

    const baselineCheck = findMatchingCoverageCheck(baseline, current, ref.rule_id, ref.asset_key);
    const currentCheck = findMatchingCoverageCheck(current, baseline, ref.rule_id, ref.asset_key);

    // 2a. If the specific asset was not evaluated by this rule in the current scan, mark not_comparable (HS-AUDIT-001)
    if (!currentCheck) {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Asset "${ref.asset_key}" was not evaluated by rule ${ref.rule_id} in the current run; cannot verify status across different target assets.`
      });
      continue;
    }

    // If a previous HTML page is now non-HTML or returns a non-success HTTP status,
    // the original condition was not retested. Do not count it as a verified fix.
    if (currentCheck.reason?.startsWith('not_applicable:')) {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `The current rule was not applicable to the original asset (${currentCheck.reason}); a comparable successful endpoint is required.`
      });
      continue;
    }

    // 2b. If the check was explicitly skipped in the current scan, never mark fixed
    if (currentCheck.status === 'skipped') {
      counts.skipped += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'skipped',
        explanation: `Check ${ref.rule_id} was skipped in current run (${currentCheck.reason ?? 'not executed'}); cannot verify status.`
      });
      continue;
    }

    if (currentCheck.status !== 'executed') {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Check ${ref.rule_id} did not execute cleanly in current run (status: ${currentCheck.status}).`
      });
      continue;
    }

    // 3. Check rule version drift (SEC-009 / HSR-10)
    const baselineRuleVersion = bf?.rule_version ?? baselineCheck?.rule_version;
    const currentRuleVersion = cf?.rule_version ?? currentCheck.rule_version;
    if (baselineRuleVersion && currentRuleVersion && baselineRuleVersion !== currentRuleVersion) {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Rule ${ref.rule_id} version changed (${baselineRuleVersion} -> ${currentRuleVersion}); comparison requires manual review.`
      });
      continue;
    }

    // 3b. Check source scanner rulepack_version or stale DB drift (Sprint C — P1)
    if (
      baselineCheck?.rulepack_version &&
      currentCheck.rulepack_version &&
      baselineCheck.rulepack_version !== currentCheck.rulepack_version
    ) {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Scanner rulepack version drifted (${baselineCheck.rulepack_version} -> ${currentCheck.rulepack_version}); comparison requires manual review.`
      });
      continue;
    }

    if (currentCheck.db_freshness === 'stale') {
      counts.not_comparable += 1;
      items.push({
        fingerprint: fp,
        rule_id: ref.rule_id,
        asset_key: ref.asset_key,
        title: ref.title,
        previous_state: bf ? bf.verification_status : 'not_present',
        recheck_state: 'not_comparable',
        explanation: `Scanner advisory database is stale in current run (db_freshness=stale); cannot verify remediation.`
      });
      continue;
    }

    const dbDriftSuffix =
      baselineCheck?.db_version &&
      currentCheck.db_version &&
      baselineCheck.db_version !== currentCheck.db_version
        ? ` [Scanner DB version drift noted: ${baselineCheck.db_version} -> ${currentCheck.db_version}]`
        : '';

    // 4. Both baseline and current observed the finding -> persistent
    if (bf && cf) {
      counts.persistent += 1;
      items.push({
        fingerprint: fp,
        rule_id: cf.rule_id,
        asset_key: cf.asset_key,
        title: cf.title,
        previous_state: bf.verification_status,
        recheck_state: 'persistent',
        explanation: `Condition remains observable on the target asset.${dbDriftSuffix}`
      });
      continue;
    }

    // 5. Only in current -> reopened (if previously resolved) or new
    if (!bf && cf) {
      if (previouslyResolved.has(fp)) {
        counts.reopened += 1;
        items.push({
          fingerprint: fp,
          rule_id: cf.rule_id,
          asset_key: cf.asset_key,
          title: cf.title,
          previous_state: 'no_longer_observed',
          recheck_state: 'reopened',
          explanation: `Previously resolved condition was observed again in the current run.${dbDriftSuffix}`
        });
      } else {
        counts.new += 1;
        items.push({
          fingerprint: fp,
          rule_id: cf.rule_id,
          asset_key: cf.asset_key,
          title: cf.title,
          previous_state: 'not_present',
          recheck_state: 'new',
          explanation: `Newly observed condition in the current run.${dbDriftSuffix}`
        });
      }
      continue;
    }

    // 6. Present in baseline, absent in current -> distinguish verified_fixed vs no_longer_observed (S1-05 / HSR-05)
    if (bf && !cf) {
      // Cookie findings are individual identities within a rule/endpoint. Never
      // infer an old cookie was fixed because some other cookie was configured safely.
      const proofMatchesFinding = ref.rule_id !== 'WEB-COOKIE-001' ||
        currentCheck.positive_validation_fingerprints?.includes(fp) === true;
      if (currentCheck.positive_validation_passed === true && proofMatchesFinding) {
        counts.verified_fixed += 1;
        items.push({
          fingerprint: fp,
          rule_id: bf.rule_id,
          asset_key: bf.asset_key,
          title: bf.title,
          previous_state: bf.verification_status,
          recheck_state: 'verified_fixed',
          explanation:
            `Condition is no longer observed AND the positive remediation validation criterion passed on the target endpoint.${dbDriftSuffix}`
        });
      } else {
        counts.no_longer_observed += 1;
        items.push({
          fingerprint: fp,
          rule_id: bf.rule_id,
          asset_key: bf.asset_key,
          title: bf.title,
          previous_state: bf.verification_status,
          recheck_state: 'no_longer_observed',
          explanation:
            `Condition was not observed in the current run; manual verification is recommended to confirm a complete fix.${dbDriftSuffix}`
        });
      }
    }
  }

  return {
    schema_version: SCHEMA_VERSION,
    baseline_scan_id: baseline.scan_id,
    current_scan_id: current.scan_id,
    organization_id: current.organization_id,
    project_id: current.project_id,
    comparable: true,
    incomparability_reasons: [],
    compared_at: now.toISOString(),
    counts,
    items
  };
}

