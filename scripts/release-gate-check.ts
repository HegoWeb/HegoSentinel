import { resolve } from 'node:path';
import {
  runAllSecurityGatesVerification,
  type GateVerificationEntry
} from './verify-all-security-gates.ts';

export interface ReleaseGateEvaluation {
  evaluated_at: string;
  release_allowed: boolean;
  restricted_remote_unlocked: false;
  total_gates: number;
  passed_gates: string[];
  failed_gates: string[];
  skipped_unverified_gates: string[];
  blocking_reasons: string[];
}

/**
 * Sprint 7 (Section 6): Evaluates whether all critical security gates (WKR-001..006,
 * CODE-001, DEP-001, SEC-001..014, EGR-001..006, EGR-LINUX-NETNS-RUNTIME) have achieved PASS.
 * Blocks production release if ANY security gate is in FAIL or SKIP (not verified) state.
 */
export function evaluateProductionReleaseReadiness(
  gates: readonly GateVerificationEntry[]
): ReleaseGateEvaluation {
  const passed: string[] = [];
  const failed: string[] = [];
  const skipped: string[] = [];
  const blockingReasons: string[] = [];

  for (const g of gates) {
    if (g.verdict === 'PASS') {
      passed.push(g.gate_id);
    } else if (g.verdict === 'FAIL') {
      failed.push(g.gate_id);
      blockingReasons.push(
        `[FAIL] ${g.gate_id} (${g.execution_layer}): ${g.log_evidence}`
      );
    } else {
      skipped.push(g.gate_id);
      blockingReasons.push(
        `[SKIP — NOT VERIFIED] ${g.gate_id} (${g.execution_layer}): ${g.log_evidence}`
      );
    }
  }

  return {
    evaluated_at: new Date().toISOString(),
    release_allowed: failed.length === 0 && skipped.length === 0 && gates.length > 0,
    restricted_remote_unlocked: false,
    total_gates: gates.length,
    passed_gates: passed,
    failed_gates: failed,
    skipped_unverified_gates: skipped,
    blocking_reasons: blockingReasons
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(process.cwd(), 'scripts/release-gate-check.ts')
) {
  const enforceRelease = process.argv.includes('--enforce-production-release');
  const report = await runAllSecurityGatesVerification();
  const evaluation = evaluateProductionReleaseReadiness(report.gates);

  if (evaluation.release_allowed) {
    process.stdout.write(
      `[RELEASE GATE: READY] All ${evaluation.total_gates} security gates achieved PASS (0 FAIL, 0 SKIP).\n`
    );
  } else {
    process.stdout.write(
      `[RELEASE GATE: BLOCKED] Production release is blocked (${evaluation.failed_gates.length} FAIL, ${evaluation.skipped_unverified_gates.length} SKIP — NOT VERIFIED):\n`
    );
    for (const reason of evaluation.blocking_reasons) {
      process.stdout.write(`  - ${reason}\n`);
    }
    if (enforceRelease || evaluation.failed_gates.length > 0) {
      process.exit(1);
    }
  }
}

