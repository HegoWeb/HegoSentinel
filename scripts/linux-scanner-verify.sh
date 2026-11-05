#!/usr/bin/env bash
# HegoSentinel — Sprint 7 Real Semgrep CE (1.96.0) & Trivy (0.57.1) Verification Script
# Scans the synthetic Laravel, Next.js, and Node.js target projects with real binaries,
# normalizes outputs into HegoSentinel's finding schema, and saves reports/real-scanner-evidence.json.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_FILE="${REPO_ROOT}/reports/real-scanner-evidence.json"
mkdir -p "${REPO_ROOT}/reports"

if ! command -v semgrep >/dev/null 2>&1; then
  echo "[SKIP — NOT VERIFIED] semgrep binary is not installed in PATH" >&2
  exit 2
fi

if ! command -v trivy >/dev/null 2>&1; then
  echo "[SKIP — NOT VERIFIED] trivy binary is not installed in PATH" >&2
  exit 2
fi

SEMGREP_VER="$(semgrep --version | head -n 1)"
TRIVY_VER="$(trivy --version | head -n 1)"

echo "=== Running Real Semgrep (${SEMGREP_VER}) & Trivy (${TRIVY_VER}) against Synthetic Targets ==="

node --experimental-strip-types -e "
import { resolve } from 'node:path';
import { writeFileSync, readFileSync } from 'node:fs';
import { runSemgrepAdapter } from './integrations/semgrep/src/index.ts';
import { runTrivyAdapter } from './integrations/trivy/src/index.ts';

const baseGrant = JSON.parse(readFileSync('./examples/safe-demo/hegosentinel.scope.json', 'utf8'));
const targetsRoot = resolve(process.cwd(), 'examples/synthetic-targets');
const rulepackPath = resolve(targetsRoot, 'semgrep-rules.yml');

const grant = {
  ...baseGrant,
  allowed_checks: ['CODE-001', 'DEP-001'],
  allowed_repositories: [targetsRoot]
};

const stacks = [
  { name: 'laravel', path: resolve(targetsRoot, 'laravel-app') },
  { name: 'nextjs', path: resolve(targetsRoot, 'nextjs-app') },
  { name: 'nodejs', path: resolve(targetsRoot, 'nodejs-app') }
];

const summary = [];
for (const s of stacks) {
  const sg = await runSemgrepAdapter({
    grant,
    repositoryPath: s.path,
    rulepackRef: rulepackPath
  });
  if (sg.coverage.status !== 'executed' || sg.findings.length === 0) {
    console.error('Real Semgrep scan failed or found 0 issues on ' + s.name, sg.coverage);
    process.exit(1);
  }
  const tv = await runTrivyAdapter({
    grant,
    repositoryPath: s.path
  });
  if (tv.coverage.status === 'denied') {
    console.error('Real Trivy scan denied on ' + s.name, tv.coverage);
    process.exit(1);
  }
  summary.push({
    stack: s.name,
    semgrep_status: sg.coverage.status,
    semgrep_tool_version: sg.coverage.tool_version,
    semgrep_rulepack: sg.coverage.rulepack_version,
    semgrep_findings: sg.findings.length,
    trivy_status: tv.coverage.status,
    trivy_tool_version: tv.coverage.tool_version,
    trivy_db_freshness: tv.coverage.db_freshness,
    trivy_findings: tv.findings.length
  });
}

writeFileSync('./reports/real-scanner-evidence.json', JSON.stringify({
  verified_at: new Date().toISOString(),
  semgrep_version: '${SEMGREP_VER}',
  trivy_version: '${TRIVY_VER}',
  stacks: summary
}, null, 2) + '\n', 'utf8');
console.log('[OK] Real Semgrep & Trivy verification succeeded:', JSON.stringify(summary));
"

