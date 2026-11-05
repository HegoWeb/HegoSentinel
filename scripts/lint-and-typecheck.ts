import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  validateRecheckReportDocument,
  validateScanReportDocument
} from '../packages/findings-schema/src/index.ts';
import { validateScopeAuthorizationGrant } from '../packages/policy-engine/src/index.ts';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

function collectTsFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'reports' || entry === '.next') continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      collectTsFiles(full, acc);
    } else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      acc.push(full);
    }
  }
  return acc;
}

async function main(): Promise<void> {
  const mode = process.argv.includes('--lint') ? 'lint' : 'typecheck';
  const targetDirs = ['apps', 'packages', 'integrations', 'scripts', 'tests'];
  const tsFiles: string[] = [];

  for (const d of targetDirs) {
    collectTsFiles(join(ROOT, d), tsFiles);
  }

  const errors: string[] = [];

  for (const file of tsFiles) {
    const rel = relative(ROOT, file).replace(/\\/g, '/');
    const source = readFileSync(file, 'utf8');

    // 1. Validate TypeScript syntax & erasable type annotations via Node 24 module.stripTypeScriptTypes
    try {
      stripTypeScriptTypes(source, { mode: 'strip', sourceUrl: rel });
    } catch (err) {
      errors.push(`[TypeScript Syntax Error] ${rel}: ${(err as Error).message}`);
    }

    // 2. Security & Code Quality Linter Rules
    if (mode === 'lint') {
      if (/\beval\s*\(/.test(source) || /\bnew\s+Function\s*\(/.test(source)) {
        errors.push(`[Lint Security Rule] ${rel}: Dynamic eval/Function is forbidden`);
      }
      if (/shell\s*:\s*true/.test(source) && !rel.startsWith('tests/') && !rel.startsWith('scripts/')) {
        errors.push(`[Lint Security Rule] ${rel}: shell: true is forbidden in subprocess execution (SEC-006)`);
      }
      if (/\bchild_process\b/.test(source) && /\bexec\s*\(/.test(source) && !rel.startsWith('tests/')) {
        errors.push(`[Lint Security Rule] ${rel}: Use execFile with shell: false instead of exec()`);
      }
    }

    // 3. For typecheck mode, also dynamically import non-test modules to verify module graph resolution
    if (
      mode === 'typecheck' &&
      !rel.startsWith('tests/') &&
      !rel.startsWith('scripts/') &&
      !rel.startsWith('apps/web/next.config.') &&
      !rel.startsWith('apps/web/src/middleware.') &&
      !rel.startsWith('apps/web/src/app/')
    ) {
      try {
        await import(pathToFileURL(file).href);
      } catch (err) {
        errors.push(`[Module Resolution Error] ${rel}: ${(err as Error).message}`);
      }
    }
  }

  // 4. Validate JSON schemas, demo fixtures, and runtime document schemas (HS-AUDIT-008)
  const jsonFiles = [
    'schemas/scope.schema.json',
    'schemas/finding.schema.json',
    'schemas/report.schema.json',
    'schemas/recheck.schema.json',
    'apps/worker/container-policy.json',
    'apps/worker/seccomp-profile.json',
    'apps/worker/source-offline-manifest.json',
    'examples/safe-demo/hegosentinel.scope.json',
    'examples/safe-demo/fixture-baseline.json',
    'examples/safe-demo/fixture-patched.json',
    'examples/synthetic-targets/recorded-scanner-outputs.json'
  ];

  for (const jf of jsonFiles) {
    try {
      JSON.parse(readFileSync(join(ROOT, jf), 'utf8'));
    } catch (err) {
      errors.push(`[JSON Validation Error] ${jf}: ${(err as Error).message}`);
    }
  }

  try {
    const scopeDoc = JSON.parse(
      readFileSync(join(ROOT, 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
    );
    const scopeDecision = validateScopeAuthorizationGrant(
      scopeDoc,
      new Date('2026-11-04T20:00:00.000Z')
    );
    if (!scopeDecision.allowed) {
      errors.push(`[Runtime Scope Schema Error] ${scopeDecision.detail}`);
    }
  } catch (err) {
    errors.push(`[Runtime Scope Schema Error] ${(err as Error).message}`);
  }

  for (const reportFile of ['reports/demo-baseline.json', 'reports/demo-patched.json']) {
    const fullPath = join(ROOT, reportFile);
    if (existsSync(fullPath)) {
      const parsed = JSON.parse(readFileSync(fullPath, 'utf8'));
      const check = validateScanReportDocument(parsed);
      if (!check.valid) {
        errors.push(`[Runtime ScanReport Schema Error] ${reportFile}: ${check.errors.join('; ')}`);
      }
    }
  }

  const recheckFile = join(ROOT, 'reports/demo-recheck.json');
  if (existsSync(recheckFile)) {
    const parsed = JSON.parse(readFileSync(recheckFile, 'utf8'));
    const check = validateRecheckReportDocument(parsed);
    if (!check.valid) {
      errors.push(
        `[Runtime RecheckReport Schema Error] reports/demo-recheck.json: ${check.errors.join('; ')}`
      );
    }
  }

  if (errors.length > 0) {
    console.error(`${mode.toUpperCase()} FAILED with ${errors.length} error(s):`);
    for (const e of errors) {
      console.error(`  - ${e}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    `[OK] ${mode.toUpperCase()} passed: verified ${tsFiles.length} TypeScript files, ${jsonFiles.length} JSON schema/fixture files, and runtime document contracts.`
  );
}

main();

