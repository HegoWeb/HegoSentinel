import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

/**
 * Verifies that every relative Markdown link in the repository resolves to an existing file.
 * Usage: npm run docs:links   (exit code 1 on any broken link)
 */
const ROOT = resolve(process.cwd());
const SKIP_DIRS = new Set(['node_modules', 'vendor', '.next', '.git', '.tools', 'reports', 'HegoSentinel', '.playwright-mcp']);

function collect(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) collect(full, acc);
    else if (entry.endsWith('.md')) acc.push(full);
  }
  return acc;
}

const linkRe = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const broken: string[] = [];
let checked = 0;
for (const file of collect(ROOT)) {
  const text = readFileSync(file, 'utf8');
  // ignore fenced code blocks
  const stripped = text.replace(/```[\s\S]*?```/g, '');
  let m: RegExpExecArray | null;
  linkRe.lastIndex = 0;
  while ((m = linkRe.exec(stripped)) !== null) {
    const target = m[1] ?? '';
    if (/^(https?:|mailto:|#|\/\/|file:|tel:)/i.test(target)) continue;
    const pathPart = target.split('#')[0] ?? '';
    if (pathPart === '') continue;
    checked += 1;
    let decoded = pathPart;
    try {
      decoded = decodeURIComponent(pathPart);
    } catch {
      // keep raw
    }
    const resolved = resolve(dirname(file), decoded);
    if (!existsSync(resolved)) {
      broken.push(`${relative(ROOT, file).replace(/\\/g, '/')} -> ${target}`);
    }
  }
}

if (broken.length > 0) {
  console.error(`[FAIL] ${broken.length} broken relative Markdown link(s) (of ${checked} checked):`);
  for (const b of broken) console.error(`  - ${b}`);
  process.exitCode = 1;
} else {
  console.log(`[OK] All ${checked} relative Markdown links resolve.`);
}

