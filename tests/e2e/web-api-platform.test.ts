import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import { PLATFORM_I18N } from '../../apps/web/src/lib/i18n.ts';
import {
  handleWebPlatformRequest,
  isDemoModeEnabled,
  renderPlatformAppDocument
} from '../../apps/web/src/server.ts';

function invokeWebRoute(url: string): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
} {
  let statusCode = 200;
  const headers: Record<string, string> = {};
  let body = '';

  const req = {
    url,
    method: 'GET',
    headers: {}
  } as unknown as IncomingMessage;

  const res = {
    setHeader(name: string, value: string) {
      headers[name.toLowerCase()] = value;
    },
    writeHead(code: number, hdrs?: Record<string, string>) {
      statusCode = code;
      if (hdrs) {
        for (const [k, v] of Object.entries(hdrs)) {
          headers[k.toLowerCase()] = v;
        }
      }
    },
    end(chunk?: string) {
      if (chunk) body += chunk;
    }
  } as unknown as ServerResponse;

  handleWebPlatformRequest(req, res);
  return { statusCode, headers, body };
}

describe('Sprint 8 â€” Full Web Platform (apps/web) & Laravel API (apps/api) E2E Suite', () => {
  it('renders all 9 platform screens, bilingual TR/EN dictionaries, and dark obsidian design tokens', () => {
    const html = renderPlatformAppDocument();

    const requiredScreenIds = [
      'id="screen-dashboard"',
      'id="screen-projects"',
      'id="screen-scanner"',
      'id="screen-vulnerabilities"',
      'id="screen-remediation"',
      'id="screen-rechecks"',
      'id="screen-reports"',
      'id="screen-settings"',
      'id="screen-auth"'
    ];
    for (const screenId of requiredScreenIds) {
      assert.ok(html.includes(screenId), `Expected web platform document to contain ${screenId}`);
    }

    assert.ok(html.includes('<meta name="color-scheme" content="dark" />'));
    assert.ok(html.includes('application/ld+json'));
    assert.ok(html.includes('#d4ff33'));
    assert.ok(html.includes('RESTRICTED-REMOTE: KAPALI (FAIL-CLOSED)'));

    assert.equal(typeof PLATFORM_I18N.tr.dashboard.title, 'string');
    assert.equal(typeof PLATFORM_I18N.en.dashboard.title, 'string');
  });

  it('serves /, /robots.txt, /sitemap.xml, and /llms.txt with hardened security headers', () => {
    const homeRes = invokeWebRoute('/');
    assert.equal(homeRes.statusCode, 200);
    assert.equal(homeRes.headers['x-content-type-options'], 'nosniff');
    assert.equal(homeRes.headers['x-frame-options'], 'DENY');

    const robotsRes = invokeWebRoute('/robots.txt');
    assert.equal(robotsRes.statusCode, 200);
    assert.ok(robotsRes.body.includes('Sitemap:'));

    const sitemapRes = invokeWebRoute('/sitemap.xml');
    assert.equal(sitemapRes.statusCode, 200);
    assert.ok(sitemapRes.body.includes('<urlset'));

    const llmsRes = invokeWebRoute('/llms.txt');
    assert.equal(llmsRes.statusCode, 200);
    assert.ok(llmsRes.body.includes('# HegoSentinel Security Platform'));
  });

  it('passes all 36 Laravel API (apps/api) 14-module & SEC-011/012/013 integration assertions', async () => {
    const phpCandidate = existsSync('C:\\xampp\\php\\php.exe')
      ? 'C:\\xampp\\php\\php.exe'
      : 'php';
    const testScript = resolve(process.cwd(), 'apps/api/tests/run-api-tests.php');

    const output = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFile(
        phpCandidate,
        [testScript],
        {
          shell: false,
          timeout: 60_000,
          maxBuffer: 4 * 1024 * 1024
        },
        (err, stdout, stderr) => {
          if (err) {
            rejectPromise(new Error(`API test runner failed: ${err.message}\n${stdout}\n${stderr}`));
            return;
          }
          resolvePromise(stdout);
        }
      );
    });

    assert.ok(output.includes('0 failed'), `Expected 0 failed API tests, got:\n${output}`);
    assert.ok(output.includes('36 passed'));
  });

  it('Sprint 9 B1: API security regression suite (production/dev/test modes, BOLA, RBAC, traversal, throttle) has 0 failures', async () => {
    const phpCandidate = existsSync('C:\\xampp\\php\\php.exe') ? 'C:\\xampp\\php\\php.exe' : 'php';
    const testScript = resolve(process.cwd(), 'apps/api/tests/run-security-regression-tests.php');
    const output = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFile(
        phpCandidate,
        [testScript],
        { shell: false, timeout: 120_000, maxBuffer: 4 * 1024 * 1024 },
        (err, stdout, stderr) => {
          if (err) {
            rejectPromise(new Error(`API security regression runner failed: ${err.message}\n${stdout}\n${stderr}`));
            return;
          }
          resolvePromise(stdout);
        }
      );
    });
    assert.ok(output.includes('0 failed'), `Expected 0 failed, got:\n${output}`);
    assert.match(output, /Sprint 9 Security Regression Summary: (\d+) passed, 0 failed/);
    assert.equal(output.includes('[FAIL]'), false);
  });
});

describe('Sprint 9 B1 — web platform never carries or forwards client-controlled identity', () => {
  it('isDemoModeEnabled is operator-environment only and hard-off in production', () => {
    assert.equal(isDemoModeEnabled({}), false);
    assert.equal(isDemoModeEnabled({ HEGOSENTINEL_DEMO_MODE: '1', NODE_ENV: 'production' }), false);
    assert.equal(isDemoModeEnabled({ HEGOSENTINEL_DEMO_MODE: '1', APP_ENV: 'production' }), false);
    assert.equal(isDemoModeEnabled({ HEGOSENTINEL_DEMO_MODE: 'true' }), false);
    assert.equal(isDemoModeEnabled({ HEGOSENTINEL_DEMO_MODE: '1', NODE_ENV: 'development' }), true);
  });

  it('default (production-safe) HTML contains no demo credentials, no demo personas and no X-Demo-Principal', () => {
    const html = renderPlatformAppDocument();
    assert.equal(html.includes('HegoSentinel!2026'), false);
    assert.equal(html.includes('X-Demo-Principal'), false);
    assert.equal(html.includes('demoPrincipal'), false);
    assert.ok(html.includes('const DEMO_MODE = false;'));
    assert.equal(/id="login-email"[^>]*value="admin@hegoweb\.local"/.test(html), false);
  });

  it('demo HTML (explicit demoMode:true) prefills demo credentials but still never sends X-Demo-Principal', () => {
    const html = renderPlatformAppDocument({ demoMode: true });
    assert.ok(html.includes('const DEMO_MODE = true;'));
    assert.equal(html.includes('X-Demo-Principal'), false);
  });

  it('the /api/v1 proxy drops X-Demo-Principal, forwards only Authorization, and rejects dot-segment escapes and oversized bodies', async () => {
    const realFetch = globalThis.fetch;
    const calls: Array<{ url: string; headers: Record<string, string> }> = [];
    globalThis.fetch = (async (url: string, init?: { headers?: Record<string, string> }) => {
      calls.push({ url: String(url), headers: { ...(init?.headers ?? {}) } });
      return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    function proxyCall(url: string, headers: Record<string, string>, bodyChunks: string[] = []) {
      let statusCode = 0;
      let body = '';
      const done = new Promise<void>((resolveDone) => {
        const req = Object.assign(new EventEmitter(), { url, method: 'GET', headers }) as unknown as IncomingMessage;
        const res = {
          setHeader() {},
          writeHead(code: number) {
            statusCode = code;
          },
          end(chunk?: string) {
            if (chunk) body += chunk;
            resolveDone();
          }
        } as unknown as ServerResponse;
        handleWebPlatformRequest(req, res, { apiUpstreamUrl: 'http://127.0.0.1:8000' });
        for (const chunk of bodyChunks) (req as unknown as EventEmitter).emit('data', chunk);
        (req as unknown as EventEmitter).emit('end');
      });
      return done.then(() => ({ statusCode, body }));
    }

    try {
      const ok = await proxyCall('/api/v1/auth/me', { 'x-demo-principal': 'usr-owner-01', authorization: 'Bearer hst_abc' });
      assert.equal(ok.statusCode, 200);
      const sent = calls.at(-1)!.headers;
      assert.equal(Object.keys(sent).some((k) => k.toLowerCase() === 'x-demo-principal'), false);
      assert.equal(sent.Authorization, 'Bearer hst_abc');

      const callsBefore = calls.length;
      const escape1 = await proxyCall('/api/v1/%2e%2e/%2e%2e/admin', {});
      const escape2 = await proxyCall('/api/v1/../health', {});
      assert.equal(escape1.statusCode, 400);
      assert.equal(escape2.statusCode, 400);
      assert.equal(calls.length, callsBefore, 'escaped paths must never reach the upstream');

      const big = await proxyCall('/api/v1/auth/login', {}, ['x'.repeat(1024 * 1024 + 10)]);
      assert.equal(big.statusCode, 413);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
