import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import { evaluateCspPolicySemantics, executeScan } from '../../packages/scanner-core/src/index.ts';
import {
  readJsonBody,
  renderWorkbenchCss,
  renderWorkbenchHtml,
  renderWorkbenchJs,
  setSecurityHeaders,
  validateLoopbackRequest,
  WORKBENCH_CSP_HEADER
} from '../../packages/scanner-core/src/server.ts';
import { compareScanReports } from '../../packages/recheck-engine/src/index.ts';
import { validateScanReportDocument, type ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';

function createMockRequestStream(chunks: string[]): IncomingMessage {
  const listeners: Record<string, Array<(arg?: unknown) => void>> = {};
  const mock = {
    headers: {},
    on(event: string, listener: (arg?: unknown) => void) {
      listeners[event] = listeners[event] ?? [];
      listeners[event].push(listener);
      if (event === 'end') {
        queueMicrotask(() => {
          for (const chunk of chunks) {
            for (const dataListener of listeners['data'] ?? []) {
              dataListener(chunk);
            }
          }
          for (const endListener of listeners['end'] ?? []) {
            endListener();
          }
        });
      }
      return mock;
    }
  };
  return mock as unknown as IncomingMessage;
}

const grant = JSON.parse(readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')) as ScopeAuthorizationGrant;
const url = 'https://demo.example.test/';
function fixture(setCookie: string) {
  return {
    fixture_id: 'COOKIE-IDENTITY-REGRESSION',
    description: 'Synthetic cookie evidence with stable HTML response',
    endpoints: [{url, method: 'GET' as const, status_code: 200,
      headers: {'content-type': 'text/html', 'content-security-policy': "default-src 'self'", 'set-cookie': [setCookie]}}]
  };
}

describe('Audit: evidence must prove the same cookie was fixed', () => {
  it('different secure cookie cannot prove remediation of the original vulnerable cookie', async () => {
    const before = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=abc; Path=/'), scanId:'COOKIE-A'});
    const after = await executeScan({grant, mode:'offline-fixture', fixture:fixture('new_cookie=xyz; Secure; HttpOnly; SameSite=Lax'), scanId:'COOKIE-B'});
    const result = compareScanReports(before.report, after.report);
    assert.equal(before.report.findings.some(f=>f.rule_id==='WEB-COOKIE-001'),true);
    assert.equal(result.counts.verified_fixed,0);
    assert.equal(result.items.find(i=>i.rule_id==='WEB-COOKIE-001')?.recheck_state,'no_longer_observed');
  });
  it('the same cookie with all valid attributes can verify remediation', async () => {
    const before = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=abc; Path=/'), scanId:'COOKIE-C'});
    const after = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=xyz; Secure; HttpOnly; SameSite=Strict'), scanId:'COOKIE-D'});
    const result = compareScanReports(before.report, after.report);
    assert.equal(result.items.find(i=>i.rule_id==='WEB-COOKIE-001')?.recheck_state,'verified_fixed');
    assert.equal(validateScanReportDocument(after.report).valid, true);
  });
  it('unknown SameSite attribute must not be accepted as a secure fix', async () => {
    const before = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=abc; Path=/'), scanId:'COOKIE-E'});
    const after = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=xyz; Secure; HttpOnly; SameSite=Unknown'), scanId:'COOKIE-F'});
    const result = compareScanReports(before.report, after.report);
    assert.equal(result.counts.verified_fixed,0);
    assert.equal(result.items.find(i=>i.rule_id==='WEB-COOKIE-001')?.recheck_state,'persistent');
  });
  it('__Host- cookie prefix with Domain attribute or non-root Path must not verify remediation', async () => {
    const before = await executeScan({grant, mode:'offline-fixture', fixture:fixture('__Host-session=abc; Path=/'), scanId:'COOKIE-G'});
    const after = await executeScan({
      grant,
      mode:'offline-fixture',
      fixture:fixture('__Host-session=xyz; Secure; HttpOnly; SameSite=Strict; Domain=demo.example.test; Path=/admin'),
      scanId:'COOKIE-H'
    });
    const result = compareScanReports(before.report, after.report);
    assert.equal(result.counts.verified_fixed, 0);
    assert.equal(result.items.find(i=>i.rule_id==='WEB-COOKIE-001')?.recheck_state, 'persistent');
  });
  it('duplicate SameSite attributes must not be accepted as a clean cookie remediation', async () => {
    const before = await executeScan({grant, mode:'offline-fixture', fixture:fixture('auth_session=abc; Path=/'), scanId:'COOKIE-I'});
    const after = await executeScan({
      grant,
      mode:'offline-fixture',
      fixture:fixture('auth_session=xyz; Secure; HttpOnly; SameSite=Strict; SameSite=Unknown'),
      scanId:'COOKIE-J'
    });
    const result = compareScanReports(before.report, after.report);
    assert.equal(result.counts.verified_fixed, 0);
    assert.equal(result.items.find(i=>i.rule_id==='WEB-COOKIE-001')?.recheck_state, 'persistent');
  });
});

describe('Audit: conservative CSP remediation evidence', () => {
  it('duplicate directives must not be marked enforcing (browser uses first directive)', () => {
    const r=evaluateCspPolicySemantics("default-src *; default-src 'self'");
    assert.equal(r.positiveValidationPassed,false);
  });
  it('a permissive script-src-elem override must not be marked enforcing', () => {
    const r=evaluateCspPolicySemantics("default-src 'self'; script-src-elem *");
    assert.equal(r.positiveValidationPassed,false);
  });
  it('a permissive script-src-attr override must not be marked enforcing', () => {
    const r=evaluateCspPolicySemantics("default-src 'self'; script-src-attr 'unsafe-inline'");
    assert.equal(r.positiveValidationPassed,false);
  });
  it('a narrow script policy remains accepted for deterministic demo verification', () => {
    assert.equal(evaluateCspPolicySemantics("default-src 'self'").positiveValidationPassed,true);
  });
});

describe('Audit: Local Workbench server hardening', () => {
  it('validateLoopbackRequest blocks DNS-rebinding Host headers and cross-origin POST requests', () => {
    const badHost = validateLoopbackRequest({
      method: 'GET',
      headers: { host: 'evil.example.test:4173' }
    } as unknown as IncomingMessage);
    assert.equal(badHost.allowed, false);

    const badOrigin = validateLoopbackRequest({
      method: 'POST',
      headers: { host: 'localhost:4173', origin: 'https://evil.example.test' }
    } as unknown as IncomingMessage);
    assert.equal(badOrigin.allowed, false);

    const validLoopback = validateLoopbackRequest({
      method: 'POST',
      headers: { host: '127.0.0.1:4173', origin: 'http://127.0.0.1:4173' }
    } as unknown as IncomingMessage);
    assert.equal(validLoopback.allowed, true);
  });

  it('readJsonBody rejects malformed JSON (400) and oversized payloads > 16 KB (413)', async () => {
    const malformedStream = createMockRequestStream(['{invalid-json']);
    const malformedRes = await readJsonBody(malformedStream);
    assert.equal(malformedRes.ok, false);
    assert.equal(malformedRes.statusCode, 400);

    const oversizedStream = createMockRequestStream(['a'.repeat(17000)]);
    const oversizedRes = await readJsonBody(oversizedStream);
    assert.equal(oversizedRes.ok, false);
    assert.equal(oversizedRes.statusCode, 413);
  });

  it('serves Workbench HTML/CSS/JS with enforcing CSP free of unsafe-inline', () => {
    const capturedHeaders: Record<string, string> = {};
    const mockRes = {
      setHeader(name: string, value: string) {
        capturedHeaders[name.toLowerCase()] = value;
      }
    } as unknown as ServerResponse;

    setSecurityHeaders(mockRes, 'text/html; charset=utf-8');
    const csp = capturedHeaders['content-security-policy'] ?? '';
    assert.equal(csp, WORKBENCH_CSP_HEADER);
    assert.equal(csp.includes("'unsafe-inline'"), false);
    const cspEval = evaluateCspPolicySemantics(csp);
    assert.equal(cspEval.positiveValidationPassed, true);

    const html = renderWorkbenchHtml();
    assert.equal(html.includes('<link rel="stylesheet" href="/workbench.css" />'), true);
    assert.equal(html.includes('<script src="/workbench.js" defer></script>'), true);
    assert.equal(html.includes('style="'), false);

    const css = renderWorkbenchCss();
    assert.equal(css.includes('--bg-obsidian: #050507'), true);

    const js = renderWorkbenchJs();
    assert.equal(js.includes("callApi('/api/demo'"), true);
  });
});
