import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  buildTrustedProxyRequestFromWorkerPayload,
  BROKER_OUTBOUND_HEADER_ALLOWLIST,
  handleTrustedEgressBrokerHttpRequest,
  MAX_BROKER_RESPONSE_BYTES,
  MAX_BROKER_TIMEOUT_MS,
  sanitizeAuditText,
  sanitizeUrlForAudit,
  TrustedEgressBroker,
  type BrokerUpstreamTransport
} from '../../apps/egress-broker/src/index.ts';
import {
  generatePerRunNetworkPolicy,
  signRemoteExecutionGrant
} from '../../apps/worker/src/index.ts';
import type { ScopeAuthorizationGrant } from '../../packages/findings-schema/src/index.ts';
import type { DnsResolver } from '../../packages/policy-engine/src/index.ts';

const baseGrant = JSON.parse(
  readFileSync(resolve(process.cwd(), 'examples/safe-demo/hegosentinel.scope.json'), 'utf8')
) as ScopeAuthorizationGrant;

const resolver: DnsResolver = {
  async resolve4(hostname: string) {
    return hostname === 'demo.example.test' ? ['93.184.216.34'] : [];
  },
  async resolve6() {
    return [];
  }
};

const SIGNER = 'hegosentinel-control-plane-signer-v1';
const SECRET = 'b2-regression-signer-secret-2026';
const FIXED_NOW = new Date('2026-11-04T20:00:00.000Z');

async function makeBroker(runId: string) {
  const broker = new TrustedEgressBroker({ trustedSigners: { [SIGNER]: SECRET }, resolver });
  const net = await generatePerRunNetworkPolicy({ runId, grant: baseGrant, resolver, now: FIXED_NOW });
  assert.ok(net.policy);
  broker.registerPerRunNetworkPolicy(net.policy);
  const sign = (nonce: string, overrides: Record<string, unknown> = {}) =>
    signRemoteExecutionGrant(
      {
        signer_id: SIGNER,
        run_id: runId,
        organization_id: baseGrant.organization_id,
        project_id: baseGrant.project_id,
        grant_id: baseGrant.grant_id,
        scope_version: baseGrant.scope_version,
        target_scheme: 'https',
        target_host: 'demo.example.test',
        target_port: 443,
        target_path_prefix: '/',
        allowed_methods: ['GET', 'HEAD'],
        max_request_budget: 50,
        network_policy_id: net.policy!.policy_digest,
        emergency_stop_token_id: `ESTOP-${runId}`,
        nonce,
        issued_at: '2026-11-04T19:59:00.000Z',
        expires_at: '2026-11-04T20:03:00.000Z',
        ...overrides
      },
      SECRET
    );
  const request = (over: Record<string, unknown>) => ({
    requestId: 'REQ-B2',
    url: 'https://demo.example.test/',
    method: 'GET',
    scopeGrant: baseGrant,
    expectedRunId: runId,
    expectedOrganizationId: baseGrant.organization_id,
    expectedProjectId: baseGrant.project_id,
    expectedGrantId: baseGrant.grant_id,
    expectedScopeVersion: baseGrant.scope_version,
    expectedNetworkPolicyId: net.policy!.policy_digest,
    now: FIXED_NOW,
    ...over
  });
  return { broker, sign, request, policy: net.policy! };
}

const okTransport: BrokerUpstreamTransport = async (p) => ({
  statusCode: 200,
  headers: { 'content-type': 'text/html' },
  body: '<html lang="en">ok</html>',
  connectedSocketPeerIp: p.pinnedIp,
  tlsServername: 'demo.example.test'
});

const SECRET_TOKENS = [
  'top-secret-audit-value',
  'abcdef123456',
  'p@ssw0rd-value',
  'sk_live_REALLYSECRET',
  'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1rwW'
];

describe('Sprint 9 / B2 â€” Trusted Egress Broker evidence minimization (masking happens BEFORE the first log record)', () => {
  it('sanitizeUrlForAudit masks token/password/secret/code/api_key/session-like params, userinfo and fragments', () => {
    const url =
      'https://user:hunter2@demo.example.test/path/ok?page=2&lang=tr&token=top-secret-audit-value&password=p%40ssw0rd-value&secret=s3cr3t&code=abcdef123456' +
      '&api_key=sk_live_REALLYSECRET&apikey=zzz&access_token=aaa&refresh_token=bbb&client_secret=ccc&session=ddd&sid=eee&auth=fff&signature=ggg' +
      '&opaque=3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a#frag-with-secret';
    const out = sanitizeUrlForAudit(url);
    for (const leaked of ['top-secret-audit-value', 'p%40ssw0rd-value', 'p@ssw0rd-value', 's3cr3t', 'abcdef123456', 'sk_live_REALLYSECRET', 'zzz', 'aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff', 'ggg', 'hunter2', 'frag-with-secret', '3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a']) {
      assert.equal(out.includes(leaked), false, `leaked: ${leaked}`);
    }
    assert.ok(out.startsWith('https://demo.example.test/path/ok?'));
    assert.ok(out.includes('page=2') && out.includes('lang=tr'), 'benign short params stay useful for forensics');
    assert.ok(out.includes('token=[REDACTED]') && out.includes('api_key=[REDACTED]'));
    assert.equal(out.includes('#'), false);
    assert.equal(out.includes('@'), false);
  });

  it('sanitizeUrlForAudit / sanitizeAuditText neutralize malformed input, secrets in paths and log injection', () => {
    assert.equal(sanitizeUrlForAudit('javascript:alert(1)'), '[INVALID_URL]');
    assert.equal(sanitizeUrlForAudit('not a url'), '[INVALID_URL]');
    assert.equal(sanitizeUrlForAudit('https://demo.example.test/ghp_abcdefghijklmnopqrstuvwxyz0123456789').includes('ghp_abcdefghijklmnopqrstuvwxyz0123456789'), false);
    const text = sanitizeAuditText('line1\nline2|forged=1 Bearer abcdefghijklmnopqrstuvwxyz0123456789 see https://demo.example.test/x?token=zzz-secret');
    assert.equal(/[\r\n]/.test(text), false);
    assert.equal(text.includes('|'), false);
    assert.equal(text.includes('zzz-secret'), false);
    assert.equal(text.includes('abcdefghijklmnopqrstuvwxyz0123456789'), false);
  });

  it('NO secret survives in the audit log on ANY path (deny and allow) and the hash chain stays valid', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-LEAK');
    const secretUrl =
      'https://demo.example.test/?token=top-secret-audit-value&code=abcdef123456&password=p@ssw0rd-value&api_key=sk_live_REALLYSECRET&x=ghp_abcdefghijklmnopqrstuvwxyz0123456789';

    // 1. disallowed method
    await broker.executeBrokeredPassiveRequest(request({ url: secretUrl, method: 'POST', signedExecutionGrant: sign('nonce-b2-0001') }) as never, okTransport);
    // 2. out-of-scope host
    await broker.executeBrokeredPassiveRequest(request({ url: secretUrl.replace('demo.example.test', 'evil.example.test'), signedExecutionGrant: sign('nonce-b2-0002') }) as never, okTransport);
    // 3. unsigned grant
    await broker.executeBrokeredPassiveRequest(request({ url: secretUrl, signedExecutionGrant: {} }) as never, okTransport);
    // 4. transport error that echoes secrets in its message
    const errRes = await broker.executeBrokeredPassiveRequest(
      request({ url: secretUrl, signedExecutionGrant: sign('nonce-b2-0004') }) as never,
      async () => {
        throw new Error(`connect failed for ${secretUrl} with Authorization: Bearer ${SECRET_TOKENS[5]} and password=p@ssw0rd-value`);
      }
    );
    assert.equal(errRes.allowed, false);
    assert.equal(errRes.reason, 'upstream_transport_error');
    // 5. successful ALLOW
    const allow = await broker.executeBrokeredPassiveRequest(request({ url: secretUrl, signedExecutionGrant: sign('nonce-b2-0005') }) as never, okTransport);
    assert.equal(allow.allowed, true);

    const serialized = JSON.stringify(broker.getAuditLog());
    for (const s of SECRET_TOKENS) assert.equal(serialized.includes(s), false, `audit log leaked ${s.slice(0, 12)}â€¦`);
    const resultSerialized = JSON.stringify([errRes.detail, allow.detail, allow.auditEntry]);
    for (const s of SECRET_TOKENS) assert.equal(resultSerialized.includes(s), false, `returned result leaked ${s.slice(0, 12)}â€¦`);
    assert.equal(broker.verifyAuditLogIntegrity().valid, true);
    assert.equal(broker.getAuditLog().length, 5);
    // tamper-evidence is retained after sanitization
    const tampered = broker.getAuditLog()[0] as { detail: string };
    const original = tampered.detail;
    tampered.detail = original + ' tampered';
    assert.equal(broker.verifyAuditLogIntegrity().valid, false);
    tampered.detail = original;
    assert.equal(broker.verifyAuditLogIntegrity().valid, true);
  });

  it('log-injection through request identifiers cannot forge extra fields or lines', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-INJ');
    await broker.executeBrokeredPassiveRequest(
      request({ requestId: 'REQ\n2026|ALLOW|forged', signedExecutionGrant: sign('nonce-inj-0001'), method: 'POST' }) as never,
      okTransport
    );
    const entry = broker.getAuditLog()[0]!;
    assert.equal(/[\r\n|]/.test(entry.request_id), false);
    assert.equal(broker.verifyAuditLogIntegrity().valid, true);
  });
});

describe('Sprint 9 / B2 â€” outbound header allowlist (worker-supplied headers are never forwarded)', () => {
  it('forwards ONLY broker defaults + validated allowlisted headers; drops credentials, cookies, forwarding and arbitrary headers', async () => {
    assert.deepEqual([...BROKER_OUTBOUND_HEADER_ALLOWLIST].sort(), ['accept-language', 'x-custom-trace']);
    const { broker, sign, request } = await makeBroker('RUN-B2-HDR');
    let seen: Record<string, string> = {};
    const res = await broker.executeBrokeredPassiveRequest(
      request({
        signedExecutionGrant: sign('nonce-hdr-0001'),
        headers: {
          Authorization: 'Bearer worker-stolen-jwt-value-1234567890',
          'Proxy-Authorization': 'Basic abc',
          Cookie: 'sid=secret-cookie-value',
          'Set-Cookie': 'x=y',
          Origin: 'https://evil.example',
          Referer: 'https://internal.example/admin?token=zzz-referer-secret',
          Host: 'internal.example',
          'X-Forwarded-For': '10.0.0.1',
          'X-Real-IP': '10.0.0.2',
          'X-API-Key': 'k-123',
          'X-Internal-Admin': 'true',
          'User-Agent': 'worker-override',
          Accept: 'text/evil',
          'X-Custom-Trace': 'trace-1',
          'Accept-Language': 'tr-TR,tr;q=0.9'
        }
      }) as never,
      async (p) => {
        seen = p.sanitizedHeaders;
        return okTransport(p);
      }
    );
    assert.equal(res.allowed, true);
    assert.deepEqual(Object.keys(seen).sort(), ['accept', 'accept-language', 'user-agent', 'x-custom-trace']);
    assert.equal(seen['user-agent'].startsWith('HegoSentinel-Passive-Broker/'), true, 'worker cannot override the broker User-Agent');
    assert.equal(seen.accept.includes('evil'), false, 'worker cannot override Accept');
    assert.deepEqual(Object.keys(res.sanitizedRequestHeaders ?? {}).sort(), ['accept', 'accept-language', 'user-agent', 'x-custom-trace']);
    const log = JSON.stringify(broker.getAuditLog());
    for (const v of ['worker-stolen-jwt-value-1234567890', 'secret-cookie-value', 'zzz-referer-secret', 'k-123', 'internal.example']) {
      assert.equal(log.includes(v), false, `header VALUE ${v} must never be recorded`);
    }
    assert.ok(log.includes('dropped_request_headers=['), 'dropped header NAMES are recorded for forensics');
    assert.ok(log.includes('credential-class header from worker discarded'));
  });

  it('rejects malformed values of allowlisted headers (CRLF injection, oversized, secret-like, bad charset)', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-HDRV');
    const attempts: Array<Record<string, string>> = [
      { 'X-Custom-Trace': 'a\r\nInjected: 1' },
      { 'X-Custom-Trace': 'has space' },
      { 'X-Custom-Trace': 'x'.repeat(129) },
      { 'X-Custom-Trace': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
      { 'Accept-Language': 'en\r\nX-Evil: 1' },
      { 'Accept-Language': '<script>' }
    ];
    let i = 0;
    for (const headers of attempts) {
      let seen: Record<string, string> = {};
      const res = await broker.executeBrokeredPassiveRequest(
        request({ signedExecutionGrant: sign(`nonce-hv-000${i++}`), headers }) as never,
        async (p) => {
          seen = p.sanitizedHeaders;
          return okTransport(p);
        }
      );
      assert.equal(res.allowed, true);
      assert.deepEqual(Object.keys(seen).sort(), ['accept', 'user-agent'], `unsafe value must not be forwarded: ${JSON.stringify(headers)}`);
    }
  });
});

describe('Sprint 9 / B2 â€” redirects never carry sensitive data to another origin', () => {
  it('transport is told not to follow redirects; the Location returned to the worker has sensitive params masked; single upstream hop', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-REDIR');
    let hops = 0;
    let followFlag: unknown = 'unset';
    let forwarded: Record<string, string> = {};
    const res = await broker.executeBrokeredPassiveRequest(
      request({
        signedExecutionGrant: sign('nonce-redir-0001'),
        headers: { Authorization: 'Bearer should-never-reach-target-123456789', Referer: 'https://demo.example.test/?token=abc' }
      }) as never,
      async (p) => {
        hops += 1;
        followFlag = p.followRedirects;
        forwarded = p.sanitizedHeaders;
        return {
          statusCode: 302,
          headers: { location: 'https://demo.example.test/next?token=abc123secretvalue&code=zzz999&page=2#frag' },
          body: '',
          connectedSocketPeerIp: p.pinnedIp
        };
      }
    );
    assert.equal(hops, 1, 'the broker must not chase redirects itself');
    assert.equal(followFlag, false);
    assert.equal(Object.keys(forwarded).some((k) => ['authorization', 'referer', 'cookie', 'origin'].includes(k)), false);
    assert.equal(res.allowed, true);
    const location = String(res.response?.headers.location);
    assert.equal(location.includes('abc123secretvalue') || location.includes('zzz999') || location.includes('frag'), false);
    assert.ok(location.includes('token=[REDACTED]') && location.includes('page=2'));
    assert.equal(JSON.stringify(broker.getAuditLog()).includes('abc123secretvalue'), false);
  });

  it('relative Location values are masked too, and out-of-scope / metadata redirects are DROPPED with no secret in the log', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-REDIR2');
    const rel = await broker.executeBrokeredPassiveRequest(
      request({ signedExecutionGrant: sign('nonce-redir-0002') }) as never,
      async (p) => ({ statusCode: 301, headers: { Location: '/login?session=very-secret-session-id&next=%2F' }, body: '', connectedSocketPeerIp: p.pinnedIp })
    );
    assert.equal(rel.allowed, true);
    assert.equal(JSON.stringify(rel.response?.headers).includes('very-secret-session-id'), false);

    const out = await broker.executeBrokeredPassiveRequest(
      request({ signedExecutionGrant: sign('nonce-redir-0003') }) as never,
      async (p) => ({ statusCode: 302, headers: { location: 'https://169.254.169.254/latest/meta-data/?token=metadata-secret-token' }, body: '', connectedSocketPeerIp: p.pinnedIp })
    );
    assert.equal(out.allowed, false);
    assert.equal(JSON.stringify(broker.getAuditLog()).includes('metadata-secret-token'), false);
    assert.equal(JSON.stringify(out).includes('metadata-secret-token'), false);

    const crossOrigin = await broker.executeBrokeredPassiveRequest(
      request({ signedExecutionGrant: sign('nonce-redir-0004') }) as never,
      async (p) => ({ statusCode: 302, headers: { location: 'https://evil.example.test/steal?token=cross-origin-secret' }, body: '', connectedSocketPeerIp: p.pinnedIp })
    );
    assert.equal(crossOrigin.allowed, false);
    assert.equal(JSON.stringify(broker.getAuditLog()).includes('cross-origin-secret'), false);
  });
});

describe('Sprint 9 / B2 â€” signed grant, nonce, TTL and scope controls are preserved', () => {
  it('replay, expiry, wrong scope target, unsigned and unknown-signer grants are all still DROPPED', async () => {
    const { broker, sign, request } = await makeBroker('RUN-B2-CTRL');
    const grant = sign('nonce-ctrl-0001');
    assert.equal((await broker.executeBrokeredPassiveRequest(request({ signedExecutionGrant: grant }) as never, okTransport)).allowed, true);
    const replay = await broker.executeBrokeredPassiveRequest(request({ signedExecutionGrant: grant }) as never, okTransport);
    assert.equal(replay.allowed, false);

    const expired = await broker.executeBrokeredPassiveRequest(
      request({ signedExecutionGrant: sign('nonce-ctrl-0002'), now: new Date('2026-11-04T20:10:00.000Z') }) as never,
      okTransport
    );
    assert.equal(expired.allowed, false);

    const wrongHost = await broker.executeBrokeredPassiveRequest(
      request({ signedExecutionGrant: sign('nonce-ctrl-0003'), url: 'https://other.example.test/' }) as never,
      okTransport
    );
    assert.equal(wrongHost.allowed, false);

    assert.equal((await broker.executeBrokeredPassiveRequest(request({ signedExecutionGrant: undefined }) as never, okTransport)).allowed, false);
    const forged = sign('nonce-ctrl-0004', { signer_id: 'attacker-signer' });
    assert.equal((await broker.executeBrokeredPassiveRequest(request({ signedExecutionGrant: forged }) as never, okTransport)).allowed, false);

    broker.getEmergencyStopRegistry().cancelRun({ runId: 'RUN-B2-CTRL', cancelledBy: 'test', reason: 'regression' });
    const killed = await broker.executeBrokeredPassiveRequest(request({ signedExecutionGrant: sign('nonce-ctrl-0005') }) as never, okTransport);
    assert.equal(killed.allowed, false);
    assert.equal(killed.reason, 'scan_cancelled');
    assert.equal(broker.getBrokerMetrics().prohibitedAllowedCount, 0);
  });
});

describe('Sprint 9 / B2 â€” the HTTP daemon never trusts worker-supplied clock, environment or limits', () => {
  function mockHttp(options: Parameters<typeof handleTrustedEgressBrokerHttpRequest>[2]) {
    return async (method: string, url: string, headers: Record<string, string>, body?: unknown) => {
      const bodyStr = body !== undefined ? JSON.stringify(body) : '';
      const req = {
        method,
        url,
        headers,
        on(event: string, listener: (...args: unknown[]) => void) {
          if (event === 'data' && bodyStr) listener(bodyStr);
          if (event === 'end') listener();
          return this;
        }
      } as unknown as IncomingMessage;
      let status = 200;
      let raw = '{}';
      const res = {
        statusCode: 200,
        setHeader() {},
        writeHead(code: number) {
          status = code;
          return this;
        },
        end(d?: string) {
          if (d) raw = d;
          return this;
        }
      } as unknown as ServerResponse;
      await handleTrustedEgressBrokerHttpRequest(req, res, options);
      return { status, json: JSON.parse(raw) as Record<string, any> };
    };
  }

  it('an EXPIRED signed grant cannot be revived by a back-dated worker `now` (original PoC: ALLOW before, DROP now)', async () => {
    const { broker, sign, policy } = await makeBroker('RUN-B2-HTTP1');
    const control = 'b2-control-plane-secret-regression-2026';
    const http = mockHttp({ broker, controlPlaneSecret: control, upstreamTransport: okTransport });
    const expired = sign('nonce-http-0001'); // valid only 2026-11-04T19:59â€“20:03; real clock is later
    const res = await http('POST', '/v1/egress/fetch', {}, {
      requestId: 'H-1',
      url: 'https://demo.example.test/',
      method: 'GET',
      signedExecutionGrant: expired,
      scopeGrant: baseGrant,
      expectedRunId: 'RUN-B2-HTTP1',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedNetworkPolicyId: policy.policy_digest,
      now: '2026-11-04T20:00:00.000Z'
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.allowed, false);
  });

  it('worker-supplied timeoutMs / maxResponseBytes are clamped; now / env / signal are discarded', () => {
    const built = buildTrustedProxyRequestFromWorkerPayload({
      requestId: 'r',
      url: 'https://demo.example.test/',
      method: 'GET',
      signedExecutionGrant: {},
      scopeGrant: baseGrant,
      expectedRunId: 'RUN',
      expectedOrganizationId: 'o',
      expectedProjectId: 'p',
      expectedGrantId: 'g',
      expectedScopeVersion: 1,
      expectedNetworkPolicyId: 'n',
      timeoutMs: 9_999_999,
      maxResponseBytes: 9_999_999_999,
      now: '2000-01-01T00:00:00.000Z',
      env: { HTTP_PROXY: '', HTTPS_PROXY: '' },
      signal: { aborted: false }
    });
    assert.equal(built.timeoutMs, MAX_BROKER_TIMEOUT_MS);
    assert.equal(built.maxResponseBytes, MAX_BROKER_RESPONSE_BYTES);
    assert.equal('now' in built, false);
    assert.equal('env' in built, false);
    assert.equal('signal' in built, false);
    const negative = buildTrustedProxyRequestFromWorkerPayload({ timeoutMs: -5, maxResponseBytes: 'x' });
    assert.equal(negative.timeoutMs, 8_000);
    assert.equal(negative.maxResponseBytes, 262_144);
  });

  it('over HTTP: secret query / credential headers never reach the target or the audit endpoint; control endpoints stay authenticated', async () => {
    const { broker, policy } = await makeBroker('RUN-B2-HTTP2');
    const control = 'b2-control-plane-secret-regression-2026';
    let seen: Record<string, string> = {};
    let seenFollow: unknown;
    const http = mockHttp({
      broker,
      controlPlaneSecret: control,
      upstreamTransport: async (p) => {
        seen = p.sanitizedHeaders;
        seenFollow = p.followRedirects;
        return okTransport(p);
      }
    });
    const nowMs = Date.now();
    const live = signRemoteExecutionGrant(
      {
        signer_id: SIGNER,
        run_id: 'RUN-B2-HTTP2',
        organization_id: baseGrant.organization_id,
        project_id: baseGrant.project_id,
        grant_id: baseGrant.grant_id,
        scope_version: baseGrant.scope_version,
        target_scheme: 'https',
        target_host: 'demo.example.test',
        target_port: 443,
        target_path_prefix: '/',
        allowed_methods: ['GET', 'HEAD'],
        max_request_budget: 5,
        network_policy_id: policy.policy_digest,
        emergency_stop_token_id: 'ESTOP-HTTP2',
        nonce: 'nonce-http-live-0001',
        issued_at: new Date(nowMs - 60_000).toISOString(),
        expires_at: new Date(nowMs + 180_000).toISOString()
      },
      SECRET
    );
    const res = await http('POST', '/v1/egress/fetch', {}, {
      requestId: 'H-2',
      url: 'https://demo.example.test/?token=http-secret-value&page=1',
      method: 'GET',
      headers: { Authorization: 'Bearer http-worker-jwt-12345678901234567890', Cookie: 'sid=http-cookie-secret', 'X-Internal-Admin': '1' },
      signedExecutionGrant: live,
      scopeGrant: baseGrant,
      expectedRunId: 'RUN-B2-HTTP2',
      expectedOrganizationId: baseGrant.organization_id,
      expectedProjectId: baseGrant.project_id,
      expectedGrantId: baseGrant.grant_id,
      expectedScopeVersion: baseGrant.scope_version,
      expectedNetworkPolicyId: policy.policy_digest
    });
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(seen).sort(), ['accept', 'user-agent']);
    assert.equal(seenFollow, false);

    const noAuth = await http('GET', '/v1/egress/audit', {});
    assert.equal(noAuth.status, 403);
    const wrong = await http('GET', '/v1/egress/audit', { 'x-hegosentinel-control-secret': 'wrong-secret-value-0000000' });
    assert.equal(wrong.status, 403);
    const audit = await http('GET', '/v1/egress/audit', { 'x-hegosentinel-control-secret': control });
    assert.equal(audit.status, 200);
    const body = JSON.stringify(audit.json);
    for (const v of ['http-secret-value', 'http-worker-jwt', 'http-cookie-secret']) assert.equal(body.includes(v), false, `audit endpoint leaked ${v}`);
    assert.equal(audit.json.integrity.valid, true);
    assert.equal((await http('POST', '/v1/egress/kill-switch', {}, { runId: 'RUN-B2-HTTP2' })).status, 403);
    assert.equal((await http('POST', '/v1/egress/policy', {}, {})).status, 403);
  });
});
