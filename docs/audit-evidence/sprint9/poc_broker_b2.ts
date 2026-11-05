// B2 PoC — runs against ANY checkout root (HEAD copy = "before", working tree = "after").
// Usage: node --experimental-strip-types poc_broker_b2.ts <repoRootAbsolutePath>
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

const root = process.argv[2];
if (!root) throw new Error('repo root argument required');
const imp = (p: string) => import(pathToFileURL(`${root}/${p}`).href);
const broker = await imp('apps/egress-broker/src/index.ts');
const worker = await imp('apps/worker/src/index.ts');
const grant = JSON.parse(readFileSync(`${root}/examples/safe-demo/hegosentinel.scope.json`, 'utf8'));

const resolver = { async resolve4(h: string) { return h === 'demo.example.test' ? ['93.184.216.34'] : []; }, async resolve6() { return []; } };
const signerSecret = 'poc-signer-secret-for-b2-regression-2026';
const controlSecret = 'poc-control-plane-secret-b2-2026';
const b = new broker.TrustedEgressBroker({ trustedSigners: { 'hegosentinel-control-plane-signer-v1': signerSecret }, resolver });
const seen: Array<{ url: string; headers: Record<string, string>; followRedirects?: unknown }> = [];
const options = {
  broker: b,
  controlPlaneSecret: controlSecret,
  upstreamTransport: async (p: { url: string; pinnedIp: string; sanitizedHeaders: Record<string, string>; followRedirects?: unknown }) => {
    seen.push({ url: p.url, headers: p.sanitizedHeaders, followRedirects: p.followRedirects });
    return { statusCode: 200, headers: { 'content-type': 'text/html' }, body: '<html lang="en">ok</html>', connectedSocketPeerIp: p.pinnedIp };
  }
};

async function http(method: string, url: string, headers: Record<string, string>, body?: unknown) {
  const bodyStr = body !== undefined ? JSON.stringify(body) : '';
  const req: any = { method, url, headers, on(ev: string, l: (...a: unknown[]) => void) { if (ev === 'data' && bodyStr) l(bodyStr); if (ev === 'end') l(); return this; } };
  let status = 200; let raw = '{}';
  const res: any = { statusCode: 200, setHeader() {}, writeHead(c: number) { status = c; return this; }, end(d?: string) { if (d) raw = d; return this; } };
  await broker.handleTrustedEgressBrokerHttpRequest(req, res, options);
  return { status, json: JSON.parse(raw) };
}

const policyRes = await worker.generatePerRunNetworkPolicy({ runId: 'RUN-B2-POC', grant, resolver, now: new Date() });
await http('POST', '/v1/egress/policy', { 'x-hegosentinel-control-secret': controlSecret }, policyRes.policy);

function signed(nonce: string, issued: string, expires: string) {
  return worker.signRemoteExecutionGrant({
    signer_id: 'hegosentinel-control-plane-signer-v1', run_id: 'RUN-B2-POC',
    organization_id: grant.organization_id, project_id: grant.project_id, grant_id: grant.grant_id, scope_version: grant.scope_version,
    target_scheme: 'https', target_host: 'demo.example.test', target_port: 443, target_path_prefix: '/',
    allowed_methods: ['GET', 'HEAD'], max_request_budget: 50, network_policy_id: policyRes.policy.policy_digest,
    emergency_stop_token_id: 'ESTOP-B2-POC', nonce, issued_at: issued, expires_at: expires
  }, signerSecret);
}
const common = {
  scopeGrant: grant, expectedRunId: 'RUN-B2-POC', expectedOrganizationId: grant.organization_id, expectedProjectId: grant.project_id,
  expectedGrantId: grant.grant_id, expectedScopeVersion: grant.scope_version, expectedNetworkPolicyId: policyRes.policy.policy_digest
};

const results: Record<string, unknown> = {};

// 1) Expired grant + back-dated worker-supplied clock
const expired = signed('nonce-expired-1', '2026-11-04T19:59:00.000Z', '2026-11-04T20:03:00.000Z');
const r1 = await http('POST', '/v1/egress/fetch', {}, { requestId: 'POC-1', url: 'https://demo.example.test/', method: 'GET', signedExecutionGrant: expired, ...common, now: '2026-11-04T20:00:00.000Z' });
results.expired_grant_with_backdated_now = { http_status: r1.status, allowed: r1.json.allowed, reason: r1.json.reason };

// 2) Valid grant: header smuggling + secret query string + oversize limits
const nowMs = Date.now();
const fresh = signed('nonce-fresh-1', new Date(nowMs - 60_000).toISOString(), new Date(nowMs + 180_000).toISOString());
seen.length = 0;
const r2 = await http('POST', '/v1/egress/fetch', {}, {
  requestId: 'POC-2', url: 'https://demo.example.test/?token=top-secret-audit-value&code=abcdef&page=2', method: 'GET',
  headers: { Authorization: 'Bearer worker-stolen-jwt', Cookie: 'sid=secret', Origin: 'https://evil.example', Referer: 'https://internal/admin?token=zzz', 'X-Internal-Admin': 'true', 'X-Custom-Trace': 'trace-1' },
  signedExecutionGrant: fresh, ...common, maxResponseBytes: 9_999_999_999, timeoutMs: 9_999_999
});
const forwarded = seen[0]?.headers ?? {};
results.valid_grant_request = { http_status: r2.status, allowed: r2.json.allowed };
results.forwarded_headers_to_target = Object.keys(forwarded).sort();
results.forwarded_unapproved_header = ['authorization', 'cookie', 'origin', 'referer', 'x-internal-admin'].filter((h) => h in forwarded);
results.transport_followRedirects = seen[0]?.followRedirects ?? 'not-provided';

const audit = (await http('GET', '/v1/egress/audit', { 'x-hegosentinel-control-secret': controlSecret })).json;
const serialized = JSON.stringify(audit.entries);
results.audit_contains_secret_query_value = /top-secret-audit-value|abcdef/.test(serialized);
results.audit_contains_credential_header_values = /worker-stolen-jwt|sid=secret|zzz/.test(serialized);
results.audit_sample_target_url = audit.entries[audit.entries.length - 1]?.target_url;
results.audit_chain_valid = audit.integrity.valid;
console.log(JSON.stringify(results, null, 2));
