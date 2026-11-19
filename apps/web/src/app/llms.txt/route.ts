export async function GET(): Promise<Response> {
  const text = [
    '# HegoSentinel Security Platform (Sprint 10 Production Architecture)',
    '> Self-hosted, authorization-first security assessment, evidence normalization, developer remediation, and re-test verification platform.',
    '',
    '- Stack: Next.js 15 App Router + React 19 + Laravel 11 API + PostgreSQL 16 (RLS) + Redis 7 / Horizon + Isolated Docker Worker Supervisor',
    '- Scanners: Real Semgrep CE 1.183.0 & Trivy 0.76.1',
    '- Remote Scanning: Fail-Closed by Default (restricted-remote disabled)'
  ].join('\n');

  return new Response(text, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

