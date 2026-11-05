export async function GET(): Promise<Response> {
  const body = [
    'User-agent: *',
    'Allow: /',
    'Disallow: /api/',
    'Sitemap: http://127.0.0.1:3000/sitemap.xml'
  ].join('\n');

  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

