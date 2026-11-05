const MAX_PROXY_BODY_BYTES = 1024 * 1024; // 1 MiB

function getApiUpstreamUrl(): string {
  const envUrl = process.env.HEGOSENTINEL_API_UPSTREAM_URL;
  if (typeof envUrl === 'string' && envUrl.trim().length > 0) {
    return envUrl.trim().replace(/\/$/, '');
  }
  return 'http://127.0.0.1:8000';
}

function hasDotSegmentTraversal(rawUrl: string, pathSegments: string[]): boolean {
  if (/(\.\.|%2e%2e)/i.test(rawUrl)) {
    return true;
  }
  return pathSegments.some((seg) => seg === '.' || seg === '..' || /%2e/i.test(seg));
}

async function handleApiV1Proxy(
  request: Request,
  context: { params: Promise<{ path?: string[] }> }
): Promise<Response> {
  const resolvedParams = await context.params;
  const pathSegments = resolvedParams.path ?? [];
  const reqUrl = new URL(request.url);

  if (hasDotSegmentTraversal(request.url, pathSegments)) {
    return Response.json(
      { ok: false, error: 'invalid_api_path', message: 'Path traversal segments are forbidden' },
      { status: 400 }
    );
  }

  let bodyText: string | undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const ab = await request.arrayBuffer();
    if (ab.byteLength > MAX_PROXY_BODY_BYTES) {
      return Response.json(
        { ok: false, error: 'payload_too_large', message: 'Request body exceeds 1 MiB limit' },
        { status: 413 }
      );
    }
    bodyText = new TextDecoder().decode(ab);
  }

  const forwardHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': request.headers.get('content-type') ?? 'application/json'
  };

  // Forward only legitimate Authorization / Cookie headers; NEVER forward X-Demo-Principal (Sprint 9 B1)
  const authHeader = request.headers.get('authorization');
  if (authHeader) {
    forwardHeaders.Authorization = authHeader;
  }
  const cookieHeader = request.headers.get('cookie');
  if (cookieHeader) {
    forwardHeaders.Cookie = cookieHeader;
  }

  const targetUrl = `${getApiUpstreamUrl()}/api/v1/${pathSegments.join('/')}${reqUrl.search}`;

  try {
    const upstreamRes = await fetch(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body: bodyText && bodyText.length > 0 ? bodyText : undefined,
      cache: 'no-store'
    });

    const responseText = await upstreamRes.text();
    const resHeaders = new Headers({
      'Content-Type': upstreamRes.headers.get('content-type') ?? 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    const setCookie = upstreamRes.headers.get('set-cookie');
    if (setCookie) {
      resHeaders.set('Set-Cookie', setCookie);
    }

    return new Response(responseText, {
      status: upstreamRes.status,
      headers: resHeaders
    });
  } catch (err) {
    return Response.json(
      {
        ok: false,
        error: 'upstream_unreachable',
        message: err instanceof Error ? err.message : 'Laravel 11 API upstream unreachable'
      },
      { status: 502 }
    );
  }
}

export async function GET(
  request: Request,
  context: { params: Promise<{ path?: string[] }> }
): Promise<Response> {
  return handleApiV1Proxy(request, context);
}

export async function POST(
  request: Request,
  context: { params: Promise<{ path?: string[] }> }
): Promise<Response> {
  return handleApiV1Proxy(request, context);
}

export async function PATCH(
  request: Request,
  context: { params: Promise<{ path?: string[] }> }
): Promise<Response> {
  return handleApiV1Proxy(request, context);
}

export async function DELETE(
  request: Request,
  context: { params: Promise<{ path?: string[] }> }
): Promise<Response> {
  return handleApiV1Proxy(request, context);
}
