export async function GET(): Promise<Response> {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 36">
  <rect width="36" height="36" rx="4" fill="#050507" stroke="#d4ff33" stroke-width="2"/>
  <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#d4ff33" font-family="monospace" font-weight="bold" font-size="15">HS</text>
</svg>`;

  return new Response(svg, {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

