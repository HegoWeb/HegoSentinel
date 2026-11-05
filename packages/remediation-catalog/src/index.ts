import type { RemediationGuidance, RuleId, StackTag } from '../../findings-schema/src/index.ts';

const CATALOG: Record<string, RemediationGuidance> = {
  'WEB-HEADER-001:csp': {
    summary:
      'Define a context-appropriate Content-Security-Policy, validate in Content-Security-Policy-Report-Only mode first, and enforce after verifying frontend asset compatibility.',
    owner_role: 'Frontend / Web Platform Engineer',
    framework_guides: [
      {
        framework: 'nextjs',
        prerequisites: 'Audit inline scripts, third-party analytics, font hosts, and image domains used by pages/app router.',
        steps: [
          'Configure response headers in next.config.js (or middleware.ts for nonce-based policies).',
          'Start with Content-Security-Policy-Report-Only: default-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'.',
          'Promote to Content-Security-Policy once zero legitimate browser console violations occur in staging.'
        ],
        side_effects:
          'Strict script-src without nonces or hashes can block Next.js hydration scripts or inline styles if deployed without Report-Only validation.'
      },
      {
        framework: 'laravel',
        prerequisites: 'Identify Blade inline scripts (@script), Vite asset origins, and any external form targets.',
        steps: [
          'Create an HTTP response middleware (e.g., app/Http/Middleware/SecurityHeadersMiddleware.php) and register it in bootstrap/app.php.',
          'Emit Content-Security-Policy-Report-Only during staging verification using Vite::useCspNonce() where inline scripts are needed.',
          'Switch header name to Content-Security-Policy and verify via HegoSentinel re-test.'
        ],
        side_effects:
          'Enforcing script-src \'self\' without nonce registration will block inline Blade scripts and Livewire/Alpine expressions.'
      }
    ]
  },
  'WEB-HEADER-001:general': {
    summary:
      'Emit baseline defensive HTTP response headers (X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, frame restrictions) on HTML/API responses.',
    owner_role: 'Frontend / Web Platform Engineer',
    framework_guides: [
      {
        framework: 'nextjs',
        prerequisites: 'Check whether any routes must be embedded in partner iframes before setting X-Frame-Options: DENY.',
        steps: [
          'Add X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, and Permissions-Policy: camera=(), microphone=(), geolocation=() in next.config.js headers().'
        ],
        side_effects: 'Setting X-Frame-Options: DENY blocks legitimate cross-origin iframe embedding.'
      },
      {
        framework: 'laravel',
        prerequisites: 'Verify reverse proxy (Nginx/Cloudflare) does not duplicate or overwrite application headers.',
        steps: [
          'Set $response->headers->set(\'X-Content-Type-Options\', \'nosniff\') and Referrer-Policy in your global web middleware group.'
        ],
        side_effects: 'Restrictive Referrer-Policy values may omit full path referrers required by some legacy analytics tools.'
      }
    ]
  },
  'WEB-COOKIE-001': {
    summary:
      'Ensure session and authentication cookies include Secure, HttpOnly, and an explicit SameSite attribute matching the application authentication topology.',
    owner_role: 'Backend / Authentication Engineer',
    framework_guides: [
      {
        framework: 'laravel',
        prerequisites: 'Confirm HTTPS termination and TrustProxies middleware configuration so Laravel detects HTTPS requests accurately.',
        steps: [
          'In config/session.php, set \'secure\' => env(\'SESSION_SECURE_COOKIE\', true), \'http_only\' => true, and \'same_site\' => \'lax\' (or \'strict\').',
          'Ensure SESSION_SECURE_COOKIE=true in production .env and re-test login flow over HTTPS.'
        ],
        side_effects:
          'SameSite=Strict can prevent session cookies from being sent on top-level cross-site OAuth/SAML redirect callbacks; use Lax for standard web flows.'
      },
      {
        framework: 'nextjs',
        prerequisites: 'Review Route Handlers / Server Actions setting cookies via next/headers cookies().set().',
        steps: [
          'Pass { httpOnly: true, secure: process.env.NODE_ENV === \'production\', sameSite: \'lax\', path: \'/\' } whenever setting session cookies.'
        ],
        side_effects:
          'HttpOnly cookies cannot be read by client-side document.cookie scripts; ensure client UI uses server session state instead.'
      }
    ]
  },
  'WEB-TLS-001': {
    summary:
      'Enforce valid TLS certificates, minimum TLS 1.2/1.3 protocol versions, and Strict-Transport-Security (HSTS) on HTTPS endpoints.',
    owner_role: 'Infrastructure / Platform Engineer',
    framework_guides: [
      {
        framework: 'generic-web',
        prerequisites: 'Verify all subdomains and automated certificate renewal (ACME/Let\'s Encrypt) before enabling HSTS includeSubDomains.',
        steps: [
          'Configure TLS termination to allow TLSv1.2 and TLSv1.3 only.',
          'Emit Strict-Transport-Security: max-age=31536000; includeSubDomains after confirming HTTPS stability.'
        ],
        side_effects:
          'Enabling HSTS with includeSubDomains will cause browsers to block any internal or legacy HTTP-only subdomains.'
      }
    ]
  },
  'WEB-REDIRECT-001': {
    summary:
      'Prevent HTTPS-to-HTTP protocol downgrades and restrict redirect targets to an explicit allowlist of relative paths or authorized origins.',
    owner_role: 'Backend / Platform Engineer',
    framework_guides: [
      {
        framework: 'laravel',
        prerequisites: 'Check TrustProxies configuration so X-Forwarded-Proto is honored from trusted load balancers only.',
        steps: [
          'Use URL::forceScheme(\'https\') in AppServiceProvider::boot() for production environments.',
          'Replace raw redirect($request->input(\'next\')) calls with relative-path validation.'
        ],
        side_effects: 'Rejecting external redirect URLs may affect unallowlisted third-party SSO return flows.'
      },
      {
        framework: 'nextjs',
        prerequisites: 'Inspect middleware.ts and next.config.js redirects() rules.',
        steps: [
          'Ensure redirects preserve https:// and validate any callbackUrl query parameter against allowed relative paths.'
        ],
        side_effects: 'None when limited to internal relative paths.'
      }
    ]
  },
  'CODE-001': {
    summary:
      'Refactor unsafe source-code patterns identified by static analysis using parameterized APIs and context-aware output encoding.',
    owner_role: 'Application Developer',
    framework_guides: [
      {
        framework: 'laravel',
        prerequisites: 'Review the flagged file and line in context to confirm whether untrusted input reaches the sink.',
        steps: [
          'Replace raw Blade {!! $val !!} with escaped {{ $val }}, and replace unparameterized DB::raw() concatenations with bound parameters.'
        ],
        side_effects: 'Escaping HTML strings that intentionally contain trusted CMS markup requires an explicit HTML sanitizer.'
      },
      {
        framework: 'nextjs',
        prerequisites: 'Check whether dangerouslySetInnerHTML or dynamic eval/Function receives user-controlled props.',
        steps: [
          'Remove dangerouslySetInnerHTML or sanitize input with a strict allowlist sanitizer before rendering.'
        ],
        side_effects: 'Stripping disallowed tags may alter rich-text formatting if not configured for expected tags.'
      }
    ]
  },
  'DEP-001': {
    summary:
      'Upgrade affected dependency packages in lockfiles to patched versions and verify application test suites.',
    owner_role: 'Application Maintainer',
    framework_guides: [
      {
        framework: 'nextjs',
        prerequisites: 'Check whether the vulnerable package is a runtime dependency or build/dev-only dependency.',
        steps: [
          'Update package.json / package-lock.json to the fixed version reported in the advisory and run unit/integration tests.'
        ],
        side_effects: 'Major version upgrades may introduce breaking API changes; prefer minimum patched semver releases.'
      },
      {
        framework: 'laravel',
        prerequisites: 'Review composer.lock advisory details and PHP version compatibility.',
        steps: [
          'Run composer update vendor/package --with-dependencies in a development environment and commit the updated composer.lock.'
        ],
        side_effects: 'Transitive dependency updates should be validated against the test suite before deployment.'
      }
    ]
  }
};

export function getRemediationGuidance(
  ruleId: RuleId,
  subKey: 'csp' | 'general' | 'default' = 'default',
  preferredStacks: StackTag[] = ['laravel', 'nextjs']
): RemediationGuidance {
  const lookupKey =
    ruleId === 'WEB-HEADER-001'
      ? `WEB-HEADER-001:${subKey === 'csp' ? 'csp' : 'general'}`
      : ruleId;
  const base = CATALOG[lookupKey] ?? CATALOG['WEB-HEADER-001:general'];

  const filteredGuides = base.framework_guides.filter(
    (g) => preferredStacks.includes(g.framework) || g.framework === 'generic-web'
  );

  return {
    summary: base.summary,
    owner_role: base.owner_role,
    framework_guides: filteredGuides.length > 0 ? filteredGuides : base.framework_guides
  };
}

