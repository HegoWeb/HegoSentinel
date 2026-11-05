export interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface AuthenticatedPrincipal {
  user_id: string;
  email: string;
  name: string;
  preferred_locale: 'tr' | 'en';
  mfa_enabled: boolean;
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  verified_notification_domains: string[];
  role: 'owner' | 'security_lead' | 'developer' | 'viewer';
  project_ids: string[];
}

export class HegoSentinelApiClient {
  private readonly baseUrl: string;
  private token: string | null = null;

  constructor(baseUrl = '') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  public setSessionToken(token: string | null): void {
    this.token = token;
  }

  public async request<T>(
    method: 'GET' | 'POST' | 'PATCH',
    path: string,
    body?: Record<string, unknown>
  ): Promise<ApiEnvelope<T>> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    const json = (await res.json()) as ApiEnvelope<T>;
    return json;
  }
}

