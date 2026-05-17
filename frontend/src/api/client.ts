/**
 * client.ts — thin fetch wrapper with in-memory CSRF token storage.
 * Extended in with typed apiFetch<T>, AuthError, and ApiError.
 */

let csrfTokenInMemory: string | null = null;

export function setCsrfToken(t: string | null) {
  csrfTokenInMemory = t;
}

export function getCsrfToken(): string | null {
  return csrfTokenInMemory;
}

export function isAuthenticated(): boolean {
  return csrfTokenInMemory !== null;
}

// primeCsrfFromCookie reads osctrl_csrf out of document.cookie and seeds
// csrfTokenInMemory. Called once on app boot (main.tsx). Necessary
// because the federated-login (OIDC) flow finishes with a server-side
// 302 to "/" — the SPA bootstraps fresh, the in-memory CSRF token is
// null even though the cookie IS set, so isAuthenticated() would
// incorrectly return false and the router would bounce to /login.
//
// The password-login path goes through login() below, which calls
// setCsrfToken() directly from the JSON response body. The cookie is
// the same value; reading either source yields the same result.
//
// osctrl_csrf is intentionally NOT HttpOnly (the SPA needs to read it
// for X-CSRF-Token headers). osctrl_token IS HttpOnly and is not read
// here — its presence is inferred from osctrl_csrf via the dual-cookie
// pattern the API uses.
export function primeCsrfFromCookie(): void {
  // No-op during SSR / non-browser environments.
  if (typeof document === 'undefined') {
    return;
  }
  for (const c of document.cookie.split(';')) {
    const [rawName, ...rest] = c.trim().split('=');
    if (rawName === 'osctrl_csrf' && rest.length > 0) {
      const value = rest.join('=');
      if (value !== '') {
        csrfTokenInMemory = value;
      }
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Typed error classes
// ---------------------------------------------------------------------------

/** Thrown when the server returns 401. The router catches this and redirects to /login. */
export class AuthError extends Error {
  readonly status = 401;
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'AuthError';
  }
}

/** Thrown for non-2xx responses other than 401. */
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// ---------------------------------------------------------------------------
// Generic typed fetch helper
// ---------------------------------------------------------------------------

const MUTATING_VERBS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();

  const headers = new Headers(init.headers);
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  const csrf = getCsrfToken();
  if (MUTATING_VERBS.has(method) && csrf) {
    headers.set('X-CSRF-Token', csrf);
  }

  const res = await fetch(path, {
    credentials: 'include',
    ...init,
    method,
    headers,
  });

  if (res.status === 401) {
    // Clear in-memory auth state so subsequent renders treat us as unauthenticated.
    setCsrfToken(null);
    throw new AuthError();
  }

  if (!res.ok) {
    let errorMsg = `Request failed with status ${res.status}`;
    let code: string | undefined;
    try {
      const body = (await res.json()) as { error?: string; code?: string };
      if (body.error) errorMsg = body.error;
      code = body.code;
    } catch {
      // response wasn't JSON — keep default message
    }
    throw new ApiError(errorMsg, res.status, code);
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

export interface LoginRequest {
  username: string;
  password: string;
  exp_hours?: number;
}

export interface LoginResponse {
  /**
   * JWT bearer token returned for CLI and non-browser callers. The SPA does
   * NOT use this — authentication for SPA requests rides on the HttpOnly
   * `osctrl_token` cookie set by the same /login response. Do not send this
   * value as an Authorization header from the browser.
   */
  token: string;
  /** CSRF token; sent as the `X-CSRF-Token` header on mutating requests. */
  csrf_token: string;
}

interface LegacyApiError {
  error: string;
  code?: string;
}

export async function login(env: string, body: LoginRequest): Promise<LoginResponse> {
  const res = await fetch(`/api/v1/login/${encodeURIComponent(env)}`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({ error: 'login failed' }))) as LegacyApiError;
    throw new Error(err.error || 'Login failed. Please try again.');
  }
  const data = (await res.json()) as LoginResponse;
  // token is for CLI callers; the SPA authenticates via the HttpOnly cookie.
  // We only need the CSRF token for subsequent mutating requests.
  setCsrfToken(data.csrf_token);
  return data;
}

/** Shape returned by GET /api/v1/login/environments — pre-auth, name+uuid only. */
export interface LoginEnvironment {
  uuid: string;
  name: string;
}

/**
 * Pre-auth env list for the login screen dropdown.
 *
 * Does NOT go through apiFetch / the auth-aware client wrappers because:
 *   - The endpoint is intentionally unauthenticated.
 *   - The 401-→-redirect-to-login behaviour those wrappers add would create a
 *     redirect loop if it ever returned 401 (it can't, but: belt-and-braces).
 */
export async function listLoginEnvironments(): Promise<LoginEnvironment[]> {
  const res = await fetch('/api/v1/login/environments', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to load environments (HTTP ${res.status})`);
  }
  return (await res.json()) as LoginEnvironment[];
}

// AuthMethod mirrors the API's AuthMethod shape. `type` is the
// discriminator; the SPA renders a different control per type.
//   "password" — the existing username/password form
//   "oidc"     — a "Continue with SSO" button linking to LoginURL
//
// Order is "password first" per the API contract.
export type AuthMethod = {
  type: 'password' | 'oidc';
  loginUrl: string;
};

// listAuthMethods asks the API which auth surfaces are available for
// this deployment. Used by the login page to decide whether to render
// the SSO button alongside the password form.
//
// Unauthenticated; uses the same direct-fetch shape as
// listLoginEnvironments so it can't trigger the apiFetch 401-redirect
// loop on the login page.
export async function listAuthMethods(): Promise<AuthMethod[]> {
  const res = await fetch('/api/v1/auth/methods', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`Failed to load auth methods (HTTP ${res.status})`);
  }
  const body = (await res.json()) as { methods: AuthMethod[] };
  return body.methods ?? [];
}

export function logout(): void {
  csrfTokenInMemory = null;
  // Clear the SPA-readable cookies (osctrl_csrf) so a subsequent
  // primeCsrfFromCookie() on the next page load doesn't re-prime
  // from a stale value. osctrl_token is HttpOnly so JS can't clear
  // it directly — the server-side cookie expiry (Max-Age=tokenExp)
  // is the authoritative TTL there. Setting an immediate-expiry
  // header is best-effort.
  //
  // No server-side logout endpoint today; this is purely client
  // state cleanup.
  if (typeof document !== 'undefined') {
    document.cookie = 'osctrl_csrf=; Path=/; Max-Age=0; SameSite=Lax';
  }
}
