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
//   "oidc"     — a "Continue with SSO (OIDC)" button linking to LoginURL
//   "saml"     — a "Continue with SSO (SAML)" button linking to LoginURL
//
// Order is "password first" per the API contract. OIDC and SAML can
// both be advertised simultaneously when the deployment has both
// providers enabled — the SPA renders one button per method.
export type AuthMethod = {
  type: 'password' | 'oidc' | 'saml';
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

// Response shape from POST /api/v1/logout. idpLogoutUrl is non-empty
// when the api has an OIDC provider configured and the IdP advertised
// an end_session_endpoint. The SPA navigates to it after the local
// teardown to terminate the IdP's session cookie too; without that,
// the next "Continue with SSO" silently re-auths against the
// still-valid IdP session.
//
// idp_client_id — Keycloak accepts client_id alongside
// post_logout_redirect_uri as an alternative to id_token_hint.
//
// idp_id_token_hint — Okta REQUIRES id_token_hint when chaining a
// post-logout redirect; without it, /v1/logout returns "Missing
// parameter: id_token_hint". The api stashes the raw id_token in an
// HttpOnly cookie at callback and returns it here. The SPA forwards
// both parameters; whichever the IdP needs, it'll use.
export type LogoutResponse = {
  // auth_source carries which provider issued the active session
  // ("oidc" / "saml" / "" for password). The SPA uses it implicitly:
  // an empty idp_logout_url means "no IdP-side logout to do",
  // regardless of which provider the user came from. SAML users
  // always get an empty idp_logout_url because SLO is deferred to
  // v2 (see docs/proposals/osctrl-auth-providers-v0.1).
  auth_source?: string;
  idp_logout_url?: string;
  idp_client_id?: string;
  idp_id_token_hint?: string;
};

// logout tears down both the SPA session AND, when available, the
// IdP session. Two-step:
//
//   1. POST /api/v1/logout — server expires both cookies via
//      Set-Cookie headers (only the server can clear the HttpOnly
//      osctrl_token cookie) AND clears the user's APIToken in the
//      DB so any still-cached copy of the JWT fails the auth check
//      on its next use.
//
//   2. If the response includes idp_logout_url, navigate to it —
//      Keycloak (and most IdPs) accept ?post_logout_redirect_uri=...
//      to bounce back. Without this, ?signed-in-as-X persists in the
//      IdP and the next SSO click silently logs the user back in.
//
// Best-effort: a network failure during step 1 still proceeds to the
// in-memory clear + /login redirect. Worst case: server-side
// revocation didn't happen and the operator's JWT remains valid
// until its exp — they can re-click logout once connectivity returns.
export async function logout(): Promise<void> {
  csrfTokenInMemory = null;

  let idpLogoutUrl = '';
  let idpClientId = '';
  let idpIdTokenHint = '';
  try {
    const res = await fetch('/api/v1/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (res.ok) {
      const body = (await res.json()) as LogoutResponse;
      idpLogoutUrl = body.idp_logout_url ?? '';
      idpClientId = body.idp_client_id ?? '';
      idpIdTokenHint = body.idp_id_token_hint ?? '';
    }
  } catch {
    // Network blip — fall through to client-only cleanup.
  }

  // Defense-in-depth: clear the SPA-readable cookie locally too.
  // Server-side Set-Cookie should have done this, but if the POST
  // failed we still want primeCsrfFromCookie() on the next load
  // to see no cookie.
  if (typeof document !== 'undefined') {
    document.cookie = 'osctrl_csrf=; Path=/; Max-Age=0; SameSite=Lax';
  }

  if (idpLogoutUrl) {
    // Build the post-logout redirect URL — back to the SPA's /login.
    // Keycloak 26+ requires EITHER id_token_hint OR client_id when
    // post_logout_redirect_uri is set. We use client_id (received
    // from the api in the same response) to avoid persisting raw
    // id_tokens client-side. The redirect URI must be pre-
    // registered as a valid post-logout redirect on the client; the
    // dev compose stack does this in Keycloak's
    // post.logout.redirect.uris attribute on the osctrl-api client.
    //
    // If the api didn't return client_id (older build / missing
    // config), we still navigate but omit the parameter and let
    // Keycloak's error page guide the operator.
    const postLogout = `${window.location.origin}/login`;
    const params = new URLSearchParams({ post_logout_redirect_uri: postLogout });
    if (idpIdTokenHint) {
      // Okta requires id_token_hint when chaining a redirect.
      // Keycloak accepts it too. Send it whenever we have one.
      params.set('id_token_hint', idpIdTokenHint);
    }
    if (idpClientId) {
      // Keycloak accepts client_id as an alternative when no
      // id_token_hint is available. Harmless when id_token_hint
      // is also set — most IdPs honor whichever they recognize.
      params.set('client_id', idpClientId);
    }
    const sep = idpLogoutUrl.includes('?') ? '&' : '?';
    window.location.href = `${idpLogoutUrl}${sep}${params.toString()}`;
    return;
  }
  // No IdP logout to do; just bounce to /login. The router will see
  // isAuthenticated() === false and render the login form.
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
}
