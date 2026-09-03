import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { apiFetch, ApiError, isAuthenticated, setCsrfToken, primeCsrfFromCookie } from './client';

// Tests for the cookie-priming bootstrap. The OIDC flow finishes with
// a server 302 to "/" and the SPA boots fresh — the in-memory CSRF
// token is null even though the cookie IS set. primeCsrfFromCookie
// closes that gap. The password-login flow goes through login() which
// sets the token directly, so this bootstrap is a no-op there.

function clearCookies() {
  // jsdom cookies persist across tests if we don't wipe them.
  for (const c of document.cookie.split(';')) {
    const name = c.split('=')[0]?.trim();
    if (name) {
      document.cookie = `${name}=; Path=/; Max-Age=0`;
    }
  }
}

describe('primeCsrfFromCookie', () => {
  beforeEach(() => {
    clearCookies();
    setCsrfToken(null);
  });

  it('does nothing when no osctrl_csrf cookie is present', () => {
    primeCsrfFromCookie();
    expect(isAuthenticated()).toBe(false);
  });

  it('seeds the in-memory CSRF token from the cookie', () => {
    document.cookie = 'osctrl_csrf=abc123def456; Path=/';
    primeCsrfFromCookie();
    expect(isAuthenticated()).toBe(true);
  });

  it('ignores empty cookie value', () => {
    document.cookie = 'osctrl_csrf=; Path=/';
    primeCsrfFromCookie();
    expect(isAuthenticated()).toBe(false);
  });

  it('does not get confused by other cookies', () => {
    document.cookie = 'other_cookie=junk; Path=/';
    document.cookie = 'osctrl_csrf=real_value; Path=/';
    document.cookie = 'another=xyz; Path=/';
    primeCsrfFromCookie();
    expect(isAuthenticated()).toBe(true);
  });
});

// Every DELETE endpoint answers 204 with no body. apiFetch used to end in
// res.json(), which threw "Unexpected end of JSON input" and surfaced in
// the UI as a failed delete that had in fact succeeded.
describe('apiFetch response bodies', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it('resolves to undefined for a 204 with no body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    ) as unknown as typeof fetch;
    await expect(apiFetch<void>('/api/v1/alerts/rules/1', { method: 'DELETE' })).resolves.toBeUndefined();
  });

  it('still parses a JSON body', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: 7 }), { status: 200 }),
    ) as unknown as typeof fetch;
    await expect(apiFetch<{ id: number }>('/api/v1/alerts/rules/7')).resolves.toEqual({ id: 7 });
  });

  it('still reports the error message on a failure', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'not found' }), { status: 404 }),
    ) as unknown as typeof fetch;
    await expect(apiFetch('/api/v1/alerts/rules/9', { method: 'DELETE' })).rejects.toThrow(ApiError);
  });
});
