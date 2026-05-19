import { describe, it, expect, beforeEach } from 'vitest';
import { isAuthenticated, setCsrfToken, primeCsrfFromCookie } from './client';

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
