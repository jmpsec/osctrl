import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { LoginPage } from './LoginPage';
import type { AuthMethod } from '$/api/client';

// Tests pin the SSO button's behavior — the rest of the page (env
// dropdown, password form) is exercised manually and via e2e. We
// specifically guard:
//
//  1. SSO button is HIDDEN when /api/v1/auth/methods returns only
//     password. A regression here would land an unreachable button
//     in every deployment, breaking deploys without an IdP.
//  2. SSO button is RENDERED when methods includes oidc, with an
//     href matching the API's advertised loginUrl. A regression here
//     would break the federated-login flow at the SPA layer even
//     though the API works fine.
//  3. The SSO button uses a plain <a href> (no JS handler) so the
//     browser issues a full-page navigation that follows the 302
//     redirect chain to the IdP. fetch/XHR-driven navigation would
//     break the flow because the OAuth2 callback redirects, and
//     browsers don't follow cross-origin redirects on XHR.

const mockListEnvs = vi.fn();
const mockListMethods = vi.fn<() => Promise<AuthMethod[]>>();

vi.mock('$/api/client', async () => {
  return {
    login: vi.fn(),
    listLoginEnvironments: () => mockListEnvs(),
    listAuthMethods: () => mockListMethods(),
  };
});

function makeTestRouter() {
  const rootRoute = createRootRoute({ component: Outlet });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: LoginPage,
  });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: () => <div data-testid="app">App</div>,
  });
  const routeTree = rootRoute.addChildren([loginRoute, appRoute]);
  const history = createMemoryHistory({ initialEntries: ['/login'] });
  return createRouter({ routeTree, history });
}

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = makeTestRouter();
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('LoginPage SSO surface', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListEnvs.mockResolvedValue([{ uuid: 'env-1', name: 'prod' }]);
  });

  it('hides the SSO button when only password method is advertised', async () => {
    mockListMethods.mockResolvedValue([
      { type: 'password', loginUrl: '/api/v1/login' },
    ]);

    renderWithProviders();

    // Wait for the password form to settle so we know the methods
    // query had a chance to resolve.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });

    expect(screen.queryByRole('link', { name: /sso/i })).not.toBeInTheDocument();
  });

  it('renders the SSO button when oidc method is advertised', async () => {
    mockListMethods.mockResolvedValue([
      { type: 'password', loginUrl: '/api/v1/login' },
      { type: 'oidc', loginUrl: '/api/v1/auth/oidc/login' },
    ]);

    renderWithProviders();

    const ssoLink = await screen.findByRole('link', { name: /continue with sso/i });
    expect(ssoLink).toBeInTheDocument();
    expect(ssoLink).toHaveAttribute('href', '/api/v1/auth/oidc/login');
  });

  it('hides the SSO button when methods endpoint errors', async () => {
    mockListMethods.mockRejectedValue(new Error('boom'));

    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });

    // The methods query failed; SSO surface must be hidden, password
    // form must still work.
    expect(screen.queryByRole('link', { name: /sso/i })).not.toBeInTheDocument();
  });
});
