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
import userEvent from '@testing-library/user-event';
import { LoginPage } from './LoginPage';
import type { AuthMethod, LoginResult } from '$/api/client';

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

const mockListMethods = vi.fn<() => Promise<AuthMethod[]>>();
const mockLogin = vi.fn<() => Promise<LoginResult>>();
const mockSubmitMFACode = vi.fn();
const mockBeginEnrollment = vi.fn();
const mockFinishEnrollment = vi.fn();
const mockLoginWithSecurityKey = vi.fn();

vi.mock('$/api/client', async () => {
  return {
    login: () => mockLogin(),
    listAuthMethods: () => mockListMethods(),
  };
});

vi.mock('$/api/mfa', () => ({
  submitMFACode: (...args: unknown[]) => mockSubmitMFACode(...args),
  beginMFAEnrollment: (...args: unknown[]) => mockBeginEnrollment(...args),
  finishMFAEnrollment: (...args: unknown[]) => mockFinishEnrollment(...args),
  loginWithSecurityKey: (...args: unknown[]) => mockLoginWithSecurityKey(...args),
  isWebAuthnAvailable: () => true,
}));

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

  it('renders the OIDC button when oidc method is advertised', async () => {
    mockListMethods.mockResolvedValue([
      { type: 'password', loginUrl: '/api/v1/login' },
      { type: 'oidc', loginUrl: '/api/v1/auth/oidc/login' },
    ]);

    renderWithProviders();

    const oidcLink = await screen.findByRole('link', { name: /continue with oidc/i });
    expect(oidcLink).toBeInTheDocument();
    expect(oidcLink).toHaveAttribute('href', '/api/v1/auth/oidc/login');
    // SAML button must NOT be rendered when only OIDC is advertised.
    expect(screen.queryByRole('link', { name: /continue with saml/i })).not.toBeInTheDocument();
  });

  it('renders the SAML button when saml method is advertised', async () => {
    mockListMethods.mockResolvedValue([
      { type: 'password', loginUrl: '/api/v1/login' },
      { type: 'saml', loginUrl: '/api/v1/auth/saml/login' },
    ]);

    renderWithProviders();

    const samlLink = await screen.findByRole('link', { name: /continue with saml/i });
    expect(samlLink).toBeInTheDocument();
    expect(samlLink).toHaveAttribute('href', '/api/v1/auth/saml/login');
    // OIDC button must NOT be rendered when only SAML is advertised.
    expect(screen.queryByRole('link', { name: /continue with oidc/i })).not.toBeInTheDocument();
  });

  it('renders BOTH OIDC and SAML buttons when both methods are advertised', async () => {
    mockListMethods.mockResolvedValue([
      { type: 'password', loginUrl: '/api/v1/login' },
      { type: 'oidc', loginUrl: '/api/v1/auth/oidc/login' },
      { type: 'saml', loginUrl: '/api/v1/auth/saml/login' },
    ]);

    renderWithProviders();

    const oidcLink = await screen.findByRole('link', { name: /continue with oidc/i });
    const samlLink = await screen.findByRole('link', { name: /continue with saml/i });
    expect(oidcLink).toHaveAttribute('href', '/api/v1/auth/oidc/login');
    expect(samlLink).toHaveAttribute('href', '/api/v1/auth/saml/login');
  });

  it('hides the SSO buttons when methods endpoint errors', async () => {
    mockListMethods.mockRejectedValue(new Error('boom'));

    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });

    // The methods query failed; both SSO surfaces must be hidden, password
    // form must still work.
    expect(screen.queryByRole('link', { name: /continue with oidc/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /continue with saml/i })).not.toBeInTheDocument();
  });
});


describe('LoginPage second factor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListMethods.mockResolvedValue([{ type: 'password', loginUrl: '/api/v1/login' }]);
  });

  async function signIn() {
    const user = userEvent.setup();
    renderWithProviders();
    await user.type(await screen.findByLabelText(/username/i), 'admin');
    await user.type(screen.getByLabelText(/^password$/i), 'hunter2');
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    return user;
  }

  it('asks for a code instead of signing in when the server returns a challenge', async () => {
    mockLogin.mockResolvedValue({
      kind: 'mfa',
      challenge: 'challenge-id',
      methods: ['totp', 'webauthn', 'recovery'],
      enrollment: false,
    });
    mockSubmitMFACode.mockResolvedValue({ token: 't', csrf_token: 'c' });

    const user = await signIn();

    const codeInput = await screen.findByLabelText(/authentication code/i);
    expect(screen.queryByTestId('app')).not.toBeInTheDocument();
    // A registered security key is offered alongside the code.
    expect(screen.getByRole('button', { name: /security key or passkey/i })).toBeInTheDocument();

    await user.type(codeInput, '123456');
    await user.click(screen.getByRole('button', { name: /^verify$/i }));

    await waitFor(() => {
      expect(mockSubmitMFACode).toHaveBeenCalledWith('challenge-id', 'totp', '123456');
    });
    await screen.findByTestId('app');
  });

  it('switches to a recovery code when the user picks that option', async () => {
    mockLogin.mockResolvedValue({
      kind: 'mfa',
      challenge: 'challenge-id',
      methods: ['totp', 'recovery'],
      enrollment: false,
    });
    mockSubmitMFACode.mockResolvedValue({ token: 't', csrf_token: 'c' });

    const user = await signIn();
    await user.click(await screen.findByRole('button', { name: /use a recovery code/i }));
    await user.type(screen.getByLabelText(/recovery code/i), 'ABCDE-FGHIJ');
    await user.click(screen.getByRole('button', { name: /^verify$/i }));

    await waitFor(() => {
      expect(mockSubmitMFACode).toHaveBeenCalledWith('challenge-id', 'recovery', 'ABCDE-FGHIJ');
    });
  });

  it('walks a required enrollment through the QR step and shows the recovery codes', async () => {
    mockLogin.mockResolvedValue({
      kind: 'mfa',
      challenge: 'enroll-id',
      methods: ['totp'],
      enrollment: true,
    });
    mockBeginEnrollment.mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      uri: 'otpauth://totp/osctrl:admin?secret=JBSWY3DPEHPK3PXP',
      qr: 'data:image/png;base64,AAA',
    });
    mockFinishEnrollment.mockResolvedValue({
      token: 't',
      csrf_token: 'c',
      recovery_codes: ['CODE1-CODE1', 'CODE2-CODE2'],
    });

    const user = await signIn();

    expect(await screen.findByText(/set up two-factor authentication/i)).toBeInTheDocument();
    expect(screen.getByAltText(/enrollment qr code/i)).toBeInTheDocument();
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument();

    await user.type(screen.getByLabelText(/authentication code/i), '654321');
    await user.click(screen.getByRole('button', { name: /confirm and sign in/i }));

    // The session waits behind an acknowledgement of the recovery codes.
    expect(await screen.findByText(/save your recovery codes/i)).toBeInTheDocument();
    expect(screen.getByText('CODE1-CODE1')).toBeInTheDocument();
    expect(screen.queryByTestId('app')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /i have saved them/i }));
    await screen.findByTestId('app');
  });

  it('surfaces a rejected code and keeps the user on the challenge step', async () => {
    mockLogin.mockResolvedValue({
      kind: 'mfa',
      challenge: 'challenge-id',
      methods: ['totp'],
      enrollment: false,
    });
    mockSubmitMFACode.mockRejectedValue(new Error('invalid multi-factor authentication'));

    const user = await signIn();
    await user.type(await screen.findByLabelText(/authentication code/i), '000000');
    await user.click(screen.getByRole('button', { name: /^verify$/i }));

    expect(await screen.findByText(/invalid multi-factor authentication/i)).toBeInTheDocument();
    expect(screen.queryByTestId('app')).not.toBeInTheDocument();
  });
});
