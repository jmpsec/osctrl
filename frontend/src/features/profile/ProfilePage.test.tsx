import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { ProfilePage } from './ProfilePage';
import type { UserMeResponse } from '$/api/types';

const mockGetMe = vi.fn<() => Promise<UserMeResponse>>();
const mockListEnvironments = vi.fn();
const mockPatch = vi.fn();
const mockChange = vi.fn();

vi.mock('$/api/users', () => ({
  getMe: () => mockGetMe(),
  patchMe: (...args: unknown[]) => mockPatch(...args),
  changeMyPassword: (...args: unknown[]) => mockChange(...args),
  listUsers: vi.fn(),
  getUser: vi.fn(),
  setUserPermissions: vi.fn(),
  refreshUserToken: vi.fn(),
  deleteUserToken: vi.fn(),
}));

vi.mock('$/api/environments', () => ({
  listEnvironments: () => mockListEnvironments(),
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
  getCsrfToken: () => 'test-csrf',
  setCsrfToken: vi.fn(),
  AuthError: class AuthError extends Error {
    readonly status = 401;
    constructor() {
      super('Unauthorized');
    }
  },
  ApiError: class ApiError extends Error {
    constructor(msg: string, public status: number, public code?: string) {
      super(msg);
    }
  },
}));

function makeMe(): UserMeResponse {
  return {
    username: 'alice',
    email: 'alice@example.com',
    fullname: 'Alice Adams',
    admin: false,
    service: false,
    uuid: 'aaaa',
    token_expire: new Date(Date.now() + 86_400_000).toISOString(),
    last_access: new Date(Date.now() - 60_000).toISOString(),
    permissions: {},
  };
}

function makeTestRouter() {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const profileRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'profile',
    component: ProfilePage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([profileRoute]),
    loginRoute,
  ]);
  const history = createMemoryHistory({ initialEntries: ['/_app/profile'] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('ProfilePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListEnvironments.mockResolvedValue([]);
  });

  it('renders the operator profile after loading', async () => {
    mockGetMe.mockResolvedValue(makeMe());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });
    await waitFor(() => {
      const email = screen.getByLabelText(/^email$/i) as HTMLInputElement;
      expect(email.value).toBe('alice@example.com');
    });
    await waitFor(() => {
      expect(screen.getAllByText('Permissions').length).toBeGreaterThan(0);
    });
    expect(screen.getByText('No environment access.')).toBeInTheDocument();
  });

  it('renders environment permissions in their own section', async () => {
    mockGetMe.mockResolvedValue({
      ...makeMe(),
      permissions: {
        envA: { user: true, query: true, carve: false, admin: false },
        envB: { user: true, query: false, carve: true, admin: true },
      },
    });
    mockListEnvironments.mockResolvedValue([
      { uuid: 'envA', name: 'production' },
      { uuid: 'envB', name: 'staging' },
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('production')).toBeInTheDocument();
    });
    expect(screen.getByText('staging')).toBeInTheDocument();
    expect(screen.getAllByText('yes').length).toBe(5);
    expect(screen.getByText('envA')).toBeInTheDocument();
    expect(screen.getByText('envB')).toBeInTheDocument();
  });

  it('rejects mismatching new passwords client-side', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(makeMe());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('alice')).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/current password/i), 'oldpassword1');
    await user.type(screen.getByLabelText(/^new password$/i), 'newpassword1');
    await user.type(screen.getByLabelText(/confirm new password/i), 'mismatch');
    await user.click(screen.getByRole('button', { name: /change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/do not match/i);
    });
    expect(mockChange).not.toHaveBeenCalled();
  });
});
