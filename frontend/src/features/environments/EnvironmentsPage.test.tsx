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
import { EnvironmentsPage } from './EnvironmentsPage';
import type { TLSEnvironment } from '$/api/environments';
import type { UserMeResponse } from '$/api/types';

const mockGetMe = vi.fn<() => Promise<UserMeResponse>>();
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));
function makeMe(overrides: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'u', email: '', fullname: 'u', admin: false, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: 'aaaa',
    token_expire: new Date(Date.now() + 86_400_000).toISOString(),
    last_access: new Date().toISOString(), permissions: {}, preferred_language: '',
    ...overrides,
  };
}


const mockList = vi.fn<() => Promise<TLSEnvironment[]>>();
const mockCreate = vi.fn();
const mockUpdate = vi.fn();
const mockDelete = vi.fn();

vi.mock('$/api/environments', () => ({
  listEnvironments: () => mockList(),
  createEnvironment: (...args: unknown[]) => mockCreate(...args),
  updateEnvironment: (...args: unknown[]) => mockUpdate(...args),
  deleteEnvironment: (...args: unknown[]) => mockDelete(...args),
  getEnvironment: vi.fn(),
  getEnvironmentConfig: vi.fn(),
  patchEnvironmentConfig: vi.fn(),
  patchEnvironmentIntervals: vi.fn(),
  patchEnvironmentExpiration: vi.fn(),
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

function makeEnv(overrides: Partial<TLSEnvironment> = {}): TLSEnvironment {
  return {
    id: 1,
    created_at: new Date(Date.now() - 600_000).toISOString(),
    updated_at: new Date().toISOString(),
    uuid: '00000000-0000-0000-0000-000000000001',
    name: 'prod',
    hostname: 'osctrl.example.com',
    secret: '',
    enroll_secret_path: '',
    enroll_expire: '',
    remove_secret_path: '',
    remove_expire: '',
    type: 'osquery',
    deb_package: '',
    rpm_package: '',
    msi_package: '',
    pkg_package: '',
    debug_http: false,
    icon: 'wrench',
    options: '{}',
    schedule: '{}',
    packs: '{}',
    decorators: '{}',
    atc: '{}',
    configuration: '',
    flags: '',
    certificate: '',
    config_tls: true,
    config_interval: 300,
    logging_tls: true,
    log_interval: 600,
    query_tls: true,
    query_interval: 60,
    carves_tls: true,
    enroll_path: 'enroll',
    log_path: 'log',
    config_path: 'config',
    query_read_path: 'read',
    query_write_path: 'write',
    carver_init_path: 'init',
    carver_block_path: 'block',
    accept_enrolls: true,
    user_id: 1,
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/environments') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const envsRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'environments',
    component: EnvironmentsPage,
  });
  const envCatchAll = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env/$',
    component: () => <div data-testid="env-route">env route</div>,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envsRoute, envCatchAll]),
    loginRoute,
  ]);
  const history = createMemoryHistory({ initialEntries: [initialPath] });
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

describe('EnvironmentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMe.mockResolvedValue(makeMe({ admin: true }));
  });

  it('renders env rows after loading', async () => {
    mockList.mockResolvedValue([makeEnv(), makeEnv({ id: 2, name: 'staging', uuid: 'uuid-2' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('prod')).toBeInTheDocument();
    });
    expect(screen.getByText('staging')).toBeInTheDocument();
  });

  it('shows the empty state CTA when no envs exist', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No environments yet.')).toBeInTheDocument();
    });
    expect(
      screen.getByRole('button', { name: /create your first environment/i }),
    ).toBeInTheDocument();
  });

  it('opens the create modal and calls createEnvironment on submit', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([]);
    mockCreate.mockResolvedValue(makeEnv({ name: 'new_env' }));

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No environments yet.')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /new environment/i }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^name$/i), 'new_env');
    await user.type(screen.getByLabelText(/hostname/i), 'host.example.com');
    await user.click(screen.getByRole('button', { name: /create environment/i }));

    await waitFor(() => {
      expect(mockCreate).toHaveBeenCalledTimes(1);
    });
    const args = mockCreate.mock.calls[0] as [{ name: string; hostname: string; type?: string }];
    expect(args[0].name).toBe('new_env');
    expect(args[0].hostname).toBe('host.example.com');
  });

  it('shows New only to environment managers, and Edit/Delete only on envs they administer', async () => {
    mockGetMe.mockResolvedValue(
      makeMe({ env_manager: true, permissions: { 'uuid-2': { user: true, query: false, carve: false, admin: true } } }),
    );
    mockList.mockResolvedValue([makeEnv(), makeEnv({ id: 2, name: 'staging', uuid: 'uuid-2' })]);
    renderWithProviders(makeTestRouter());
    expect(await screen.findByRole('button', { name: /new environment/i })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Edit' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(1);
  });

  it('hides every write control from a read-only admin', async () => {
    mockGetMe.mockResolvedValue(makeMe({ read_only_admin: true }));
    mockList.mockResolvedValue([makeEnv()]);
    renderWithProviders(makeTestRouter());
    expect(await screen.findByText('prod')).toBeInTheDocument();
    await waitFor(() => expect(mockGetMe).toHaveBeenCalled());
    expect(screen.queryByRole('button', { name: /new environment/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
  it('shows only Config to a read-only admin who administers an env', async () => {
    const admin = { 'uuid-2': { user: true, query: true, carve: true, admin: true } };
    for (const flags of [{ read_only_admin: true }, { user_admin: true }]) {
      mockGetMe.mockResolvedValue(makeMe({ ...flags, permissions: admin }));
      mockList.mockResolvedValue([makeEnv({ id: 2, name: 'staging', uuid: 'uuid-2' })]);
      const { unmount } = renderWithProviders(makeTestRouter());
      expect(await screen.findByRole('button', { name: 'Config…' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
      unmount();
    }
  });

  it('shows Config, Edit, Delete and selection to an env manager who administers the env', async () => {
    mockGetMe.mockResolvedValue(
      makeMe({ env_manager: true, permissions: { 'uuid-2': { user: true, query: true, carve: true, admin: true } } }),
    );
    mockList.mockResolvedValue([makeEnv({ id: 2, name: 'staging', uuid: 'uuid-2' })]);
    renderWithProviders(makeTestRouter());
    expect(await screen.findByRole('button', { name: 'Config…' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Select environment staging' })).toBeInTheDocument();
    expect(screen.getAllByRole('checkbox')).toHaveLength(2);
  });
});
