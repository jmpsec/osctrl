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
    icon: 'fas fa-wrench',
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
});
