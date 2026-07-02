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
import { EnvConfigPage } from './EnvConfigPage';
import type { TLSEnvironment, EnvConfigResponse } from '$/api/environments';

const {
  mockGetEnvironment,
  mockGetConfig,
  mockGetAssembledConfig,
  mockPatchConfig,
  mockPatchIntervals,
  mockPatchExpiration,
} = vi.hoisted(() => ({
  mockGetEnvironment: vi.fn<() => Promise<TLSEnvironment>>(),
  mockGetConfig: vi.fn<() => Promise<EnvConfigResponse>>(),
  mockGetAssembledConfig: vi.fn<() => Promise<{ data: string }>>(),
  mockPatchConfig: vi.fn(),
  mockPatchIntervals: vi.fn(),
  mockPatchExpiration: vi.fn(),
}));

vi.mock('$/api/environments', () => ({
  getEnvironment: mockGetEnvironment,
  getEnvironmentConfig: mockGetConfig,
  getEnvironmentAssembledConfig: mockGetAssembledConfig,
  patchEnvironmentConfig: (...args: unknown[]) => mockPatchConfig(...args),
  patchEnvironmentIntervals: (...args: unknown[]) => mockPatchIntervals(...args),
  patchEnvironmentExpiration: (...args: unknown[]) => mockPatchExpiration(...args),
}));

vi.mock('$/api/client', () => ({
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

vi.mock('$/components/forms/CodeEditor', () => ({
  CodeEditor: ({ value, 'aria-label': ariaLabel }: { value: string; 'aria-label'?: string }) => (
    <div data-testid="code-editor" aria-label={ariaLabel}>
      {value}
    </div>
  ),
}));

function makeEnv(overrides: Partial<TLSEnvironment> = {}): TLSEnvironment {
  return {
    id: 1,
    created_at: new Date(Date.now() - 600_000).toISOString(),
    updated_at: new Date().toISOString(),
    uuid: '00000000-0000-0000-0000-000000000001',
    name: 'dev',
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

function makeRouter(initialPath = '/_app/env/dev/config') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });
  const configRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'config',
    component: EnvConfigPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([configRoute])]),
    loginRoute,
  ]);
  const history = createMemoryHistory({ initialEntries: [initialPath] });
  return createRouter({ routeTree, history });
}

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = makeRouter();
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('EnvConfigPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEnvironment.mockResolvedValue(makeEnv());
    mockGetConfig.mockResolvedValue({
      options: '{"logger_plugin":"tls"}',
      schedule: '{}',
      packs: '{}',
      decorators: '{}',
      atc: '{}',
      flags: '--tls_hostname=osctrl.example.com',
    });
    mockGetAssembledConfig.mockResolvedValue({
      data: '{"options":{"logger_plugin":"tls"}}',
    });
  });

  it('loads the fully rendered tab from the assembled config endpoint', async () => {
    const user = userEvent.setup();

    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Settings' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('tab', { name: 'Full Configuration' }));

    await waitFor(() => {
      expect(mockGetAssembledConfig).toHaveBeenCalledWith('dev');
    });

    expect(screen.getByText('Assembled configuration')).toBeInTheDocument();
    expect(screen.getByText('{"options":{"logger_plugin":"tls"}}')).toBeInTheDocument();
  });

  it('refetches the full configuration when clicking the tab again', async () => {
    const user = userEvent.setup();

    renderWithProviders();

    const tab = await screen.findByRole('tab', { name: 'Full Configuration' });

    await user.click(tab);

    await waitFor(() => {
      expect(mockGetAssembledConfig).toHaveBeenCalledTimes(1);
    });

    await user.click(tab);

    await waitFor(() => {
      expect(mockGetAssembledConfig).toHaveBeenCalledTimes(2);
    });
  });
});
