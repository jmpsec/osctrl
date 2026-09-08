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
import type { Features } from '$/api/features';

const {
  mockGetEnvironment,
  mockGetConfig,
  mockGetAssembledConfig,
  mockPatchConfig,
  mockPatchIntervals,
  mockPatchExpiration,
  mockGetPostureProfiles,
  mockGetFeatures,
  mockGetInactiveHours,
  mockSetInactiveHours,
  mockResetInactiveHours,
  mockGetMe,
} = vi.hoisted(() => ({
  mockGetEnvironment: vi.fn<() => Promise<TLSEnvironment>>(),
  mockGetConfig: vi.fn<() => Promise<EnvConfigResponse>>(),
  mockGetAssembledConfig: vi.fn<() => Promise<{ data: string }>>(),
  mockPatchConfig: vi.fn(),
  mockPatchIntervals: vi.fn(),
  mockPatchExpiration: vi.fn(),
  mockGetPostureProfiles: vi.fn(),
  mockGetFeatures: vi.fn<() => Promise<Features>>(),
  mockGetInactiveHours: vi.fn(),
  mockSetInactiveHours: vi.fn(),
  mockResetInactiveHours: vi.fn(),
  mockGetMe: vi.fn(),
}));

vi.mock('$/api/environments', () => ({
  getEnvironment: mockGetEnvironment,
  getEnvironmentInactiveHours: mockGetInactiveHours,
  setEnvironmentInactiveHours: mockSetInactiveHours,
  resetEnvironmentInactiveHours: mockResetInactiveHours,
  getEnvironmentConfig: mockGetConfig,
  getEnvironmentAssembledConfig: mockGetAssembledConfig,
  patchEnvironmentConfig: (...args: unknown[]) => mockPatchConfig(...args),
  patchEnvironmentIntervals: (...args: unknown[]) => mockPatchIntervals(...args),
  patchEnvironmentExpiration: (...args: unknown[]) => mockPatchExpiration(...args),
}));

vi.mock('$/api/users', () => ({ getMe: mockGetMe }));

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

vi.mock('$/api/nodes', () => ({
  getPostureProfiles: (...args: unknown[]) => mockGetPostureProfiles(...args),
}));

vi.mock('$/api/features', () => ({
  getFeatures: () => mockGetFeatures(),
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

function renderWithProviders(queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })) {
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
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    mockGetInactiveHours.mockResolvedValue({ override_hours: null, inactive_hours: 168, source: 'global' });
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
    mockGetPostureProfiles.mockResolvedValue([]);
    mockGetFeatures.mockResolvedValue({ posture: false, service_config: false, accelerated: false, file_explorer: false });
  });

  it('inherits the global value, saves an override, and resets to inheritance', async () => {
    const user = userEvent.setup();
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const keys = [['inactive-hours', 'other-env'], ['nodes', 'dev'], ['node', 'dev', 'uuid'], ['stats']];
    keys.forEach((key) => qc.setQueryData(key, {}));
    const override = { override_hours: 24, inactive_hours: 24, source: 'environment' };
    mockSetInactiveHours.mockImplementation(async () => {
      mockGetInactiveHours.mockResolvedValue(override);
      return override;
    });
    mockResetInactiveHours.mockImplementation(async () => {
      const inherited = { override_hours: null, inactive_hours: 168, source: 'global' };
      mockGetInactiveHours.mockResolvedValue(inherited);
      return inherited;
    });
    renderWithProviders(qc);
    const checkbox = await screen.findByRole('checkbox', { name: 'Use global default' });
    const hours = screen.getByRole('spinbutton', { name: 'Inactive hours' });
    const save = screen.getByRole('button', { name: 'Save inactive hours' });
    expect(checkbox).toBeChecked();
    expect(hours).toHaveValue(168);
    expect(hours).toBeDisabled();
    expect(save).toBeDisabled();
    await user.click(checkbox);
    await user.clear(hours);
    await user.type(hours, '24');
    await user.click(save);
    await waitFor(() => expect(mockSetInactiveHours).toHaveBeenCalledWith('dev', 24));
    await waitFor(() => expect(save).toBeDisabled());
    expect(checkbox).not.toBeChecked();
    keys.forEach((key) => expect(qc.getQueryState(key)?.isInvalidated).toBe(true));
    keys.forEach((key) => qc.setQueryData(key, {}));
    await user.click(checkbox);
    await user.click(save);
    await waitFor(() => expect(mockResetInactiveHours).toHaveBeenCalledWith('dev'));
    await waitFor(() => expect(hours).toHaveValue(168));
    expect(checkbox).toBeChecked();
    keys.forEach((key) => expect(qc.getQueryState(key)?.isInvalidated).toBe(true));
  });

  it('locks the form while saving and adopts the returned effective default', async () => {
    const user = userEvent.setup();
    mockGetInactiveHours.mockResolvedValue({ override_hours: 24, inactive_hours: 24, source: 'environment' });
    let finish!: (value: unknown) => void;
    mockResetInactiveHours.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    renderWithProviders();
    const checkbox = await screen.findByRole('checkbox', { name: 'Use global default' });
    await user.click(checkbox);
    const save = screen.getByRole('button', { name: 'Save inactive hours' });
    await user.click(save);
    expect(checkbox).toBeDisabled();
    expect(save).toBeDisabled();
    expect(save).toHaveTextContent('Saving');
    const inherited = { override_hours: null, inactive_hours: 72, source: 'default' };
    mockGetInactiveHours.mockResolvedValue(inherited);
    finish(inherited);
    await waitFor(() => expect(screen.getByRole('spinbutton', { name: 'Inactive hours' })).toHaveValue(72));
    expect(checkbox).toBeChecked();
  });

  it('validates override hours and preserves edits after a failed save', async () => {
    const user = userEvent.setup();
    mockSetInactiveHours.mockRejectedValue(new Error('Save unavailable'));
    renderWithProviders();
    await user.click(await screen.findByRole('checkbox', { name: 'Use global default' }));
    const hours = screen.getByRole('spinbutton', { name: 'Inactive hours' });
    const save = screen.getByRole('button', { name: 'Save inactive hours' });
    for (const value of ['', '0', '-1', '1.5', '2562048']) {
      await user.clear(hours);
      if (value) await user.type(hours, value);
      expect(save).toBeDisabled();
    }
    await user.clear(hours);
    await user.type(hours, '2562047');
    await user.click(save);
    expect(await screen.findByText('Save unavailable')).toBeInTheDocument();
    expect(hours).toHaveValue(2562047);
    expect(save).toBeEnabled();
  });

  it('shows fetch errors with retry and no guessed threshold', async () => {
    const user = userEvent.setup();
    mockGetInactiveHours.mockRejectedValueOnce(new Error('Threshold unavailable'));
    renderWithProviders();
    expect(await screen.findByText('Threshold unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('spinbutton', { name: 'Inactive hours' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry inactive hours' }));
    expect(await screen.findByRole('spinbutton', { name: 'Inactive hours' })).toHaveValue(168);
  });

  it.each([false, true])('uses environment admin permission: %s', async (admin) => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue({ admin: false, permissions: { [makeEnv().uuid]: { admin, user: true } } });
    renderWithProviders();
    const checkbox = await screen.findByRole('checkbox', { name: 'Use global default' });
    await waitFor(() => expect(checkbox).toHaveProperty('disabled', !admin));
    if (admin) {
      await user.click(checkbox);
      expect(screen.getByRole('button', { name: 'Save inactive hours' })).toBeEnabled();
    }
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

  it('loads posture profiles only after opening the picker', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });

    renderWithProviders();

    const scheduleTab = await screen.findByRole('tab', { name: 'Schedule' });
    expect(mockGetPostureProfiles).not.toHaveBeenCalled();

    await user.click(scheduleTab);
    expect(mockGetPostureProfiles).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Add posture checks' }));

    await waitFor(() => {
      expect(mockGetPostureProfiles).toHaveBeenCalledTimes(1);
    });
  });

  it('distinguishes a profile load failure from an empty profile list', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetPostureProfiles.mockRejectedValue(new Error('profiles unavailable'));

    renderWithProviders();

    await user.click(await screen.findByRole('tab', { name: 'Schedule' }));
    await user.click(screen.getByRole('button', { name: 'Add posture checks' }));

    expect(await screen.findByText('Failed to load posture profiles.', {}, { timeout: 3_000 })).toBeInTheDocument();
    expect(screen.queryByText('No posture profiles available.')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry loading profiles' })).toBeInTheDocument();
  });

  it('hides posture profile controls while the posture feature is disabled', async () => {
    const user = userEvent.setup();

    renderWithProviders();

    await user.click(await screen.findByRole('tab', { name: 'Schedule' }));

    expect(screen.queryByRole('button', { name: 'Add posture checks' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Posture' })).not.toBeInTheDocument();
    expect(mockGetPostureProfiles).not.toHaveBeenCalled();
  });

  it('adds a posture profile from the schedule picker into the posture tab', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetPostureProfiles.mockResolvedValue([
      {
        id: 'linux-server',
        name: 'Linux Servers',
        description: 'Linux host posture checks',
        platform: 'linux',
        queries: {
          users: {
            query: 'SELECT username FROM users',
            interval: 86400,
            snapshot: true,
          },
        },
      },
    ]);

    renderWithProviders();

    await user.click(await screen.findByRole('tab', { name: 'Schedule' }));
    await user.click(screen.getByRole('button', { name: 'Add posture checks' }));

    expect(await screen.findByText('Linux')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Linux Servers to schedule' }));
    await user.click(screen.getByRole('tab', { name: 'Posture' }));

    expect(screen.getByDisplayValue('osctrl:posture:users')).toBeInTheDocument();
    expect(screen.getByLabelText('Profile')).toHaveValue('linux-server');
  });

  it('saves the selected posture profile for a new manual check', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetPostureProfiles.mockResolvedValue([
      {
        id: 'linux-server',
        name: 'Linux Servers',
        description: 'Linux host posture checks',
        platform: 'linux',
        queries: {},
      },
    ]);
    mockPatchConfig.mockImplementation(async (_env, body) => ({
      options: '{}',
      schedule: body.schedule,
      packs: '{}',
      decorators: '{}',
      atc: '{}',
      flags: '',
    }));

    renderWithProviders();

    await user.click(await screen.findByRole('tab', { name: 'Posture' }));
    await user.click(screen.getByRole('button', { name: 'Add check' }));
    await user.selectOptions(screen.getByLabelText('Profile'), 'linux-server');
    await user.click(screen.getByRole('button', { name: 'Save posture checks' }));

    await waitFor(() => {
      expect(mockPatchConfig).toHaveBeenCalledWith('dev', {
        schedule: JSON.stringify({
          'osctrl:posture:new_check': {
            query: 'SELECT 1',
            interval: 86400,
            platform: 'linux',
            snapshot: true,
            profile_id: 'linux-server',
          },
        }, null, 2),
      });
    });
  });

  it('shows an environment-scoped posture tab when posture is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetConfig.mockResolvedValue({
      options: '{}',
      schedule: JSON.stringify({
        'osctrl:posture:users': {
          query: 'SELECT username FROM users',
          interval: 86400,
          snapshot: true,
          profile_id: 'linux-server',
        },
      }),
      packs: '{}',
      decorators: '{}',
      atc: '{}',
      flags: '',
    });

    renderWithProviders();

    expect(await screen.findByRole('tab', { name: 'Posture' })).toBeInTheDocument();
  });

  it('hides the posture tab when posture is disabled', async () => {
    renderWithProviders();

    await screen.findByRole('tab', { name: 'Settings' });

    expect(screen.queryByRole('tab', { name: 'Posture' })).not.toBeInTheDocument();
  });

  it('edits posture checks through the environment schedule', async () => {
    const user = userEvent.setup();
    mockGetFeatures.mockResolvedValue({ posture: true, service_config: false, accelerated: false, file_explorer: false });
    mockGetConfig.mockResolvedValue({
      options: '{}',
      schedule: JSON.stringify({
        'osctrl:posture:users': {
          query: 'SELECT username FROM users',
          interval: 86400,
          snapshot: true,
          profile_id: 'linux-server',
        },
      }),
      packs: '{}',
      decorators: '{}',
      atc: '{}',
      flags: '',
    });
    mockPatchConfig.mockImplementation(async (_env, body) => ({
      options: '{}',
      schedule: body.schedule,
      packs: '{}',
      decorators: '{}',
      atc: '{}',
      flags: '',
    }));

    renderWithProviders();

    await user.click(await screen.findByRole('tab', { name: 'Posture' }));
    await user.clear(screen.getByLabelText('Query name'));
    await user.type(screen.getByLabelText('Query name'), 'osctrl:posture:interactive_users');
    await user.clear(screen.getByLabelText('Interval'));
    await user.type(screen.getByLabelText('Interval'), '3600');
    await user.click(screen.getByRole('button', { name: 'Save posture checks' }));

    await waitFor(() => {
      expect(mockPatchConfig).toHaveBeenCalledWith('dev', {
        schedule: JSON.stringify({
          'osctrl:posture:interactive_users': {
            query: 'SELECT username FROM users',
            interval: 3600,
            snapshot: true,
            profile_id: 'linux-server',
          },
        }, null, 2),
      });
    });
  });
});
