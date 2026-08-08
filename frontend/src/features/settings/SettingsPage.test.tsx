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
import { SettingsPage } from './SettingsPage';
import type { SettingValue } from '$/api/settings';

const mockList = vi.fn<(service: string) => Promise<SettingValue[]>>();
const mockListJSON = vi.fn<(service: string) => Promise<SettingValue[]>>();
const mockPatch = vi.fn();

vi.mock('$/api/settings', () => ({
  listServiceSettings: (service: string) => mockList(service),
  patchSetting: (...args: unknown[]) => mockPatch(...args),
  listAllSettings: vi.fn(),
  listServiceJSONSettings: (service: string) => mockListJSON(service),
}));

vi.mock('$/api/client', () => ({
  isAuthenticated: () => true,
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

function makeSetting(overrides: Partial<SettingValue> = {}): SettingValue {
  return {
    ID: 1,
    CreatedAt: new Date().toISOString(),
    UpdatedAt: new Date().toISOString(),
    Name: 'service_metrics',
    Service: 'api',
    EnvironmentID: 0,
    JSON: false,
    Type: 'boolean',
    String: '',
    Boolean: false,
    Integer: 0,
    Info: 'Metrics endpoint',
    ...overrides,
  };
}

function makeJSONSetting(overrides: Partial<SettingValue> = {}): SettingValue {
  return makeSetting({
    ID: 100,
    Name: 'json_listener',
    JSON: true,
    Type: 'string',
    String: '0.0.0.0',
    Info: '',
    ...overrides,
  });
}

function makeTestRouter(initialPath = '/_app/settings/api') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const settingsRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'settings/$service',
    component: SettingsPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([settingsRoute]),
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

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListJSON.mockResolvedValue([]);
  });

  it('renders api flag parameters and editable stored settings', async () => {
    mockList.mockResolvedValue([
      makeSetting(),
      makeSetting({ ID: 2, Name: 'refresh_settings', Type: 'integer', Integer: 30 }),
    ]);
    mockListJSON.mockResolvedValue([
      makeJSONSetting(),
      makeJSONSetting({ ID: 101, Name: 'json_port', String: '9000' }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('json_listener')).toBeInTheDocument();
    });
    expect(screen.getByText('json_port')).toBeInTheDocument();
    expect(screen.getByText('service_metrics')).toBeInTheDocument();
    expect(screen.getByText('refresh_settings')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('api');
    expect(mockListJSON).toHaveBeenCalledWith('api');
  });

  it('does not expose osctrl-admin in the settings tabs', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'osctrl-api' })).toBeInTheDocument();
    });
    expect(screen.getByRole('tab', { name: 'osctrl-tls' })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'osctrl-admin' })).not.toBeInTheDocument();
  });

  it('shows flag parameters and editable settings for tls when they are available', async () => {
    mockList.mockResolvedValue([
      makeSetting({ ID: 2, Name: 'accelerated_seconds', Service: 'tls', Type: 'integer', Integer: 5 }),
    ]);
    mockListJSON.mockResolvedValue([
      makeJSONSetting({ ID: 1, Name: 'json_carver', Service: 'tls', String: 'db' }),
    ]);

    renderWithProviders(makeTestRouter('/_app/settings/tls'));

    await waitFor(() => {
      expect(screen.getByText('json_carver')).toBeInTheDocument();
    });
    expect(screen.getByText('accelerated_seconds')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('tls');
    expect(mockListJSON).toHaveBeenCalledWith('tls');
  });

  it('shows empty state when no settings exist', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No settings for api.')).toBeInTheDocument();
    });
  });

  it('patches an integer setting when Save is clicked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSetting({
      Name: 'refresh_settings',
      Type: 'integer',
      Integer: 24,
      Info: 'Refresh interval',
    })]);
    mockPatch.mockResolvedValue(makeSetting({ Integer: 48 }));

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('refresh_settings')).toBeInTheDocument();
    });

    const input = screen.getByDisplayValue('24');
    await user.clear(input);
    await user.type(input, '48');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(mockPatch).toHaveBeenCalledTimes(1);
    });
    const args = mockPatch.mock.calls[0] as [string, string, { integer: number }];
    expect(args[0]).toBe('api');
    expect(args[1]).toBe('refresh_settings');
    expect(args[2].integer).toBe(48);
  });
});
