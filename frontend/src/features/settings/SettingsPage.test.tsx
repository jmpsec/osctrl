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

const mockList = vi.fn<() => Promise<SettingValue[]>>();
const mockPatch = vi.fn();

vi.mock('$/api/settings', () => ({
  listServiceSettings: () => mockList(),
  patchSetting: (...args: unknown[]) => mockPatch(...args),
  listAllSettings: vi.fn(),
  listServiceJSONSettings: vi.fn(),
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
    Name: 'InactiveHours',
    Service: 'admin',
    EnvironmentID: 0,
    JSON: false,
    Type: 'integer',
    String: '',
    Boolean: false,
    Integer: 24,
    Info: 'Hours before a node is considered inactive',
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/settings/admin') {
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
  });

  it('renders settings rows for the selected service', async () => {
    mockList.mockResolvedValue([
      makeSetting(),
      makeSetting({ ID: 2, Name: 'NodeDashboard', Type: 'boolean', Boolean: true, Integer: 0 }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('InactiveHours')).toBeInTheDocument();
    });
    expect(screen.getByText('NodeDashboard')).toBeInTheDocument();
  });

  it('shows empty state when no settings exist', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No settings for admin.')).toBeInTheDocument();
    });
  });

  it('patches an integer setting when Save is clicked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSetting()]);
    mockPatch.mockResolvedValue(makeSetting({ Integer: 48 }));

    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('InactiveHours')).toBeInTheDocument();
    });

    const input = screen.getByDisplayValue('24');
    await user.clear(input);
    await user.type(input, '48');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(mockPatch).toHaveBeenCalledTimes(1);
    });
    const args = mockPatch.mock.calls[0] as [string, string, { integer: number }];
    expect(args[0]).toBe('admin');
    expect(args[1]).toBe('InactiveHours');
    expect(args[2].integer).toBe(48);
  });
});
