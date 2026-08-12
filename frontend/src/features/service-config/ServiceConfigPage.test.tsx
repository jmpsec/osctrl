import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
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
import { ServiceConfigPage } from './ServiceConfigPage';
import type { ServiceConfig } from '$/api/service-config';

const mockList = vi.fn<(service: string) => Promise<ServiceConfig[]>>();
const mockUpdate = vi.fn();
const mockApply = vi.fn();

vi.mock('$/api/service-config', () => ({
  listServiceConfig: (service: string) => mockList(service),
  updateServiceConfig: (...args: unknown[]) => mockUpdate(...args),
  applyServiceConfig: () => mockApply(),
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

function makeSection(overrides: Partial<ServiceConfig> = {}): ServiceConfig {
  return {
    ID: 1,
    CreatedAt: new Date().toISOString(),
    UpdatedAt: new Date().toISOString(),
    Name: 'logger',
    Service: 'api',
    EnvironmentID: 0,
    Type: 'json',
    Value: '{"type":"stdout"}',
    Source: 'yaml',
    Editable: false,
    Info: 'Log sinks',
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/config/api') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });
  const configRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'config/$service',
    component: ServiceConfigPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([configRoute]),
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

describe('ServiceConfigPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders service config sections with their names and badges', async () => {
    mockList.mockResolvedValue([
      makeSection(),
      makeSection({
        ID: 2,
        Name: 'saml',
        Value: '{"enabled":true}',
        Source: 'db',
        Editable: true,
        Info: 'SAML federated login',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('logger')).toBeInTheDocument();
    });
    expect(screen.getByText('saml')).toBeInTheDocument();
    expect(screen.getByText('yaml')).toBeInTheDocument();
    expect(screen.getByText('db')).toBeInTheDocument();
    expect(screen.getByText('read-only')).toBeInTheDocument();
    expect(screen.getByText('editable')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('api');
  });

  it('renders the service tabs and switches service on click', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter('/_app/config/tls'));

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'osctrl-tls' })).toBeInTheDocument();
    });
    expect(screen.getByRole('tab', { name: 'osctrl-api' })).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('tls');
  });

  it('shows empty state when no sections are returned', async () => {
    mockList.mockResolvedValue([]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No service config for api.')).toBeInTheDocument();
    });
  });

  it('shows error state when the API fails', async () => {
    const { ApiError } = await import('$/api/client');
    mockList.mockRejectedValue(new ApiError('Internal error', 500));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('Internal error')).toBeInTheDocument();
    });
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders structured form fields for editable sections', async () => {
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'debug',
        Value: '{"enableHttp":false,"httpFile":"/tmp/debug.log","showBody":true}',
        Info: 'HTTP debug dump settings',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('debug')).toBeInTheDocument();
    });
    // Boolean fields render as toggle switches
    expect(screen.getAllByRole('switch').length).toBeGreaterThanOrEqual(1);
    // String fields render as text inputs
    expect(screen.getByDisplayValue('/tmp/debug.log')).toBeInTheDocument();
    // Save button is present but disabled (no changes yet)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('renders read-only values for non-editable sections', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: false,
        Name: 'db',
        Value: '{"Host":"osctrl-postgres","Port":5432}',
        Info: 'Backend connection',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('db')).toBeInTheDocument();
    });
    // Read-only sections are collapsed by default — expand by clicking header
    await user.click(screen.getByText('db'));
    // Read-only sections show values as text, not inputs
    expect(screen.getByText('osctrl-postgres')).toBeInTheDocument();
    expect(screen.getByText('5432')).toBeInTheDocument();
    // No Save button for read-only sections
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });

  it('enables Save button when a field is modified', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'debug',
        Value: '{"enableHttp":false,"httpFile":"/tmp/debug.log"}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByDisplayValue('/tmp/debug.log')).toBeInTheDocument();
    });
    const input = screen.getByDisplayValue('/tmp/debug.log');
    await user.clear(input);
    await user.type(input, '/var/log/debug.log');

    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
  });

  it('calls updateServiceConfig when Save is clicked after editing', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'debug',
        Value: '{"enableHttp":false,"httpFile":"/tmp/debug.log"}',
      }),
    ]);
    mockUpdate.mockResolvedValue(
      makeSection({ Value: '{"enableHttp":false,"httpFile":"/var/log/debug.log"}', Source: 'db' }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByDisplayValue('/tmp/debug.log')).toBeInTheDocument();
    });
    const input = screen.getByDisplayValue('/tmp/debug.log');
    await user.clear(input);
    await user.type(input, '/var/log/debug.log');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(mockUpdate).toHaveBeenCalledTimes(1);
    });
    const args = mockUpdate.mock.calls[0] as [string, string, { value: unknown }];
    expect(args[0]).toBe('api');
    expect(args[1]).toBe('debug');
    expect(args[2].value).toEqual({ enableHttp: false, httpFile: '/var/log/debug.log' });
  });

  it('edits API rate limits and omits TLS-only values when saving', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'rateLimits',
        Value: JSON.stringify({
          login: { burst: 10, period: 60_000_000_000, evictAfter: 600_000_000_000, retryAfter: 60, maxBuckets: 0 },
          preAuth: { burst: 60, period: 60_000_000_000, evictAfter: 600_000_000_000, retryAfter: 60, maxBuckets: 0 },
          serviceConfigApply: { burst: 3, period: 600_000_000_000, evictAfter: 1_800_000_000_000, retryAfter: 60, maxBuckets: 0 },
          enroll: { burst: 20, period: 60_000_000_000, evictAfter: 600_000_000_000, retryAfter: 60, maxBuckets: 0 },
        }),
      }),
    ]);
    mockUpdate.mockResolvedValue(makeSection({ Name: 'rateLimits', Source: 'db' }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('rateLimits')).toBeInTheDocument();
    });
    const loginPeriod = screen.getByLabelText('login period');
    expect(loginPeriod).toHaveValue('1m');
    expect(screen.queryByLabelText('enroll period')).not.toBeInTheDocument();

    await user.clear(loginPeriod);
    await user.type(loginPeriod, '2m');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(mockUpdate).toHaveBeenCalledTimes(1);
    });
    const args = mockUpdate.mock.calls[0] as [string, string, { value: Record<string, Record<string, number>> }];
    expect(args[0]).toBe('api');
    expect(args[1]).toBe('rateLimits');
    expect(args[2].value.login.period).toBe(120_000_000_000);
    expect(args[2].value.login.burst).toBe(10);
    expect(args[2].value.enroll).toBeUndefined();
  });

  it('shows only the TLS enroll rate limit on the tls service page', async () => {
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'rateLimits',
        Service: 'tls',
        Value: JSON.stringify({
          login: { burst: 10, period: 60_000_000_000, evictAfter: 600_000_000_000, retryAfter: 60, maxBuckets: 0 },
          enroll: { burst: 20, period: 60_000_000_000, evictAfter: 600_000_000_000, retryAfter: 60, maxBuckets: 0 },
        }),
      }),
    ]);
    renderWithProviders(makeTestRouter('/_app/config/tls'));

    await waitFor(() => {
      expect(screen.getByText('rateLimits')).toBeInTheDocument();
    });
    expect(screen.getByLabelText('enroll period')).toHaveValue('1m');
    expect(screen.queryByLabelText('login period')).not.toBeInTheDocument();
  });

  it('shows an error when the PUT returns 409 (not editable)', async () => {
    const user = userEvent.setup();
    const { ApiError } = await import('$/api/client');
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'debug',
        Value: '{"enableHttp":false,"httpFile":"/tmp/debug.log"}',
      }),
    ]);
    mockUpdate.mockRejectedValue(new ApiError('section is not editable', 409));
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByDisplayValue('/tmp/debug.log')).toBeInTheDocument();
    });
    const input = screen.getByDisplayValue('/tmp/debug.log');
    await user.clear(input);
    await user.type(input, '/changed');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(screen.getByText('Section is not editable.')).toBeInTheDocument();
    });
  });

  it('renders boolean toggle switches that can be toggled', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: true,
        Name: 'debug',
        Value: '{"enableHttp":false,"showBody":true}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('debug')).toBeInTheDocument();
    });
    const switches = screen.getAllByRole('switch');
    expect(switches).toHaveLength(2);
    // First switch (enableHttp) should be off
    expect(switches[0]).toHaveAttribute('aria-checked', 'false');
    // Toggle it on
    await user.click(switches[0]);
    expect(switches[0]).toHaveAttribute('aria-checked', 'true');
    // Save should now be enabled
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
  });

  it('masks sensitive fields in read-only sections', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: false,
        Name: 'db',
        Value: '{"Host":"localhost","Password":"secret123"}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('db')).toBeInTheDocument();
    });
    // Expand the collapsed read-only section
    await user.click(screen.getByText('db'));
    // Password should be masked
    expect(screen.getByText('●●●●●●')).toBeInTheDocument();
    // The actual value should not be visible
    expect(screen.queryByText('secret123')).not.toBeInTheDocument();
  });

  it('reveals masked sensitive fields when the eye button is clicked', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: false,
        Name: 'db',
        Value: '{"Host":"localhost","Password":"secret123"}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('db')).toBeInTheDocument();
    });
    await user.click(screen.getByText('db'));
    expect(screen.getByText('●●●●●●')).toBeInTheDocument();
    await user.click(screen.getByTitle('Reveal'));
    expect(screen.getByText('secret123')).toBeInTheDocument();
  });

  it('shows "empty" when revealing an empty sensitive field', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: false,
        Name: 'redis',
        Value: '{"Host":"redis-server","Password":""}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('redis')).toBeInTheDocument();
    });
    await user.click(screen.getByText('redis'));
    expect(screen.getByText('●●●●●●')).toBeInTheDocument();
    await user.click(screen.getByTitle('Reveal'));
    expect(screen.getByText('empty')).toBeInTheDocument();
  });

  it('renders string arrays as tag chips in read-only sections', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([
      makeSection({
        Editable: false,
        Name: 'oidc',
        Value: '{"Scopes":["openid","profile","email"]}',
      }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('oidc')).toBeInTheDocument();
    });
    await user.click(screen.getByText('oidc'));
    expect(screen.getByText('openid')).toBeInTheDocument();
    expect(screen.getByText('profile')).toBeInTheDocument();
    expect(screen.getByText('email')).toBeInTheDocument();
  });

  it('does not show Apply & Restart button when no sections have source=db', async () => {
    mockList.mockResolvedValue([makeSection({ Source: 'yaml' })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('logger')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Apply & Restart/i })).not.toBeInTheDocument();
  });

  it('shows Apply & Restart button when a section has source=db', async () => {
    mockList.mockResolvedValue([makeSection({ Source: 'db', Name: 'debug', Editable: true })]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Apply & Restart/i })).toBeInTheDocument();
    });
  });

  it('calls applyServiceConfig when Apply & Restart is confirmed', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Source: 'db', Name: 'debug', Editable: true })]);
    mockApply.mockResolvedValue({ message: 'Restart triggered.' });
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Apply & Restart/i })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: /Apply & Restart/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
    expect(screen.getByRole('dialog')).toHaveTextContent('debug');
    expect(screen.getByRole('button', { name: 'Restart now' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Restart now' }));

    await waitFor(() => {
      expect(mockApply).toHaveBeenCalledTimes(1);
    });
  });

  it('does not call applyServiceConfig when Apply is cancelled', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue([makeSection({ Source: 'db', Name: 'debug', Editable: true })]);
    mockApply.mockResolvedValue({ message: 'Restart triggered.' });
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Apply & Restart/i })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: /Apply & Restart/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
    expect(mockApply).not.toHaveBeenCalled();
  });
});
