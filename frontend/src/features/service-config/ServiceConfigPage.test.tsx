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
import { ServiceConfigPage } from './ServiceConfigPage';
import type { ServiceConfig } from '$/api/service-config';

const mockList = vi.fn<(service: string) => Promise<ServiceConfig[]>>();

vi.mock('$/api/service-config', () => ({
  listServiceConfig: (service: string) => mockList(service),
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

// Monaco Editor is lazy-loaded and not available in jsdom.
vi.mock('@monaco-editor/react', () => ({
  Editor: ({ value }: { value: string }) => (
    <div data-testid="monaco-editor" data-value={value} />
  ),
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

  it('pretty-prints JSON values in the editor', async () => {
    mockList.mockResolvedValue([
      makeSection({ Value: '{"type":"stdout","alwaysLog":true}' }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      const editor = screen.getByTestId('monaco-editor');
      const value = editor.getAttribute('data-value') ?? '';
      // Pretty-printed JSON should contain newlines and indentation.
      expect(value).toContain('\n');
      expect(value).toContain('"type": "stdout"');
    });
  });

  it('renders raw value when it is not valid JSON', async () => {
    mockList.mockResolvedValue([
      makeSection({ Value: 'not-json' }),
    ]);
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      const editor = screen.getByTestId('monaco-editor');
      expect(editor.getAttribute('data-value')).toBe('not-json');
    });
  });
});
