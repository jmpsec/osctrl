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
import { CarvesListPage } from './CarvesListPage';
import { carvesSearchSchema } from '$/routes/_app/env/$env/carves';
import type { CarvesPagedResponse, DistributedQuery } from '$/api/types';

const mockList = vi.fn<(p: unknown) => Promise<CarvesPagedResponse>>();

vi.mock('$/api/carves', () => ({
  listCarves: (params: unknown) => mockList(params),
  getCarve: vi.fn(),
  runCarve: vi.fn(),
  getCarveArchiveUrl: () => '/api/v1/carves/test-env/archive/carve_x',
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

function makeCarve(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 99,
    created_at: new Date(Date.now() - 120_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'carve_abcdef',
    creator: 'analyst',
    query: "SELECT * FROM carves WHERE carve=1 AND path = '/etc/hosts';",
    expected: 2,
    executions: 1,
    errors: 0,
    active: true,
    hidden: false,
    protected: false,
    completed: false,
    deleted: false,
    expired: false,
    type: 'carve',
    path: '/etc/hosts',
    environment_id: 1,
    extra_data: '',
    expiration: '0001-01-01T00:00:00Z',
    target: 'platform=linux',
    ...overrides,
  };
}

function makeResponse(overrides: Partial<CarvesPagedResponse> = {}): CarvesPagedResponse {
  return {
    items: [makeCarve()],
    page: 1,
    page_size: 50,
    total_items: 1,
    total_pages: 1,
    ...overrides,
  };
}

function makeTestRouter(initialPath = '/_app/env/test-env/carves') {
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
  const carvesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'carves',
    validateSearch: carvesSearchSchema,
    component: CarvesListPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([carvesRoute])]),
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

describe('CarvesListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders carve rows after loading', async () => {
    mockList.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('carve_abcdef')).toBeInTheDocument();
    });
    expect(screen.getByText('analyst')).toBeInTheDocument();
    expect(screen.getByText('/etc/hosts')).toBeInTheDocument();
  });

  it('shows the empty state with a "Start first carve" CTA when none exist', async () => {
    mockList.mockResolvedValue(
      makeResponse({ items: [], total_items: 0, total_pages: 0 }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No carves yet.')).toBeInTheDocument();
    });
    expect(
      screen.getByRole('link', { name: /start first carve/i }),
    ).toBeInTheDocument();
  });

  it('passes search params through to listCarves', async () => {
    mockList.mockResolvedValue(makeResponse());
    renderWithProviders(
      makeTestRouter('/_app/env/test-env/carves?target=active&sort=name&dir=asc'),
    );

    await waitFor(() => {
      expect(mockList).toHaveBeenCalled();
    });
    const firstCall = mockList.mock.calls[0];
    expect(firstCall).toBeDefined();
    const args = firstCall?.[0] as {
      env: string;
      target: string;
      sort: string;
      dir: string;
    };
    expect(args.env).toBe('test-env');
    expect(args.target).toBe('active');
    expect(args.sort).toBe('name');
    expect(args.dir).toBe('asc');
  });
});
