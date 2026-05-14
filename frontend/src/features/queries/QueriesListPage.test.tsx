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
import { QueriesListPage } from './QueriesListPage';
import { queriesSearchSchema } from '$/routes/_app/env/$env/queries';
import type { QueriesPagedResponse, DistributedQuery } from '$/api/types';

// ---------------------------------------------------------------------------
// Mock the queries API module
// ---------------------------------------------------------------------------
const mockListQueries = vi.fn<() => Promise<QueriesPagedResponse>>();

vi.mock('$/api/queries', () => ({
  listQueries: (...args: unknown[]) => mockListQueries(...(args as [])),
  actOnQuery: vi.fn(),
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
    constructor(
      msg: string,
      public status: number,
      public code?: string,
    ) {
      super(msg);
    }
  },
}));

// ---------------------------------------------------------------------------
// Stub response factory
// ---------------------------------------------------------------------------
function makeQuery(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 1,
    created_at: new Date(Date.now() - 60_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'q_test_0001',
    creator: 'admin',
    query: 'SELECT * FROM osquery_info;',
    expected: 10,
    executions: 7,
    errors: 0,
    active: true,
    hidden: false,
    protected: false,
    completed: false,
    deleted: false,
    expired: false,
    type: 'query',
    path: '',
    environment_id: 1,
    extra_data: '',
    expiration: '0001-01-01T00:00:00Z',
    target: 'platform=linux',
    ...overrides,
  };
}

function makeResponse(
  overrides: Partial<QueriesPagedResponse> = {},
): QueriesPagedResponse {
  return {
    items: [makeQuery()],
    page: 1,
    page_size: 50,
    total_items: 1,
    total_pages: 1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Router factory
// ---------------------------------------------------------------------------
function makeTestRouter(initialPath = '/_app/env/test-env/queries') {
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

  const queriesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries',
    validateSearch: queriesSearchSchema,
    component: QueriesListPage,
  });

  // Stub for "queries/new" link navigation
  const queriesNewRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries/new',
    component: () => <div data-testid="run-page">Run page</div>,
  });

  const queriesDetailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries/$name',
    component: () => <div data-testid="detail-page">Detail page</div>,
  });

  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">Login</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([queriesRoute, queriesNewRoute, queriesDetailRoute]),
    ]),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('QueriesListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders query rows after loading', async () => {
    mockListQueries.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('q_test_0001')).toBeInTheDocument();
    });

    expect(screen.getByText('admin')).toBeInTheDocument();
    expect(screen.getByText('query')).toBeInTheDocument();
  });

  it('shows skeleton rows while loading', () => {
    mockListQueries.mockReturnValue(new Promise(() => {}));
    renderWithProviders(makeTestRouter());
    // Data row should not be present while loading
    expect(screen.queryByText('q_test_0001')).not.toBeInTheDocument();
  });

  it('shows empty state when API returns no items', async () => {
    mockListQueries.mockResolvedValue(
      makeResponse({ items: [], total_items: 0, total_pages: 0 }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('No queries match.')).toBeInTheDocument();
    });
  });

  it('clicking a status tab calls listQueries with updated target', async () => {
    const user = userEvent.setup();
    mockListQueries.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('q_test_0001')).toBeInTheDocument();
    });

    const activeTab = screen.getByRole('tab', { name: /^Active$/i });
    await user.click(activeTab);

    await waitFor(() => {
      const calls = mockListQueries.mock.calls as unknown as Array<[unknown]>;
      const lastArg = calls[calls.length - 1][0] as { target?: string };
      expect(lastArg.target).toBe('active');
    });
  });

  it('multi-select dock toolbar appears when rows are checked', async () => {
    const user = userEvent.setup();
    mockListQueries.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('q_test_0001')).toBeInTheDocument();
    });

    const checkbox = screen.getByRole('checkbox', { name: /select query q_test_0001/i });
    await user.click(checkbox);

    await waitFor(() => {
      expect(screen.getByRole('toolbar', { name: /bulk actions/i })).toBeInTheDocument();
    });

    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('query name cell is a link to the detail page', async () => {
    mockListQueries.mockResolvedValue(makeResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getByText('q_test_0001')).toBeInTheDocument();
    });

    const link = screen.getByRole('link', { name: 'q_test_0001' });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute('href')).toContain('queries');
  });
});
