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
import { QueryDetailPage } from './QueryDetailPage';
import type { DistributedQuery, QueryResultsResponse } from '$/api/types';

const mockGetQuery = vi.fn<() => Promise<DistributedQuery>>();
const mockListQueryResults = vi.fn<() => Promise<QueryResultsResponse>>();
const mockActOnQuery = vi.fn<() => Promise<{ message: string }>>();
const mockListNodes = vi.fn<() => Promise<{ items: Array<{ uuid: string; hostname: string; localname: string }> }>>();

vi.mock('$/api/queries', () => ({
  getQuery: (...args: unknown[]) => mockGetQuery(...(args as [])),
  listQueryResults: (...args: unknown[]) => mockListQueryResults(...(args as [])),
  getQueryResultsCSVUrl: () => '/download.csv',
  actOnQuery: (...args: unknown[]) => mockActOnQuery(...(args as [])),
}));

vi.mock('$/api/nodes', () => ({
  listNodes: (...args: unknown[]) => mockListNodes(...(args as [])),
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
}));

function makeQuery(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 1,
    created_at: new Date(Date.now() - 60_000).toISOString(),
    updated_at: new Date().toISOString(),
    name: 'q_test_0001',
    creator: 'admin',
    query: 'SELECT 1;',
    expected: 10,
    executions: 3,
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
    target: '',
    targets: [{ type: 'environment', value: 'test-env' }],
    ...overrides,
  };
}

function makeResults(): QueryResultsResponse {
  return {
    items: [],
    page: 1,
    page_size: 50,
    total_items: 0,
    total_pages: 0,
  };
}

function makeTestRouter(initialPath = '/_app/env/test-env/queries/q_test_0001') {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: '/_app', component: Outlet });
  const envRoute = createRoute({ getParentRoute: () => appRoute, path: 'env/$env', component: Outlet });
  const listRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries',
    component: () => <div data-testid="queries-page">queries</div>,
  });
  const detailRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'queries/$name',
    component: QueryDetailPage,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login">login</div>,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([envRoute.addChildren([listRoute, detailRoute])]),
    loginRoute,
  ]);
  return createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('QueryDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetQuery.mockResolvedValue(makeQuery());
    mockListQueryResults.mockResolvedValue(makeResults());
    mockListNodes.mockResolvedValue({ items: [] });
    mockActOnQuery.mockResolvedValue({ message: 'ok' });
  });

  it('shows a complete button for incomplete queries and triggers the action', async () => {
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());

    const button = await screen.findByRole('button', { name: 'Complete query' });
    await user.click(button);

    await waitFor(() => {
      expect(mockActOnQuery).toHaveBeenCalledWith('test-env', 'q_test_0001', 'complete');
    });
  });

  it('Refresh button reloads the query and its results (refresh everything)', async () => {
    const user = userEvent.setup();
    renderWithProviders(makeTestRouter());

    // Initial load fires both the query and its results.
    await screen.findByText('SELECT 1;');
    const initialQueries = mockGetQuery.mock.calls.length;
    const initialResults = mockListQueryResults.mock.calls.length;
    expect(initialQueries).toBeGreaterThanOrEqual(1);
    expect(initialResults).toBeGreaterThanOrEqual(1);

    // The Refresh button invalidates everything, so both fetch again.
    const refresh = await screen.findByRole('button', { name: 'Refresh query results' });
    await user.click(refresh);
    await waitFor(() => {
      expect(mockGetQuery.mock.calls.length).toBeGreaterThan(initialQueries);
      expect(mockListQueryResults.mock.calls.length).toBeGreaterThan(initialResults);
    });
  });

  it('hides the complete button for completed queries', async () => {
    mockGetQuery.mockResolvedValue(makeQuery({ active: false, completed: true }));
    renderWithProviders(makeTestRouter());

    await screen.findByText('SELECT 1;');
    expect(screen.queryByRole('button', { name: 'Complete query' })).not.toBeInTheDocument();
  });
});
