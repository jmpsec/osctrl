import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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
import { DashboardPage } from './DashboardPage';
import type { StatsResponse } from '$/api/stats';

// ---------------------------------------------------------------------------
// Mock the stats API module
// ---------------------------------------------------------------------------
const mockGetStats = vi.fn<() => Promise<StatsResponse>>();

vi.mock('$/api/stats', () => ({
  getStats: () => mockGetStats(),
  // Other dashboard panels call these; tests don't assert on them, so
  // resolve to empty so the queries don't reject and trigger extra logs.
  getOsqueryVersionCounts: () => Promise.resolve([]),
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
function makeStatsResponse(overrides: Partial<StatsResponse> = {}): StatsResponse {
  return {
    total_nodes: 10,
    active_nodes: 7,
    inactive_nodes: 3,
    inactive_hours: 72,
    total_active_queries: 2,
    total_active_carves: 1,
    platform_counts: { linux: 6, darwin: 2, windows: 2, other: 0 },
    environments: [
      {
        uuid: 'env-uuid-1',
        name: 'prod',
        active: 5,
        inactive: 2,
        total: 7,
        active_queries: 1,
        active_carves: 0,
        platform_counts: { linux: 4, darwin: 2, windows: 1, other: 0 },
      },
      {
        uuid: 'env-uuid-2',
        name: 'staging',
        active: 2,
        inactive: 1,
        total: 3,
        active_queries: 1,
        active_carves: 1,
        platform_counts: { linux: 2, darwin: 0, windows: 1, other: 0 },
      },
    ],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test harness: wrap DashboardPage in a minimal router + QueryClient
// ---------------------------------------------------------------------------
function makeTestRouter() {
  const rootRoute = createRootRoute({ component: Outlet });

  const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/_app',
    component: Outlet,
  });

  const dashRoute = createRoute({
    getParentRoute: () => appRoute,
    path: '/',
    component: DashboardPage,
  });

  // Env nodes route so Link to="/_app/env/$env/nodes" resolves correctly.
  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });

  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <div data-testid="nodes-page">nodes</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      dashRoute,
      envRoute.addChildren([nodesRoute]),
    ]),
  ]);

  const history = createMemoryHistory({ initialEntries: ['/_app/'] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton cards while loading (no data yet)', () => {
    // Never resolves during this test — simulates pending network request
    mockGetStats.mockReturnValue(new Promise(() => {}));
    renderWithProviders(makeTestRouter());
    // While loading, env names are not in the DOM
    expect(screen.queryByText('prod')).not.toBeInTheDocument();
    expect(screen.queryByText('staging')).not.toBeInTheDocument();
  });

  it('renders the page header', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    );
    expect(screen.getByText('overview')).toBeInTheDocument();
  });

  it('renders KPI card labels from the stats response', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive ≥ 72h')).toBeInTheDocument();
    expect(screen.getByText('Active Queries')).toBeInTheDocument();
    expect(screen.getByText('Forensic Carves')).toBeInTheDocument();
  });

  it('uses the backend stats threshold for inactive labeling', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ inactive_hours: 168 }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive ≥ 168h')).toBeInTheDocument();
  });

  it('renders one tile per environment', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('prod')).toBeInTheDocument());
    expect(screen.getByText('staging')).toBeInTheDocument();
  });

  it('renders env tile links to /env/{uuid}/nodes', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('prod')).toBeInTheDocument());

    const links = screen.getAllByRole('link');
    const hrefs = links.map((l) => l.getAttribute('href')).filter(Boolean);
    expect(hrefs).toContain('/_app/env/env-uuid-1/nodes');
    expect(hrefs).toContain('/_app/env/env-uuid-2/nodes');
  });

  it('shows empty state when environments array is empty', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ environments: [] }));
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByText('No environments configured.')).toBeInTheDocument(),
    );
  });

  it('shows error state and retry button when the API call fails', async () => {
    mockGetStats.mockRejectedValue(new Error('network failure'));
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByText('Failed to load stats.')).toBeInTheDocument(),
    );
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  // Regression: when the backend returns inactive_hours: 0 (e.g. setting
  // missing from DB), the dashboard must fall back to the default 72h
  // label rather than showing "Inactive >= 0h".
  it('falls back to default inactive threshold when API returns 0', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse({ inactive_hours: 0 }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive \u2265 72h')).toBeInTheDocument();
    expect(screen.queryByText('Inactive \u2265 0h')).not.toBeInTheDocument();
  });
});
