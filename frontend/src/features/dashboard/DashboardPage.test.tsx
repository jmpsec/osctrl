import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
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
import userEvent from '@testing-library/user-event';
import type { NodeTileSeries, StatsResponse, ErrorNodeRow } from '$/api/stats';

// ---------------------------------------------------------------------------
// Mock the stats API module
// ---------------------------------------------------------------------------
const mockGetStats = vi.fn<() => Promise<StatsResponse>>();
const mockGetEnvActivityTiles = vi.fn<(env: string, days?: number) => Promise<NodeTileSeries>>();
const mockGetEnvErrorNodes = vi.fn<(env: string, days?: number) => Promise<ErrorNodeRow[]>>();

vi.mock('$/api/stats', async () => {
  const actual = await vi.importActual<typeof import('$/api/stats')>('$/api/stats');
  return {
    ...actual,
    getStats: () => mockGetStats(),
    // Other dashboard panels call these; tests don't assert on them, so
    // resolve to empty so the queries don't reject and trigger extra logs.
    getOsqueryVersionCounts: () => Promise.resolve([]),
    getEnvActivityTiles: (env: string, days?: number) => mockGetEnvActivityTiles(env, days),
    getEnvErrorNodes: (env: string, days?: number) => mockGetEnvErrorNodes(env, days),
  };
});

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

function makeTileSeries(overrides: Partial<NodeTileSeries> = {}): NodeTileSeries {
  const buckets = 24;
  const start = new Date(Date.now() - (buckets - 1) * 60 * 60 * 1000).toISOString();
  const zeros = () => Array.from({ length: buckets }, () => 0);
  return {
    start,
    bucket_seconds: 3600,
    enroll: zeros(),
    status_error: zeros(),
    config: [...zeros().slice(0, buckets - 1), 3],
    status: [...zeros().slice(0, buckets - 2), 1, 2],
    result: [...zeros().slice(0, buckets - 3), 2, 1, 1],
    query_read: [...zeros().slice(0, buckets - 1), 1],
    query_write: [...zeros().slice(0, buckets - 1), 1],
    total: [...zeros().slice(0, buckets - 3), 2, 2, 7],
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

  // Env layout route — DashboardPage is now mounted under env/$env
  const envRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'env/$env',
    component: Outlet,
  });

  const dashRoute = createRoute({
    getParentRoute: () => envRoute,
    path: '/',
    component: DashboardPage,
  });

  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <div data-testid="nodes-page">nodes</div>,
  });

  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([
      envRoute.addChildren([dashRoute, nodesRoute]),
    ]),
  ]);

  const history = createMemoryHistory({ initialEntries: ['/_app/env/prod'] });
  return createRouter({ routeTree, history });
}

function renderWithProviders(router: ReturnType<typeof makeTestRouter>) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  let ui: ReturnType<typeof render>;
  act(() => {
    ui = render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
  });
  return ui!;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    mockGetEnvErrorNodes.mockResolvedValue([]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows skeleton cards while loading (no data yet)', async () => {
    // Never resolves during this test — simulates pending network request
    mockGetStats.mockReturnValue(new Promise(() => {}));
    renderWithProviders(makeTestRouter());
    // Let the router's async route match resolve inside act() so the
    // MatchesInner state update does not leak out as an unhandled act warning.
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    // While loading, env names are not in the DOM
    expect(screen.queryByText('prod')).not.toBeInTheDocument();
    expect(screen.queryByText('staging')).not.toBeInTheDocument();
  });

  it('fetches 2 days of activity tiles so the trailing 24h window spans the UTC day boundary', async () => {
    // The Redis tile blobs are aligned to UTC midnight. Fetching days=1
    // right after midnight yields a single hourly bucket and the activity
    // chart rendered nothing; the trailing 12h/24h windows need 2 days.
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());
    await waitFor(() => expect(mockGetEnvActivityTiles).toHaveBeenCalled());
    for (const call of mockGetEnvActivityTiles.mock.calls) {
      expect(call[1]).toBe(2);
    }
  });

  it('renders the page header', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    );
    expect(screen.getByText(/overview/)).toBeInTheDocument();
  });

  it('renders KPI card labels from the stats response', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Active Nodes')).toBeInTheDocument());

    expect(screen.getByText('Inactive ≥ 72h')).toBeInTheDocument();
    expect(screen.getByText('Active Queries')).toBeInTheDocument();
    expect(screen.getByText('Forensic Carves')).toBeInTheDocument();
  });

  // The tile replaced a "Failed enrolls" counter that read the audit log.
  // It now sums ERROR-severity status logs from the activity rollup, which is
  // the only source that works whatever logger.type the deployment uses.
  it('sums the last 24h of status errors into the reported-errors tile', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(
      makeTileSeries({ status_error: [2, 0, 3] }),
    );
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(await screen.findByText('5 in 24h — see nodes')).toBeInTheDocument();
    // The old tile must be gone, not merely relabeled.
    expect(screen.queryByText('Failed enrolls (24h)')).not.toBeInTheDocument();
  });

  it('reads all clear when no errors were reported', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(screen.getByText('all clear')).toBeInTheDocument();
  });

  it('opens the erroring-nodes drill-down from the tile', async () => {
    const user = userEvent.setup();
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries({ status_error: [4] }));
    mockGetEnvErrorNodes.mockResolvedValue([
      { uuid: 'NODE-1', hostname: 'web-01', errors: 3 },
      // A node deleted since it errored keeps its row, shown by UUID.
      { uuid: 'NODE-2', hostname: '', errors: 1 },
    ]);
    renderWithProviders(makeTestRouter());

    const tile = await screen.findByRole('button', { name: /nodes reporting errors/i });
    await user.click(tile);

    expect(await screen.findByText('web-01')).toBeInTheDocument();
    expect(screen.getByText('NODE-2')).toBeInTheDocument();
    expect(mockGetEnvErrorNodes).toHaveBeenCalled();
  });

  // A tile with nothing behind it must not look clickable.
  it('leaves the errors tile inert when there are no errors', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries());
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Reported errors (24h)')).toBeInTheDocument());
    expect(
      screen.queryByRole('button', { name: /nodes reporting errors/i }),
    ).not.toBeInTheDocument();
  });

  it('shows an Errors row in endpoint health', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(makeTileSeries({ status_error: [7] }));
    renderWithProviders(makeTestRouter());

    await waitFor(() => expect(screen.getByText('Errors')).toBeInTheDocument());
  });

  it('draws the errors line in the activity chart', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    mockGetEnvActivityTiles.mockResolvedValue(
      makeTileSeries({ status_error: [0, 2, 0, 5] }),
    );
    renderWithProviders(makeTestRouter());

    const chart = await screen.findByRole('img', {
      name: /Node activity by category/i,
    });

    // The chart element exists before the tiles query resolves, so wait on
    // the drawn data rather than on the element — every path is d="" until
    // the series arrives.
    await waitFor(() => {
      const errorLine = chart.querySelector('path[stroke="#ff4d4f"]');
      expect(errorLine?.getAttribute('d')).toBeTruthy();
    });

    // One line per category, errors included and styled like the rest.
    const strokes = Array.from(chart.querySelectorAll('path')).map((p) =>
      p.getAttribute('stroke'),
    );
    expect(strokes).toContain('#ff4d4f');
    expect(chart.querySelectorAll('circle')).toHaveLength(0);

    // And it is recolourable like every other line.
    expect(screen.getByLabelText('error color')).toBeInTheDocument();
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

    await waitFor(() => { expect(screen.getAllByText('prod').length).toBeGreaterThanOrEqual(1); });
    expect(screen.getAllByText('staging').length).toBeGreaterThanOrEqual(1);
  });

  it('renders env tile links to /env/{uuid}/nodes', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() => {
      expect(screen.getAllByText('prod').length).toBeGreaterThanOrEqual(1);
    });

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

  it('shows endpoint health instead of recent enrollments', async () => {
    mockGetStats.mockResolvedValue(makeStatsResponse());
    renderWithProviders(makeTestRouter());

    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    );

    expect(screen.getByText('Endpoint health')).toBeInTheDocument();
    expect(await screen.findByText('Query read')).toBeInTheDocument();
    expect(screen.getByText('Query write')).toBeInTheDocument();
    expect(screen.queryByText('Recent enrollments')).not.toBeInTheDocument();
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
