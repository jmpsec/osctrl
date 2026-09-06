import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRouter, createRoute, createRootRoute,
  RouterProvider, Outlet,
} from '@tanstack/react-router';
import { HealthPage } from './HealthPage';
import type { HealthStatus } from '$/api/health';

const mockGetHealth = vi.fn<() => Promise<HealthStatus>>();
vi.mock('$/api/health', () => ({
  getHealthStatus: () => mockGetHealth(),
}));

function makeStatus(overrides: Partial<HealthStatus> = {}): HealthStatus {
  return {
    generated_at: new Date().toISOString(),
    components: [
      { id: 'database', name: 'Database', status: 'operational', summary: 'reachable in 2ms' },
      { id: 'redis', name: 'Redis', status: 'operational', summary: 'PING ok in 1ms' },
      {
        id: 'api', name: 'osctrl-api', status: 'operational', summary: 'up 1h0m0s, 56 goroutines',
        details: { version: '0.5.8', goroutines: 56, runtime: { heap_alloc: 70254592, num_gc: 26440 } },
      },
      { id: 'tls', name: 'osctrl-tls', status: 'stale', summary: 'last reported 4m0s ago' },
      { id: 'workers', name: 'Workers', status: 'degraded', summary: 'alerts worker dropped 12 hits' },
    ],
    upgrade: { current: '0.5.8', suggested: '0.5.8', latest: '0.5.9', up_to_date: true, checked: true, skew: false },
    ...overrides,
  };
}

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const pageRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: HealthPage });
  const history = createMemoryHistory({ initialEntries: ['/'] });
  const router = createRouter({ routeTree: rootRoute.addChildren([pageRoute]), history });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('HealthPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetHealth.mockResolvedValue(makeStatus());
  });

  it('lists every component with its status', async () => {
    renderPage();
    expect(await screen.findByText('Database')).toBeInTheDocument();
    expect(screen.getByText('osctrl-tls')).toBeInTheDocument();
    expect(screen.getAllByText('Operational').length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText('Stale')).toBeInTheDocument();
    expect(screen.getByText('Degraded')).toBeInTheDocument();
  });

  it('expands a component to show its details without refetching', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: /osctrl-api/ }));
    // Exact match on the capitalized detail-row label: the row's own
    // summary text already contains the lowercase substring "goroutines"
    // ("up 1h0m0s, 56 goroutines"), so a case-insensitive /goroutines/i
    // regex matches both it and the expanded label and throws for
    // multiple matches. The exact string only matches the label.
    expect(await screen.findByText('Goroutines')).toBeInTheDocument();
    expect(mockGetHealth).toHaveBeenCalledTimes(1);
  });

  it('shows upgrade status and hides the skew row when versions agree', async () => {
    renderPage();
    expect(await screen.findByText('0.5.9')).toBeInTheDocument();
    expect(screen.queryByText(/version mismatch/i)).not.toBeInTheDocument();
  });

  it('calls out version skew between services', async () => {
    mockGetHealth.mockResolvedValue(makeStatus({
      upgrade: { current: '0.5.8', suggested: '0.5.8', latest: '0.5.9', up_to_date: true, checked: true, skew: true, api_version: '0.5.8', tls_version: '0.5.7' },
    }));
    renderPage();
    expect(await screen.findByText(/version mismatch/i)).toBeInTheDocument();
  });
});
