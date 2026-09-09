import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRouter, createRoute, createRootRoute,
  RouterProvider, Outlet,
} from '@tanstack/react-router';
import { HealthPage } from './HealthPage';
import type { HealthStatus } from '$/api/health';
import { setLanguageEphemeral } from '$/i18n/i18n';

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

  afterEach(async () => {
    await act(() => setLanguageEphemeral('en'));
  });

  it('updates translated headings, statuses, details, and numbers when the language changes', async () => {
    const user = userEvent.setup();
    mockGetHealth.mockResolvedValue(makeStatus({
      components: [{
        id: 'database', name: 'Database', status: 'operational', summary: 'reachable in 2ms',
        details: {
          degraded: false, latency_ms: 2.5, diagnostic_code: 'DB_OK',
          reported_at: '2026-09-09T10:00:00.000Z',
        },
      }],
    }));
    renderPage();
    await user.click(await screen.findByRole('button', { name: /Database/ }));
    await act(() => setLanguageEphemeral('es'));

    expect(screen.getByRole('heading', { name: 'Estado de salud' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Servicios' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Estado de actualización' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Estado del sistema' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Actualizar' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Base de datos/ })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText('Operativo')).toBeInTheDocument();
    expect(screen.getByText('Latencia (ms)')).toBeInTheDocument();
    expect(screen.getByText('2,5')).toBeInTheDocument();
    expect(screen.getByText(new Intl.DateTimeFormat('es-ES', {
      dateStyle: 'medium', timeStyle: 'medium',
    }).format(new Date('2026-09-09T10:00:00.000Z')))).toBeInTheDocument();
    expect(screen.getByText('sí')).toBeInTheDocument();
    expect(screen.getByText('DB_OK')).toBeInTheDocument();
    expect(screen.getByText('reachable in 2ms')).toBeInTheDocument();
    expect(screen.getByText('Diagnostic code')).toBeInTheDocument();
    expect(mockGetHealth).toHaveBeenCalledTimes(1);
  });

  it('translates runtime labels and interpolates version warnings in Catalan', async () => {
    await setLanguageEphemeral('ca');
    mockGetHealth.mockResolvedValue(makeStatus({
      upgrade: { current: '0.5.8', up_to_date: false, checked: false, skew: true, api_version: '0.5.8', tls_version: '0.5.7' },
    }));
    renderPage();
    expect(await screen.findByText('en directe')).toBeInTheDocument();
    expect(screen.getByText('Heap assignat')).toBeInTheDocument();
    expect(screen.getByText('La comprovació de noves versions encara no s’ha executat')).toBeInTheDocument();
    expect(screen.getByText('Versions diferents — osctrl-api 0.5.8 / osctrl-tls 0.5.7')).toBeInTheDocument();
    expect(screen.queryByText('Health Status')).not.toBeInTheDocument();
  });

  it('translates the error heading while preserving the API diagnostic', async () => {
    await setLanguageEphemeral('es');
    mockGetHealth.mockRejectedValue(new Error('health reporting not enabled'));
    renderPage();
    expect(await screen.findByText('Datos de salud no disponibles')).toBeInTheDocument();
    expect(screen.getByText('health reporting not enabled')).toBeInTheDocument();
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

  it('labels each runtime card live or as-of, so stale numbers are obvious', async () => {
    const reported = '2026-09-06T10:00:00.000Z';
    mockGetHealth.mockResolvedValue(makeStatus({
      components: [
        {
          id: 'api', name: 'osctrl-api', status: 'operational', summary: 'up 1h0m0s, 56 goroutines',
          details: { version: '0.5.8', goroutines: 56, runtime: { heap_alloc: 70254592, num_gc: 26440 } },
        },
        {
          id: 'tls', name: 'osctrl-tls', status: 'operational', summary: 'up 2h0m0s, 71 goroutines',
          details: { version: '0.5.8', reported_at: reported, goroutines: 71, runtime: { heap_alloc: 12345678, num_gc: 99 } },
        },
      ],
    }));
    renderPage();
    // The API reads its own runtime while serving the request.
    expect(await screen.findByText('live')).toBeInTheDocument();
    // The TLS card came from a heartbeat, so it is timestamped.
    expect(screen.getByText(new RegExp(`as of ${new Date(reported).toLocaleTimeString()}`))).toBeInTheDocument();
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

  it('shows the check has not run instead of a stale verdict when upgrade.checked is false', async () => {
    mockGetHealth.mockResolvedValue(makeStatus({
      upgrade: { current: '0.5.8', up_to_date: false, checked: false, skew: false },
    }));
    renderPage();
    expect(await screen.findByText(/upstream check has not run yet/i)).toBeInTheDocument();
    expect(screen.queryByText(/up to date/i)).not.toBeInTheDocument();
    expect(screen.queryByText('no')).not.toBeInTheDocument();
  });
});
