import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type { Features } from '$/api/features';
import { RequireOsctrld } from './useOsctrldEnabled';

const mockGetFeatures = vi.fn<() => Promise<Features>>();
vi.mock('$/api/features', () => ({ getFeatures: () => mockGetFeatures() }));

const base: Features = { posture: false, service_config: false, accelerated: false, file_explorer: false };

function renderGate(retry: number | false = false) {
  const root = createRootRoute({ component: Outlet });
  const app = createRoute({ getParentRoute: () => root, path: '/_app', component: () => <div>dashboard home</div> });
  const page = createRoute({
    getParentRoute: () => root,
    path: '/_app/extensions',
    component: () => <RequireOsctrld><div>secret page</div></RequireOsctrld>,
  });
  const router = createRouter({
    routeTree: root.addChildren([app, page]),
    history: createMemoryHistory({ initialEntries: ['/_app/extensions'] }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry, retryDelay: 0 } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('RequireOsctrld', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders the page when osctrld is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ ...base, osctrld: true });
    renderGate();
    expect(await screen.findByText('secret page')).toBeInTheDocument();
  });

  it.each([['false', { osctrld: false }], ['absent', {}]])('redirects to the dashboard when osctrld is %s', async (_l, extra) => {
    mockGetFeatures.mockResolvedValue({ ...base, ...extra });
    renderGate();
    expect(await screen.findByText('dashboard home')).toBeInTheDocument();
    expect(screen.queryByText('secret page')).not.toBeInTheDocument();
  });

  it('renders nothing and does not redirect while features load', async () => {
    mockGetFeatures.mockReturnValue(new Promise(() => {}));
    renderGate();
    await waitFor(() => expect(mockGetFeatures).toHaveBeenCalled());
    expect(screen.queryByText('secret page')).not.toBeInTheDocument();
    expect(screen.queryByText('dashboard home')).not.toBeInTheDocument();
  });

  it('redirects to the dashboard once a failing features request has retried', async () => {
    mockGetFeatures.mockRejectedValue(new Error('boom'));
    renderGate(1);
    expect(await screen.findByText('dashboard home')).toBeInTheDocument();
    expect(mockGetFeatures).toHaveBeenCalledTimes(2);
    expect(screen.queryByText('secret page')).not.toBeInTheDocument();
  });

  it('renders nothing while the failed request is being retried', async () => {
    mockGetFeatures.mockRejectedValue(new Error('boom'));
    const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, retryDelay: 60_000 } } });
    const root = createRootRoute({ component: Outlet });
    const app = createRoute({ getParentRoute: () => root, path: '/_app', component: () => <div>dashboard home</div> });
    const page = createRoute({
      getParentRoute: () => root,
      path: '/_app/extensions',
      component: () => <RequireOsctrld><div>secret page</div></RequireOsctrld>,
    });
    const router = createRouter({
      routeTree: root.addChildren([app, page]),
      history: createMemoryHistory({ initialEntries: ['/_app/extensions'] }),
    });
    render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>);
    await waitFor(() => expect(mockGetFeatures).toHaveBeenCalledTimes(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText('secret page')).not.toBeInTheDocument();
    expect(screen.queryByText('dashboard home')).not.toBeInTheDocument();
  });
});
