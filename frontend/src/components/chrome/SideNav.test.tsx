import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type { Features } from '$/api/features';
import { SideNav } from './SideNav';

const mockGetFeatures = vi.fn<() => Promise<Features>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();

vi.mock('./EnvSwitcher', () => ({ EnvSwitcher: () => null }));
vi.mock('$/api/features', () => ({ getFeatures: () => mockGetFeatures() }));
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));
vi.mock('$/api/environments', () => ({
  listEnvironments: () => Promise.resolve([{ id: 1, name: 'dev', uuid: 'env-uuid' }]),
}));

const baseFeatures: Features = { posture: false, service_config: false, accelerated: false, file_explorer: false };

function renderNav() {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: '/_app', component: Outlet });
  const envRoute = createRoute({ getParentRoute: () => appRoute, path: 'env/$env', component: Outlet });
  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <SideNav previewsEnabled={false} />,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([appRoute.addChildren([envRoute.addChildren([nodesRoute])])]),
    history: createMemoryHistory({ initialEntries: ['/_app/env/dev/nodes'] }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

async function settle() {
  await waitFor(() => expect(mockGetFeatures).toHaveBeenCalled());
  await screen.findByRole('link', { name: 'Nodes' });
  await act(() => Promise.resolve());
}

describe('SideNav vulnerabilities entry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is shown to environment admins when the feature is on', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, vulnerabilities: true });
    mockGetMe.mockResolvedValue({ admin: false, permissions: { 'env-uuid': { user: true, query: false, carve: false, admin: true } } });
    renderNav();
    const link = await screen.findByRole('link', { name: 'Vulnerabilities' });
    expect(link).toHaveAttribute('href', '/_app/env/dev/vulnerabilities');
  });

  it('is hidden while the feature is off', async () => {
    mockGetFeatures.mockResolvedValue(baseFeatures);
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    renderNav();
    await settle();
    expect(screen.queryByRole('link', { name: 'Vulnerabilities' })).not.toBeInTheDocument();
  });

  // The API answers 403 to anyone below environment admin, so the entry
  // would only lead to an error page.
  it('is hidden from users who cannot administer the environment', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, vulnerabilities: true });
    mockGetMe.mockResolvedValue({ admin: false, permissions: { 'env-uuid': { user: true, query: true, carve: false, admin: false } } });
    renderNav();
    await settle();
    expect(screen.queryByRole('link', { name: 'Vulnerabilities' })).not.toBeInTheDocument();
  });
});
