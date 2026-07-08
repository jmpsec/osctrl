import { describe, it, expect, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRouter,
  createRoute,
  createRootRoute,
  RouterProvider,
  Outlet,
} from '@tanstack/react-router';
import { usePageTitle } from './usePageTitle';

function Probe({ page }: { page: string }) {
  usePageTitle(page);
  return null;
}

function makeRouter(initialPath: string, page: string) {
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
  const nodesRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes',
    component: () => <Probe page={page} />,
  });
  const auditRoute = createRoute({
    getParentRoute: () => appRoute,
    path: 'audit',
    component: () => <Probe page={page} />,
  });
  const routeTree = rootRoute.addChildren([
    appRoute.addChildren([auditRoute, envRoute.addChildren([nodesRoute])]),
  ]);
  const history = createMemoryHistory({ initialEntries: [initialPath] });
  return createRouter({ routeTree, history });
}

function renderWith(router: ReturnType<typeof makeRouter>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('usePageTitle', () => {
  afterEach(() => {
    document.title = '';
  });

  it('sets "Page: env" for env-scoped routes', async () => {
    renderWith(makeRouter('/_app/env/dev/nodes', 'Nodes'));
    // Wait a tick for the router to resolve and effects to flush.
    await new Promise((r) => setTimeout(r, 0));
    expect(document.title).toBe('Nodes: dev');
  });

  it('sets "Page · osctrl" for routes without an environment', async () => {
    renderWith(makeRouter('/_app/audit', 'Audit'));
    await new Promise((r) => setTimeout(r, 0));
    expect(document.title).toBe('Audit · osctrl');
  });

  it('updates when the environment changes', async () => {
    const router = makeRouter('/_app/env/dev/nodes', 'Nodes');
    renderWith(router);
    await new Promise((r) => setTimeout(r, 0));
    expect(document.title).toBe('Nodes: dev');
    await router.navigate({ to: '/_app/env/$env/nodes', params: { env: 'prod' } });
    await new Promise((r) => setTimeout(r, 0));
    expect(document.title).toBe('Nodes: prod');
  });
});
