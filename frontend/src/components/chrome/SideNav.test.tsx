import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type { Features } from '$/api/features';
import type { UserMeResponse } from '$/api/types';
import { SideNav } from './SideNav';

const mockGetFeatures = vi.fn<() => Promise<Features>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();

vi.mock('./EnvSwitcher', () => ({ EnvSwitcher: () => null }));
vi.mock('$/api/features', () => ({ getFeatures: () => mockGetFeatures() }));
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));
vi.mock('$/api/environments', () => ({
  listEnvironments: () => Promise.resolve([{ id: 1, name: 'dev', uuid: 'env-uuid' }]),
}));

function makeMe(overrides: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'u', email: '', fullname: 'u', admin: false, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: 'aaaa',
    token_expire: '', last_access: '', permissions: {}, preferred_language: '',
    ...overrides,
  };
}

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

describe('SideNav extensions entry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is shown to super admins', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, osctrld: true });
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    renderNav();
    const link = await screen.findByRole('link', { name: 'Extensions' });
    expect(link).toHaveAttribute('href', '/_app/extensions');
  });

  it('is hidden from non-admins', async () => {
    mockGetFeatures.mockResolvedValue(baseFeatures);
    mockGetMe.mockResolvedValue({ admin: false, permissions: { 'env-uuid': { user: true, query: false, carve: false, admin: false } } });
    renderNav();
    await settle();
    expect(screen.queryByRole('link', { name: 'Extensions' })).not.toBeInTheDocument();
  });
});

describe('SideNav osquery versions entry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is shown to super admins', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, osctrld: true });
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    renderNav();
    const link = await screen.findByRole('link', { name: 'Osquery versions' });
    expect(link).toHaveAttribute('href', '/_app/osquery-versions');
  });

  it('is hidden from environment admins', async () => {
    mockGetFeatures.mockResolvedValue(baseFeatures);
    mockGetMe.mockResolvedValue({ admin: false, permissions: { 'env-uuid': { user: true, query: false, carve: false, admin: true } } });
    renderNav();
    await settle();
    expect(screen.queryByRole('link', { name: 'Osquery versions' })).not.toBeInTheDocument();
  });
});

describe('SideNav osctrld-gated admin entries', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  const names = ['Extensions', 'Osquery versions'];
  const nonAdmin = { admin: false, permissions: { 'env-uuid': { user: true, query: false, carve: false, admin: true } } };

  it('shows both to super admins when osctrld is enabled', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, osctrld: true });
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    renderNav();
    await settle();
    for (const n of names) expect(await screen.findByRole('link', { name: n })).toBeInTheDocument();
  });

  it.each([['false', { osctrld: false }], ['absent', {}]])('hides both when osctrld is %s', async (_l, extra) => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, service_config: true, ...extra });
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    renderNav();
    await settle();
    for (const n of names) expect(screen.queryByRole('link', { name: n })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Service Config' })).toBeInTheDocument();
  });

  it('never shows them to non-super-admins', async () => {
    mockGetFeatures.mockResolvedValue({ ...baseFeatures, osctrld: true });
    mockGetMe.mockResolvedValue(nonAdmin);
    renderNav();
    await settle();
    for (const n of names) expect(screen.queryByRole('link', { name: n })).not.toBeInTheDocument();
  });
});

describe('SideNav role-aware sections', () => {
  const allFeatures: Features = {
    ...baseFeatures, vulnerabilities: true, alerts: true, health: true, log_sinks: true,
    service_config: true, auth_providers: true,
  };
  const adminLinks = ['Operators', 'Environments', 'Alerts', 'Health'];
  const cases: [string, Partial<UserMeResponse>, string[]][] = [
    ['superuser', { admin: true }, [...adminLinks, 'Settings', 'Log Sinks']],
    ['user admin', { user_admin: true }, adminLinks],
    ['environment manager', { env_manager: true }, adminLinks],
    ['read-only admin', { read_only_admin: true }, adminLinks],
    ['alert admin', { alert_admin: true }, ['Alerts']],
    ['plain user', {}, []],
  ];
  it.each(cases)('shows the right admin links to a %s', async (_name, role, expected) => {
    mockGetFeatures.mockResolvedValue(allFeatures);
    mockGetMe.mockResolvedValue(
      makeMe({ ...role, permissions: { 'env-uuid': { user: true, query: false, carve: false, admin: false } } }),
    );
    renderNav();
    await settle();
    for (const name of [...adminLinks, 'Settings', 'Log Sinks']) {
      const el = screen.queryByRole('link', { name });
      if (expected.includes(name)) expect(el).toBeInTheDocument();
      else expect(el).not.toBeInTheDocument();
    }
  });

  it('lets a read-only admin read an environment but not administer it', async () => {
    mockGetFeatures.mockResolvedValue(allFeatures);
    mockGetMe.mockResolvedValue(makeMe({ read_only_admin: true }));
    renderNav();
    await settle();
    for (const name of ['Nodes', 'Queries', 'Carves']) {
      expect(screen.getByRole('link', { name })).toBeInTheDocument();
    }
    // The server requires environment admin for these.
    for (const name of ['Vulnerabilities', 'Tags', 'Enrollment', 'Configuration']) {
      expect(screen.queryByRole('link', { name })).not.toBeInTheDocument();
    }
  });

  it('shows carves to a user with the tags carve tier', async () => {
    mockGetFeatures.mockResolvedValue(baseFeatures);
    mockGetMe.mockResolvedValue(
      makeMe({ permissions: { 'env-uuid': { user: false, query: false, carve: true, carve_tier: 'tags', admin: false } } }),
    );
    renderNav();
    await settle();
    expect(screen.getByRole('link', { name: 'Carves' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Queries' })).not.toBeInTheDocument();
  });
});
