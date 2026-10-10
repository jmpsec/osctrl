import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type {
  VulnAdvisoryDetail, VulnFeedStatus, VulnFinding, VulnFindingFilter, VulnFindingsPage, VulnSummary,
} from '$/api/vulnerabilities';
import { VulnerabilitiesPage } from './VulnerabilitiesPage';
import { vulnSearchSchema } from './search';

const mockList = vi.fn<(env: string, filter: VulnFindingFilter) => Promise<VulnFindingsPage>>();
const mockSummary = vi.fn<() => Promise<VulnSummary>>();
const mockAdvisory = vi.fn<() => Promise<VulnAdvisoryDetail>>();
const mockFeeds = vi.fn<() => Promise<VulnFeedStatus>>();
const mockSync = vi.fn<() => Promise<{ message: string }>>();
const mockGetMe = vi.fn<() => Promise<unknown>>();

vi.mock('$/api/vulnerabilities', async () => {
  const actual = await vi.importActual<typeof import('$/api/vulnerabilities')>('$/api/vulnerabilities');
  return {
    ...actual,
    listVulnFindings: (env: string, filter: VulnFindingFilter) => mockList(env, filter),
    getVulnSummary: () => mockSummary(),
    getVulnAdvisory: () => mockAdvisory(),
    getVulnFeeds: () => mockFeeds(),
    requestVulnSync: () => mockSync(),
  };
});
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));

function finding(overrides: Partial<VulnFinding> = {}): VulnFinding {
  return {
    id: 1, node_uuid: 'NODE-A-0000-0001', environment_id: 1, advisory_id: 'DSA-1',
    ecosystem: 'Debian:12', package: 'openssl', installed_version: '3.0.11-1', fixed_version: '3.0.13-1',
    confidence: 'confirmed', severity: 'critical', kev: true,
    first_seen: new Date(Date.now() - 3_600_000).toISOString(), last_seen: new Date().toISOString(),
    resolved_at: null, ...overrides,
  };
}

function summary(overrides: Partial<VulnSummary> = {}): VulnSummary {
  return {
    loaded: true, stale: false,
    by_severity: { critical: { confirmed: 2 }, medium: { confirmed: 1 } },
    kev: 2, possible: 0, affected_nodes: 2, not_assessed: 5, top_advisories: [], top_packages: [],
    ...overrides,
  };
}

function renderPage() {
  const rootRoute = createRootRoute({ component: Outlet });
  const appRoute = createRoute({ getParentRoute: () => rootRoute, path: '/_app', component: Outlet });
  const envRoute = createRoute({ getParentRoute: () => appRoute, path: 'env/$env', component: Outlet });
  const pageRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'vulnerabilities',
    validateSearch: vulnSearchSchema,
    component: VulnerabilitiesPage,
  });
  const nodeRoute = createRoute({
    getParentRoute: () => envRoute,
    path: 'nodes/$uuid',
    component: () => <div>node page</div>,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([appRoute.addChildren([envRoute.addChildren([pageRoute, nodeRoute])])]),
    history: createMemoryHistory({ initialEntries: ['/_app/env/dev/vulnerabilities'] }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...view, router };
}

describe('VulnerabilitiesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMe.mockResolvedValue({ admin: false, permissions: {} });
    mockSummary.mockResolvedValue(summary());
    mockList.mockResolvedValue({
      findings: [finding(), finding({ id: 2, advisory_id: 'DSA-2', package: 'curl', fixed_version: '', severity: 'medium', kev: false })],
      total: 2, page: 1,
    });
  });

  it('counts only confirmed findings in the headline and de-emphasizes possible ones', async () => {
    mockSummary.mockResolvedValue(summary({
      by_severity: { critical: { confirmed: 2, possible: 4 }, medium: { confirmed: 1 } },
      possible: 4,
    }));
    mockList.mockResolvedValue({
      findings: [
        finding(),
        finding({ id: 3, advisory_id: 'CVE-2026-9', ecosystem: 'cpe', package: 'mozilla:firefox', confidence: 'possible', kev: false }),
      ],
      total: 2, page: 1,
    });
    renderPage();
    const possibleRow = (await screen.findByRole('button', { name: 'CVE-2026-9' })).closest('tr');
    expect(possibleRow).toHaveClass('opacity-70');
    expect(screen.getByRole('button', { name: 'DSA-1' }).closest('tr')).not.toHaveClass('opacity-70');
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('Possible matches not counted: 4')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Critical/ })).toHaveTextContent('6');
  });

  it('filters by confidence, starting from the first page', async () => {
    const user = userEvent.setup();
    mockSummary.mockResolvedValue(summary({ by_severity: { critical: { confirmed: 2, possible: 4 } }, possible: 4 }));
    renderPage();
    await user.selectOptions(await screen.findByLabelText('Confidence'), 'possible');
    await waitFor(() =>
      expect(mockList).toHaveBeenLastCalledWith('dev', expect.objectContaining({ confidence: 'possible', page: 1 })),
    );
    expect(screen.getByRole('button', { name: /^Critical/ })).toHaveTextContent('4');
  });

  it('shows the summary and the findings', async () => {
    renderPage();
    expect(await screen.findByRole('button', { name: 'DSA-1' })).toBeInTheDocument();
    expect(screen.getByText('Open findings')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('No fix yet')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'NODE-A-0' })[0]).toHaveAttribute('href', '/_app/env/dev/nodes/NODE-A-0000-0001');
    expect(mockList).toHaveBeenCalledWith('dev', expect.objectContaining({ state: 'open', page: 1, page_size: 50 }));
  });

  it('explains that an empty list means nothing before advisory data loads', async () => {
    mockSummary.mockResolvedValue(summary({ loaded: false }));
    mockList.mockResolvedValue({ findings: [], total: 0, page: 1 });
    renderPage();
    expect(await screen.findByText(/Advisory data has not been loaded yet/)).toBeInTheDocument();
  });

  it('warns when advisory data is stale', async () => {
    mockSummary.mockResolvedValue(summary({ stale: true }));
    renderPage();
    expect(await screen.findByText(/Advisory data is out of date/)).toBeInTheDocument();
  });

  it('goes back to the first page when a filter changes', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue({ findings: [finding()], total: 120, page: 1 });
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Next page' }));
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith('dev', expect.objectContaining({ page: 2 })));
    await user.click(screen.getByRole('button', { name: /^Critical/ }));
    await waitFor(() =>
      expect(mockList).toHaveBeenLastCalledWith('dev', expect.objectContaining({ severity: 'critical', page: 1 })),
    );
  });

  // The environment switcher keeps the sub-route and drops the search, and
  // the router reuses the page component: page 3 of dev must not become a
  // request for page 3 of an environment with ten findings.
  it('starts a newly selected environment on its first page', async () => {
    const user = userEvent.setup();
    mockList.mockResolvedValue({ findings: [finding()], total: 120, page: 1 });
    const { router } = renderPage();
    await user.click(await screen.findByRole('button', { name: 'Next page' }));
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith('dev', expect.objectContaining({ page: 2 })));
    await act(async () => {
      router.history.push('/_app/env/prod/vulnerabilities');
    });
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith('prod', expect.objectContaining({ page: 1 })));
  });

  // Triage is filter, open a node, go Back: the filters must still be set.
  it('keeps the filters after visiting a node and going back', async () => {
    const user = userEvent.setup();
    const { router } = renderPage();
    await user.click(await screen.findByRole('button', { name: /^Critical/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: /^Critical/ })).toHaveAttribute('aria-pressed', 'true'));
    await act(async () => {
      router.history.push('/_app/env/dev/nodes/NODE-A-0000-0001');
    });
    expect(await screen.findByText('node page')).toBeInTheDocument();
    await act(async () => {
      router.history.back();
    });
    await waitFor(() => expect(screen.getByRole('button', { name: /^Critical/ })).toHaveAttribute('aria-pressed', 'true'));
  });

  it('opens the advisory from a finding', async () => {
    const user = userEvent.setup();
    mockAdvisory.mockResolvedValue({
      advisory: {
        id: 'DSA-1', summary: 'openssl: denial of service', details: '', cvss_vector: '', cvss_score: 0,
        severity: 'critical', kev: false, published: '', modified: '',
      },
      aliases: [], references: [], findings: [],
    });
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'DSA-1' }));
    const dialog = await screen.findByRole('dialog', { name: 'DSA-1' });
    expect(await within(dialog).findByText('openssl: denial of service')).toBeInTheDocument();
  });

  it('shows the API error instead of an empty table', async () => {
    mockList.mockRejectedValue(new Error('no access'));
    renderPage();
    expect(await screen.findByText('Could not load vulnerability data.')).toBeInTheDocument();
    expect(screen.getByText('no access')).toBeInTheDocument();
    expect(screen.queryByText('No findings match these filters.')).not.toBeInTheDocument();
  });

  it('shows feed status and requests a sync for super admins', async () => {
    const user = userEvent.setup();
    const now = new Date().toISOString();
    mockGetMe.mockResolvedValue({ admin: true, permissions: {} });
    const feeds: VulnFeedStatus = {
      sources: [
        { source: 'osv:Debian', cursor: now, last_success: now, last_written: 10, last_skipped: 0, last_error: '', last_error_at: null },
        { source: 'kev', cursor: '', last_success: null, last_written: 0, last_skipped: 0, last_error: 'GET kev.json: HTTP 502', last_error_at: now },
      ],
      last_sync_at: now, sync_requested_at: null, last_sync_failed: true, loaded: true, stale: false,
    };
    mockFeeds.mockResolvedValue(feeds);
    mockSync.mockResolvedValue({ message: 'sync requested' });
    renderPage();
    expect(await screen.findByText('osv:Debian')).toBeInTheDocument();
    expect(screen.getByText('Never')).toBeInTheDocument();
    expect(screen.getByText('GET kev.json: HTTP 502')).toBeInTheDocument();

    mockFeeds.mockResolvedValue({ ...feeds, sync_requested_at: now });
    await user.click(screen.getByRole('button', { name: 'Sync now' }));
    expect(mockSync).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/Sync requested/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sync now' })).toBeDisabled();
  });

  it('hides feed status from environment admins', async () => {
    renderPage();
    await screen.findByRole('button', { name: 'DSA-1' });
    expect(screen.queryByText('Advisory feeds')).not.toBeInTheDocument();
    expect(mockFeeds).not.toHaveBeenCalled();
  });
});
