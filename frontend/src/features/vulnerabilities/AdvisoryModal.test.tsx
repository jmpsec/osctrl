import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider,
} from '@tanstack/react-router';
import type { VulnAdvisoryDetail } from '$/api/vulnerabilities';
import { AdvisoryModal } from './AdvisoryModal';

const mockGetAdvisory = vi.fn<() => Promise<VulnAdvisoryDetail>>();
vi.mock('$/api/vulnerabilities', () => ({
  getVulnAdvisory: () => mockGetAdvisory(),
}));

function detail(overrides: Partial<VulnAdvisoryDetail> = {}): VulnAdvisoryDetail {
  return {
    advisory: {
      id: 'DSA-1',
      summary: '<script>alert(1)</script> in openssl',
      details: 'Line one\nLine two',
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      cvss_score: 7.5,
      severity: 'high',
      kev: true,
      published: '2026-10-01T00:00:00Z',
      modified: '2026-10-02T00:00:00Z',
    },
    aliases: ['CVE-2026-0001'],
    references: [
      'https://security-tracker.debian.org/DSA-1',
      'javascript:alert(1)',
      'http://plain.example.org/x',
    ],
    findings: [{
      id: 1, node_uuid: 'NODE-A-0000-0001', environment_id: 1, advisory_id: 'DSA-1',
      ecosystem: 'Debian:12', package: 'openssl', installed_version: '3.0.11-1', fixed_version: '3.0.13-1',
      confidence: 'confirmed', severity: 'high', kev: true,
      first_seen: '2026-10-09T00:00:00Z', last_seen: '2026-10-10T00:00:00Z', resolved_at: null,
    }],
    ...overrides,
  };
}

function renderModal(onClose = vi.fn()) {
  const rootRoute = createRootRoute({ component: Outlet });
  const pageRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <AdvisoryModal env="dev" advisoryId="DSA-1" onClose={onClose} />,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([pageRoute]),
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('AdvisoryModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAdvisory.mockResolvedValue(detail());
  });

  it('renders feed text literally, never as markup', async () => {
    renderModal();
    expect(await screen.findByText('<script>alert(1)</script> in openssl')).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument();
    expect(screen.getByText('CVSS 7.5')).toBeInTheDocument();
    expect(screen.getByText('Known exploited')).toBeInTheDocument();
  });

  it('links only https references, in a new tab without an opener', async () => {
    renderModal();
    const link = await screen.findByRole('link', { name: 'https://security-tracker.debian.org/DSA-1' });
    expect(link).toHaveAttribute('href', 'https://security-tracker.debian.org/DSA-1');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByText('javascript:alert(1)').closest('a')).toBeNull();
    expect(screen.getByText('http://plain.example.org/x').closest('a')).toBeNull();
  });

  it('links the affected nodes of this environment', async () => {
    renderModal();
    const node = await screen.findByRole('link', { name: 'NODE-A-0' });
    expect(node).toHaveAttribute('href', '/_app/env/dev/nodes/NODE-A-0000-0001');
  });

  // On the node tab the page is not remounted by navigating to another
  // node, so a link that leaves the dialog open looks like it did nothing.
  it('closes when a node link is followed', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    renderModal(onClose);
    await user.click(await screen.findByRole('link', { name: 'NODE-A-0' }));
    expect(onClose).toHaveBeenCalled();
  });

  // The API lists at most 1,000 affected nodes per advisory, with no total.
  it('says when the affected-node list reached the server cap', async () => {
    const one = detail().findings[0];
    mockGetAdvisory.mockResolvedValue(detail({
      findings: Array.from({ length: 1000 }, (_, i) => ({ ...one, id: i + 1, node_uuid: `NODE-${i}-0000` })),
    }));
    renderModal();
    expect(await screen.findByText('Only the first 1,000 are shown.')).toBeInTheDocument();
  });

  it('says when the advisory does not exist', async () => {
    mockGetAdvisory.mockRejectedValue(Object.assign(new Error('advisory not found'), { status: 404 }));
    renderModal();
    expect(await screen.findByText('Advisory not found.')).toBeInTheDocument();
  });
});
