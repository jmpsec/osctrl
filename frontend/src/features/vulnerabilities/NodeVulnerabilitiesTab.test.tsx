import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { VulnNodeReport } from '$/api/vulnerabilities';
import { NodeVulnerabilitiesTab } from './NodeVulnerabilitiesTab';

const mockGetNodeVulns = vi.fn<() => Promise<VulnNodeReport>>();
vi.mock('$/api/vulnerabilities', () => ({
  getNodeVulns: () => mockGetNodeVulns(),
  getVulnAdvisory: vi.fn(),
}));

function report(overrides: Partial<VulnNodeReport> = {}): VulnNodeReport {
  return {
    findings: [{
      id: 1, node_uuid: 'NODE-1', environment_id: 1, advisory_id: 'DSA-1', ecosystem: 'Debian:12',
      package: 'openssl', installed_version: '3.0.11-1', fixed_version: '3.0.13-1', confidence: 'confirmed',
      severity: 'high', kev: false, first_seen: '2026-10-09T00:00:00Z', last_seen: '2026-10-10T00:00:00Z',
      resolved_at: null,
    }],
    not_assessed: 3,
    inventory_at: '2026-10-10T06:00:00Z',
    matched_at: '2026-10-10T06:01:00Z',
    loaded: true,
    stale: false,
    ...overrides,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeVulnerabilitiesTab env="dev" uuid="NODE-1" />
    </QueryClientProvider>,
  );
}

describe('NodeVulnerabilitiesTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('lists the findings and the packages it could not assess', async () => {
    mockGetNodeVulns.mockResolvedValue(report());
    renderTab();
    expect(await screen.findByRole('button', { name: 'DSA-1' })).toBeInTheDocument();
    expect(screen.getByText('Not assessed: 3')).toBeInTheDocument();
  });

  // The API returns at most 500 open findings per node, with no total.
  it('says when the list reached the server cap', async () => {
    const one = report().findings[0];
    mockGetNodeVulns.mockResolvedValue(report({
      findings: Array.from({ length: 500 }, (_, i) => ({ ...one, id: i + 1, advisory_id: `DSA-${i}` })),
    }));
    renderTab();
    expect(await screen.findByText('Only the first 500 are shown.')).toBeInTheDocument();
  });

  it('does not claim truncation below the cap', async () => {
    mockGetNodeVulns.mockResolvedValue(report());
    renderTab();
    await screen.findByRole('button', { name: 'DSA-1' });
    expect(screen.queryByText(/Only the first/)).not.toBeInTheDocument();
  });

  it('says the node has not reported inventory when there is none', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], inventory_at: null }));
    renderTab();
    expect(await screen.findByText(/has not reported a software inventory yet/)).toBeInTheDocument();
    expect(screen.queryByText('No open vulnerability findings for this node.')).not.toBeInTheDocument();
  });

  // The API sends Go's zero time when the node state exists without inventory.
  it('treats Go zero time as no inventory', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], inventory_at: '0001-01-01T00:00:00Z' }));
    renderTab();
    expect(await screen.findByText(/has not reported a software inventory yet/)).toBeInTheDocument();
  });

  it('says there are no open findings only when inventory exists', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], not_assessed: 0 }));
    renderTab();
    expect(await screen.findByText('No open vulnerability findings for this node.')).toBeInTheDocument();
  });

  // Inventory is stored before the worker matches it. Until then an empty
  // list would read as "no findings", which is a false all-clear.
  it('says matching is pending before the inventory has been matched', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], matched_at: null }));
    renderTab();
    expect(await screen.findByText(/matching against advisory data is still pending/)).toBeInTheDocument();
    expect(screen.queryByText('No open vulnerability findings for this node.')).not.toBeInTheDocument();
  });

  it('says matching is pending when the inventory is newer than the last match', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], matched_at: '2026-10-10T05:00:00Z' }));
    renderTab();
    expect(await screen.findByText(/matching against advisory data is still pending/)).toBeInTheDocument();
  });

  it('warns before advisory data has loaded', async () => {
    mockGetNodeVulns.mockResolvedValue(report({ findings: [], loaded: false }));
    renderTab();
    expect(await screen.findByText(/Advisory data has not been loaded yet/)).toBeInTheDocument();
  });

  it('shows the API error', async () => {
    mockGetNodeVulns.mockRejectedValue(new Error('vulnerability monitoring not enabled'));
    renderTab();
    expect(await screen.findByText('Could not load vulnerability data.')).toBeInTheDocument();
    expect(screen.getByText('vulnerability monitoring not enabled')).toBeInTheDocument();
  });
});
