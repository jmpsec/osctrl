import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DistributedQuery, NodesPagedResponse, OsqueryNode, QueriesPagedResponse } from '$/api/types';
import { SideNavPreview } from './SideNavPreview';

const mockListNodes = vi.fn();
const mockListQueries = vi.fn();

vi.mock('$/api/nodes', () => ({
  listNodes: (...args: unknown[]) => mockListNodes(...args),
}));

vi.mock('$/api/queries', () => ({
  listQueries: (...args: unknown[]) => mockListQueries(...args),
}));

vi.mock('@tanstack/react-router', () => ({
  Link: ({
    children,
    to,
    params,
    ...props
  }: {
    children: ReactNode;
    to: string;
    params?: Record<string, string>;
    [key: string]: unknown;
  }) => {
    const href = Object.entries(params ?? {}).reduce(
      (path, [key, value]) => path.replace(`$${key}`, value),
      to,
    );
    return <a href={href} {...props}>{children}</a>;
  },
}));

function makeNode(overrides: Partial<OsqueryNode> = {}): OsqueryNode {
  return {
    id: 1,
    created_at: '2026-08-23T10:00:00Z',
    updated_at: '2026-08-23T10:00:00Z',
    uuid: 'node-001',
    platform: 'linux',
    platform_version: '6.8',
    osquery_version: '5.18',
    hostname: 'edge-linux-01',
    localname: 'edge-linux-01',
    ip_address: '10.0.0.8',
    username: 'root',
    osquery_user: 'root',
    environment: 'dev',
    cpu: '',
    memory: '',
    hardware_serial: '',
    daemon_hash: '',
    config_hash: '',
    bytes_received: 0,
    last_seen: new Date(Date.now() - 5 * 60_000).toISOString(),
    user_id: 1,
    environment_id: 1,
    extra_data: '',
    ...overrides,
  };
}

function nodesResponse(items: OsqueryNode[]): NodesPagedResponse {
  return { items, page: 1, page_size: items.length, total_items: items.length, total_pages: 1 };
}

function makeQuery(overrides: Partial<DistributedQuery> = {}): DistributedQuery {
  return {
    id: 1,
    created_at: new Date(Date.now() - 10 * 60_000).toISOString(),
    updated_at: '2026-08-23T10:00:00Z',
    name: 'running-processes',
    creator: 'operator',
    query: 'select * from processes;',
    expected: 12,
    executions: 8,
    errors: 0,
    active: true,
    hidden: false,
    protected: false,
    completed: false,
    deleted: false,
    expired: false,
    type: 'query',
    path: '',
    environment_id: 1,
    extra_data: '',
    expiration: '',
    target: 'all',
    ...overrides,
  };
}

function queriesResponse(items: DistributedQuery[]): QueriesPagedResponse {
  return { items, page: 1, page_size: items.length, total_items: items.length, total_pages: 1 };
}

function renderPreview(kind: 'nodes' | 'queries', focusFirstItem = false) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <SideNavPreview
        kind={kind}
        env="dev"
        anchor={{ top: 100, right: 240 }}
        focusFirstItem={focusFirstItem}
        onDismiss={vi.fn()}
        onInteractionStart={vi.fn()}
        onInteractionEnd={vi.fn()}
      />
    </QueryClientProvider>,
  );
}

describe('SideNavPreview', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('puts problem nodes ahead of recently seen nodes without loading query data', async () => {
    const atRisk = makeNode({
      uuid: 'node-risk',
      hostname: 'finance-mac-07',
      platform: 'darwin',
      health: { status: 'at_risk', reason: 'Posture checks are failing' },
    });
    const recent = makeNode({ uuid: 'node-recent', hostname: 'build-linux-03' });
    mockListNodes.mockImplementation(({ status }: { status: string }) => Promise.resolve(
      status === 'inactive' ? nodesResponse([atRisk]) : nodesResponse([atRisk, recent]),
    ));

    renderPreview('nodes');

    expect(await screen.findByText('finance-mac-07')).toBeInTheDocument();
    expect(screen.getByText('Posture checks are failing')).toBeInTheDocument();
    expect(screen.getByText('build-linux-03')).toBeInTheDocument();
    expect(screen.getByText('At risk')).toBeInTheDocument();
    expect(mockListNodes).toHaveBeenCalledTimes(2);
    expect(mockListQueries).not.toHaveBeenCalled();
  });

  it('surfaces query errors and supports keyboard entry into the preview', async () => {
    const failing = makeQuery({ id: 9, name: 'network-connections', errors: 2 });
    const completed = makeQuery({
      id: 10,
      name: 'listening-ports',
      active: false,
      completed: true,
    });
    mockListQueries.mockImplementation(({ target }: { target: string }) => Promise.resolve(
      target === 'active' ? queriesResponse([failing]) : queriesResponse([failing, completed]),
    ));

    renderPreview('queries', true);

    expect(await screen.findByText('network-connections')).toBeInTheDocument();
    expect(screen.getByText('2 errors')).toBeInTheDocument();
    expect(screen.getByText('listening-ports')).toBeInTheDocument();
    await waitFor(() => expect(document.activeElement).toHaveTextContent('View all'));
    expect(mockListQueries).toHaveBeenCalledTimes(2);
    expect(mockListNodes).not.toHaveBeenCalled();
  });
});
