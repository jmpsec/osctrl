import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeFileExplorerTab } from './NodeFileExplorerTab';
import type { FileExplorerEntry, FileExplorerRequest, FileExplorerSessionResponse } from '$/api/types';

const api = vi.hoisted(() => ({
  createFileExplorerSession: vi.fn(),
  closeFileExplorerSession: vi.fn(),
  getFileExplorerSession: vi.fn(),
  listFileExplorerDirectory: vi.fn(),
  statFileExplorerPath: vi.fn(),
  getFileExplorerRequest: vi.fn(),
  getFileExplorerRequestResults: vi.fn(),
  runCarve: vi.fn(),
}));

vi.mock('$/api/file-explorer', () => ({
  createFileExplorerSession: api.createFileExplorerSession,
  closeFileExplorerSession: api.closeFileExplorerSession,
  getFileExplorerSession: api.getFileExplorerSession,
  listFileExplorerDirectory: api.listFileExplorerDirectory,
  statFileExplorerPath: api.statFileExplorerPath,
  getFileExplorerRequest: api.getFileExplorerRequest,
  getFileExplorerRequestResults: api.getFileExplorerRequestResults,
}));

vi.mock('$/api/carves', () => ({
  runCarve: api.runCarve,
}));

vi.mock('@tanstack/react-router', () => ({
  Link: ({
    to,
    params,
    children,
    ...props
  }: {
    to: string;
    params: { env: string; name: string };
    children: React.ReactNode;
  }) => (
    <a
      href={to.replace('$env', params.env).replace('$name', params.name)}
      {...props}
    >
      {children}
    </a>
  ),
}));

describe('NodeFileExplorerTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.closeFileExplorerSession.mockResolvedValue({ message: 'closed' });
    api.getFileExplorerSession.mockResolvedValue(makeSessionResponse().session);
    api.getFileExplorerRequest.mockResolvedValue(makeRequest({ id: 10, path: '/', status: 'completed' }));
    api.getFileExplorerRequestResults.mockResolvedValue([
      makeEntry({ path: '/etc', filename: 'etc', directory: '/', type: 'directory' }),
      makeEntry({ path: '/README', filename: 'README', directory: '/', type: 'regular', size: 42 }),
    ]);
    api.listFileExplorerDirectory.mockResolvedValue(makeRequest({ id: 10, path: '/' }));
    api.createFileExplorerSession.mockResolvedValue(makeSessionResponse());
    api.runCarve.mockResolvedValue({ query_name: 'carve-selected' });
  });

  it('opens a session and lists the root directory', async () => {
    renderExplorer();

    await waitFor(() => {
      expect(api.createFileExplorerSession).toHaveBeenCalledWith('env', 'NODE');
    });
    expect(api.listFileExplorerDirectory).toHaveBeenCalledWith('env', 1, '/');
    expect(await screen.findByRole('treeitem', { name: /etc directory/i })).toBeInTheDocument();
    expect(screen.getByRole('treeitem', { name: /README file/i })).toBeInTheDocument();
  });

  it('loads a child directory when expanded', async () => {
    const user = userEvent.setup();
    api.listFileExplorerDirectory
      .mockResolvedValueOnce(makeRequest({ id: 10, path: '/' }))
      .mockResolvedValueOnce(makeRequest({ id: 11, path: '/etc' }));
    api.getFileExplorerRequest
      .mockResolvedValueOnce(makeRequest({ id: 10, path: '/', status: 'completed' }))
      .mockResolvedValueOnce(makeRequest({ id: 11, path: '/etc', status: 'completed' }));
    api.getFileExplorerRequestResults
      .mockResolvedValueOnce([
        makeEntry({ path: '/etc', filename: 'etc', directory: '/', type: 'directory' }),
      ])
      .mockResolvedValueOnce([
        makeEntry({ path: '/etc/hosts', filename: 'hosts', directory: '/etc', type: 'regular' }),
      ]);

    renderExplorer();

    const etc = await screen.findByRole('treeitem', { name: /etc directory/i });
    await user.click(etc);

    await waitFor(() => {
      expect(api.listFileExplorerDirectory).toHaveBeenLastCalledWith('env', 1, '/etc');
    });
    expect(await screen.findByRole('treeitem', { name: /hosts file/i })).toBeInTheDocument();
  });

  it('keeps the details panel sticky while the page scrolls', async () => {
    renderExplorer();

    await screen.findByRole('treeitem', { name: /etc directory/i });

    const details = screen.getByRole('complementary', { name: /file details/i });
    expect(details).toHaveClass('lg:sticky');
    expect(details).toHaveClass('lg:top-3');
  });

  it('starts a node-targeted carve for the selected path', async () => {
    const user = userEvent.setup();

    renderExplorer();

    await user.click(await screen.findByRole('treeitem', { name: /etc directory/i }));
    await user.click(screen.getByRole('button', { name: /carve selected/i }));

    await waitFor(() => {
      expect(api.runCarve).toHaveBeenCalledWith('env', {
        path: '/etc',
        uuid_list: ['NODE'],
      });
    });
    expect(await screen.findByText(/created new/i)).toBeInTheDocument();
    expect(screen.queryByText(/carve-selected/i)).not.toBeInTheDocument();
    const carveLink = screen.getByRole('link', { name: /carve/i });
    expect(carveLink).toHaveAttribute('href', '/_app/env/env/carves/carve-selected');
    expect(within(carveLink).getByText('carve')).toBeInTheDocument();
    expect(carveLink.querySelector('svg')).not.toBeNull();
  });

  it('refreshes the selected directory', async () => {
    const user = userEvent.setup();
    api.listFileExplorerDirectory
      .mockResolvedValueOnce(makeRequest({ id: 10, path: '/' }))
      .mockResolvedValueOnce(makeRequest({ id: 11, path: '/etc' }))
      .mockResolvedValueOnce(makeRequest({ id: 12, path: '/etc' }));
    api.getFileExplorerRequest
      .mockResolvedValueOnce(makeRequest({ id: 10, path: '/', status: 'completed' }))
      .mockResolvedValueOnce(makeRequest({ id: 11, path: '/etc', status: 'completed' }))
      .mockResolvedValueOnce(makeRequest({ id: 12, path: '/etc', status: 'completed' }));
    api.getFileExplorerRequestResults
      .mockResolvedValueOnce([
        makeEntry({ path: '/etc', filename: 'etc', directory: '/', type: 'directory' }),
      ])
      .mockResolvedValueOnce([
        makeEntry({ path: '/etc/hosts', filename: 'hosts', directory: '/etc', type: 'regular' }),
      ])
      .mockResolvedValueOnce([
        makeEntry({ path: '/etc/services', filename: 'services', directory: '/etc', type: 'regular' }),
      ]);

    renderExplorer();

    await user.click(await screen.findByRole('treeitem', { name: /etc directory/i }));
    expect(await screen.findByRole('treeitem', { name: /hosts file/i })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /refresh/i }));

    await waitFor(() => {
      expect(api.listFileExplorerDirectory).toHaveBeenLastCalledWith('env', 1, '/etc');
    });
    expect(await screen.findByRole('treeitem', { name: /services file/i })).toBeInTheDocument();
  });

  it('shows a spinner with loading text while a directory request is pending', async () => {
    const user = userEvent.setup();
    api.listFileExplorerDirectory
      .mockResolvedValueOnce(makeRequest({ id: 10, path: '/' }))
      .mockResolvedValueOnce(makeRequest({ id: 11, path: '/etc' }));
    api.getFileExplorerRequest.mockImplementation((_env: string, _sessionId: number, requestId: number) => {
      if (requestId === 10) return Promise.resolve(makeRequest({ id: 10, path: '/', status: 'completed' }));
      return new Promise(() => undefined);
    });
    api.getFileExplorerRequestResults.mockResolvedValueOnce([
      makeEntry({ path: '/etc', filename: 'etc', directory: '/', type: 'directory' }),
    ]);

    renderExplorer();

    const etc = await screen.findByRole('treeitem', { name: /etc directory/i });
    await user.click(etc);
    await user.click(etc);

    await waitFor(() => {
      expect(screen.getAllByText('Loading...').length).toBeGreaterThan(0);
    });
  });
});

function renderExplorer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeFileExplorerTab env="env" uuid="NODE" />
    </QueryClientProvider>,
  );
}

function makeSessionResponse(): FileExplorerSessionResponse {
  return {
    session: {
      id: 1,
      created_at: '2026-08-02T00:00:00Z',
      updated_at: '2026-08-02T00:00:00Z',
      environment_id: 1,
      node_id: 2,
      node_uuid: 'NODE',
      creator: 'alice',
      platform: 'linux',
      root: '/',
      active: true,
    },
    node_info: {
      ip_address: '10.0.0.1',
      osquery_user: 'root',
      osquery_version: '5.23.1',
      platform: 'linux',
      platform_version: '22.04',
    },
  };
}

function makeRequest(overrides: Partial<FileExplorerRequest> = {}): FileExplorerRequest {
  return {
    id: 1,
    created_at: '2026-08-02T00:00:00Z',
    updated_at: '2026-08-02T00:00:00Z',
    session_id: 1,
    action: 'list',
    path: '/',
    status: 'queued',
    ...overrides,
  };
}

function makeEntry(overrides: Partial<FileExplorerEntry> = {}): FileExplorerEntry {
  return {
    path: '/',
    filename: '',
    directory: '/',
    type: 'directory',
    ...overrides,
  };
}
