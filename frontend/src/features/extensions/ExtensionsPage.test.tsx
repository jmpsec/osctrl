import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router';
import { ExtensionsPage } from './ExtensionsPage';
import type { Extension } from '$/api/types';

const mockList = vi.fn<() => Promise<Extension[]>>();
const mockCreate = vi.fn();
const mockUpdate = vi.fn();
const mockDelete = vi.fn();
const mockUpload = vi.fn();
const mockDeleteFile = vi.fn();

vi.mock('$/api/extensions', () => ({
  extensionsQueryKey: ['extensions'],
  listExtensions: () => mockList(),
  createExtension: (...a: unknown[]) => mockCreate(...a),
  updateExtension: (...a: unknown[]) => mockUpdate(...a),
  deleteExtension: (...a: unknown[]) => mockDelete(...a),
  uploadExtensionFile: (...a: unknown[]) => mockUpload(...a),
  deleteExtensionFile: (...a: unknown[]) => mockDeleteFile(...a),
}));

function ext(o: Partial<Extension> = {}): Extension {
  return {
    id: 1,
    name: 'osquery-ext',
    description: 'does things',
    version: '1.2.3',
    command_execution: false,
    files: [],
    environments: 0,
    nodes: 0,
    created_by: 'admin',
    updated_at: new Date().toISOString(),
    ...o,
  };
}

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const pageRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: ExtensionsPage });
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

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue([]);
});

describe('ExtensionsPage', () => {
  it('renders extensions with the command execution badge and files', async () => {
    mockList.mockResolvedValue([
      ext({
        command_execution: true,
        environments: 2,
        nodes: 5,
        files: [
          {
            platform: 'linux',
            arch: 'amd64',
            size: 2048,
            sha256: 'abcdef0123456789',
            filename: 'ext.ext',
            updated_at: new Date().toISOString(),
            updated_by: 'admin',
          },
        ],
      }),
    ]);
    renderPage();
    expect(await screen.findByText('osquery-ext')).toBeInTheDocument();
    expect(screen.getByText('Command execution')).toBeInTheDocument();
    expect(screen.getByText('abcdef01')).toBeInTheDocument();
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
    expect(screen.getByText(/2 environments/)).toBeInTheDocument();
    expect(screen.getByText(/5 hosts/)).toBeInTheDocument();
  });

  it('creates an extension with the typed body', async () => {
    mockCreate.mockResolvedValue(ext());
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'New extension' }));
    await user.type(screen.getByLabelText('Name'), 'my-ext');
    await user.type(screen.getByLabelText('Description'), 'desc');
    await user.type(screen.getByLabelText('Version'), '0.1.0');
    await user.click(screen.getByLabelText('Can execute commands'));
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() =>
      expect(mockCreate).toHaveBeenCalledWith({
        name: 'my-ext',
        description: 'desc',
        version: '0.1.0',
        command_execution: true,
      }),
    );
  });

  it('uploads a file as the right platform/arch', async () => {
    mockList.mockResolvedValue([ext({ id: 7 })]);
    mockUpload.mockResolvedValue(ext({ id: 7 }));
    const user = userEvent.setup();
    renderPage();
    const input = await screen.findByLabelText('Upload linux/amd64 for osquery-ext');
    const file = new File(['bin'], 'ext.ext');
    await user.upload(input, file);
    await waitFor(() => expect(mockUpload).toHaveBeenCalledWith(7, 'linux', 'amd64', file));
  });

  it('refuses files over 64 MB client-side', async () => {
    mockList.mockResolvedValue([ext({ id: 7 })]);
    const user = userEvent.setup();
    renderPage();
    const input = await screen.findByLabelText('Upload linux/amd64 for osquery-ext');
    const big = new File(['x'], 'big.ext');
    Object.defineProperty(big, 'size', { value: 64 * 1024 * 1024 + 1 });
    await user.upload(input, big);
    expect(await screen.findByText('Files can be at most 64 MB.')).toBeInTheDocument();
    expect(mockUpload).not.toHaveBeenCalled();
  });

  it('disables extension delete while assigned, with a tooltip', async () => {
    mockList.mockResolvedValue([ext({ environments: 1 }), ext({ id: 2, name: 'free-ext' })]);
    renderPage();
    await screen.findByText('osquery-ext');
    const assigned = screen.getByRole('button', { name: 'Delete osquery-ext' });
    expect(assigned).toBeDisabled();
    expect(assigned.closest('span[title]')).toHaveAttribute(
      'title',
      'Remove it from all environments and hosts first',
    );
    expect(screen.getByRole('button', { name: 'Delete free-ext' })).toBeEnabled();
  });

  it('shows server errors inline', async () => {
    mockList.mockResolvedValue([ext({ id: 7 })]);
    mockUpload.mockRejectedValue(new Error('empty file'));
    const user = userEvent.setup();
    renderPage();
    const input = await screen.findByLabelText('Upload linux/amd64 for osquery-ext');
    await user.upload(input, new File(['x'], 'a.ext'));
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('empty file')).toBeInTheDocument();
  });
});
