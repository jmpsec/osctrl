import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
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
import { OsqueryVersionsPage } from './OsqueryVersionsPage';
import type { OsqueryVersion } from '$/api/types';

const api = vi.hoisted(() => ({
  listOsqueryVersions: vi.fn(),
  putOsqueryVersion: vi.fn(),
  deleteOsqueryVersion: vi.fn(),
}));

vi.mock('$/api/osqueryVersions', () => ({
  osqueryVersionsQueryKey: ['osquery-versions'],
  listOsqueryVersions: api.listOsqueryVersions,
  putOsqueryVersion: api.putOsqueryVersion,
  deleteOsqueryVersion: api.deleteOsqueryVersion,
}));

const HEX = 'a'.repeat(64);

function ver(o: Partial<OsqueryVersion> = {}): OsqueryVersion {
  return {
    version: '5.13.0',
    in_use: false,
    entries: [
      { platform: 'linux', arch: 'amd64', format: 'deb', sha256: HEX, created_by: 'root', created_at: '2026-10-01T10:00:00Z' },
    ],
    ...o,
  };
}

function renderPage() {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const pageRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: OsqueryVersionsPage });
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
  api.listOsqueryVersions.mockResolvedValue([ver(), ver({ version: '5.12.1', in_use: true })]);
  api.putOsqueryVersion.mockResolvedValue(ver());
  api.deleteOsqueryVersion.mockResolvedValue(undefined);
});

describe('OsqueryVersionsPage', () => {
  it('lists versions with their entries and disables delete while in use', async () => {
    renderPage();
    expect(await screen.findByText('5.13.0')).toBeInTheDocument();
    expect(screen.getAllByText(HEX).length).toBe(2);
    expect(screen.getAllByText('root').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Delete 5.13.0' })).toBeEnabled();
    const inUse = screen.getByRole('button', { name: 'Delete 5.12.1' });
    expect(inUse).toBeDisabled();
    expect(inUse).toHaveAttribute('title', 'Assigned to an environment or host');
  });

  it('deletes a version that is not in use', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Delete 5.13.0' }));
    await user.click(screen.getByRole('button', { name: 'Confirm delete' }));
    await waitFor(() => expect(api.deleteOsqueryVersion).toHaveBeenCalledWith('5.13.0'));
  });

  it('rejects a SHA-256 that is not 64 lowercase hex before submitting', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Add version' }));
    await user.type(screen.getByLabelText('Version'), '5.14.0');
    for (const bad of ['xyz', 'A'.repeat(64), 'a'.repeat(63)]) {
      await user.clear(screen.getByLabelText('SHA-256 1'));
      await user.type(screen.getByLabelText('SHA-256 1'), bad);
      await user.click(screen.getByRole('button', { name: 'Save version' }));
      expect(await screen.findByRole('alert')).toHaveTextContent('64 lowercase hex');
    }
    expect(api.putOsqueryVersion).not.toHaveBeenCalled();
  });

  it('submits a valid entry', async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole('button', { name: 'Add version' }));
    await user.type(screen.getByLabelText('Version'), '5.14.0');
    await user.selectOptions(screen.getByLabelText('Package 1'), 'darwin / pkg / universal');
    await user.type(screen.getByLabelText('SHA-256 1'), HEX);
    await user.click(screen.getByRole('button', { name: 'Save version' }));
    await waitFor(() =>
      expect(api.putOsqueryVersion).toHaveBeenCalledWith('5.14.0', [
        { platform: 'darwin', arch: 'universal', format: 'pkg', sha256: HEX },
      ]),
    );
  });
});
