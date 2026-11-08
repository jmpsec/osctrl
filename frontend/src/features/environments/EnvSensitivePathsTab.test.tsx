import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EnvSensitivePathsTab } from './EnvSensitivePathsTab';
import type { SensitivePath } from '$/api/types';

const api = vi.hoisted(() => ({
  listSensitivePaths: vi.fn(),
  addSensitivePath: vi.fn(),
  deleteSensitivePath: vi.fn(),
  getMe: vi.fn(),
}));

vi.mock('$/api/environments', () => ({
  listSensitivePaths: api.listSensitivePaths,
  addSensitivePath: api.addSensitivePath,
  deleteSensitivePath: api.deleteSensitivePath,
}));
vi.mock('$/api/users', () => ({ getMe: api.getMe }));

const UUID = '00000000-0000-0000-0000-000000000001';

function sp(o: Partial<SensitivePath> = {}): SensitivePath {
  return {
    id: 1,
    environment_id: 1,
    path: '/etc/shadow',
    created_by: 'alice',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...o,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EnvSensitivePathsTab env="prod" envUuid={UUID} />
    </QueryClientProvider>,
  );
}

describe('EnvSensitivePathsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getMe.mockResolvedValue({ admin: false, permissions: { [UUID]: { admin: true, user: true } } });
    api.listSensitivePaths.mockResolvedValue([sp()]);
  });

  it('lists paths with creator and the explanation', async () => {
    renderTab();
    const row = (await screen.findByText('/etc/shadow')).closest('li') as HTMLElement;
    expect(within(row).getByText(/alice/)).toBeInTheDocument();
    expect(api.listSensitivePaths).toHaveBeenCalledWith('prod');
    expect(
      screen.getByText(
        'Users below full carve tier cannot carve these paths, anything under them, or any parent directory, and cannot see existing carves of them.',
      ),
    ).toBeInTheDocument();
  });

  it('adds a path and refetches', async () => {
    api.addSensitivePath.mockResolvedValue(sp({ id: 2, path: '/root/.ssh' }));
    const user = userEvent.setup();
    renderTab();
    await screen.findByText('/etc/shadow');
    api.listSensitivePaths.mockResolvedValue([sp(), sp({ id: 2, path: '/root/.ssh' })]);
    await user.type(await screen.findByLabelText('Sensitive path'), '/root/.ssh');
    await user.click(screen.getByRole('button', { name: 'Add path' }));
    await waitFor(() => expect(api.addSensitivePath).toHaveBeenCalledWith('prod', { path: '/root/.ssh' }));
    expect(await screen.findByText('/root/.ssh')).toBeInTheDocument();
  });

  it('shows the server message under the input', async () => {
    api.addSensitivePath.mockRejectedValue(new Error('path must be absolute'));
    const user = userEvent.setup();
    renderTab();
    await user.type(await screen.findByLabelText('Sensitive path'), 'etc/shadow');
    await user.click(screen.getByRole('button', { name: 'Add path' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('path must be absolute');
  });

  it('removes a path', async () => {
    api.deleteSensitivePath.mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole('button', { name: 'Remove /etc/shadow' }));
    await waitFor(() => expect(api.deleteSensitivePath).toHaveBeenCalledWith('prod', 1));
  });

  it('is read-only for a read-only admin', async () => {
    api.getMe.mockResolvedValue({ admin: false, read_only_admin: true, permissions: {} });
    renderTab();
    await screen.findByText('/etc/shadow');
    await waitFor(() => expect(api.getMe).toHaveBeenCalled());
    expect(screen.queryByLabelText('Sensitive path')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Remove/ })).not.toBeInTheDocument();
  });
});
