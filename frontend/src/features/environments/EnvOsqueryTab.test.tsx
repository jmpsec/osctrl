import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { EnvOsqueryTab } from './EnvOsqueryTab';
import type { EnvOsquery } from '$/api/types';

const api = vi.hoisted(() => ({ getEnvOsquery: vi.fn(), setEnvOsquery: vi.fn(), clearEnvOsquery: vi.fn() }));
vi.mock('$/api/osqueryVersions', () => api);

function make(o: Partial<EnvOsquery> = {}): EnvOsquery {
  return {
    target: { version: '5.13.0', request_id: 'r1', updated_by: 'alice', updated_at: '2026-10-01T10:00:00Z' },
    counts: [
      { version: '5.12.1', count: 7 },
      { version: '5.13.0', count: 3 },
    ],
    available: ['5.12.1', '5.13.0', '5.14.0'],
    ...o,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EnvOsqueryTab env="prod" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getEnvOsquery.mockResolvedValue(make());
  api.setEnvOsquery.mockResolvedValue(make());
  api.clearEnvOsquery.mockResolvedValue(make({ target: null }));
});

describe('EnvOsqueryTab', () => {
  it('shows the target with who set it and the host counts', async () => {
    renderTab();
    expect(await screen.findByText(/Target version/)).toHaveTextContent('5.13.0');
    expect(screen.getByText(/alice/)).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /5\.12\.1\s*7/ })).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /5\.13\.0\s*3/ })).toBeInTheDocument();
  });

  it('saves a new target only after confirming', async () => {
    const user = userEvent.setup();
    renderTab();
    await user.selectOptions(await screen.findByLabelText('Target version to set'), '5.14.0');
    await user.click(screen.getByRole('button', { name: 'Set target' }));
    const dialog = await screen.findByRole('dialog');
    expect(api.setEnvOsquery).not.toHaveBeenCalled();
    expect(dialog).toHaveTextContent('5.14.0');
    expect(dialog).toHaveTextContent('10 hosts');
    expect(dialog).toHaveTextContent('next sync (up to an hour)');
    expect(dialog).toHaveTextContent('rolls back automatically');
    await user.click(screen.getByRole('button', { name: 'Set target 5.14.0' }));
    await waitFor(() => expect(api.setEnvOsquery).toHaveBeenCalledWith('prod', '5.14.0'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('sends nothing when the confirmation is cancelled', async () => {
    const user = userEvent.setup();
    renderTab();
    await user.selectOptions(await screen.findByLabelText('Target version to set'), '5.14.0');
    await user.click(screen.getByRole('button', { name: 'Set target' }));
    await screen.findByRole('dialog');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(api.setEnvOsquery).not.toHaveBeenCalled();
  });

  it('names all hosts when the environment reports none', async () => {
    api.getEnvOsquery.mockResolvedValue(make({ counts: [] }));
    const user = userEvent.setup();
    renderTab();
    await user.selectOptions(await screen.findByLabelText('Target version to set'), '5.14.0');
    await user.click(screen.getByRole('button', { name: 'Set target' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent('all hosts in this environment');
  });

  it('clears the target', async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole('button', { name: 'Clear target' }));
    await waitFor(() => expect(api.clearEnvOsquery).toHaveBeenCalledWith('prod'));
    expect(await screen.findByText('No target version is set.')).toBeInTheDocument();
  });
});
