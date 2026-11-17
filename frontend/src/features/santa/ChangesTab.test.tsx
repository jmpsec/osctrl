import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PendingChange } from '$/api/changes';
import { ChangesTab } from './ChangesTab';

const mockList = vi.fn<() => Promise<PendingChange[]>>();
const mockDecide = vi.fn<(env: string, id: number, d: string) => Promise<unknown>>();
const mockApply = vi.fn<(c: PendingChange) => Promise<unknown>>();
vi.mock('$/api/changes', async () => {
  const actual = await vi.importActual<typeof import('$/api/changes')>('$/api/changes');
  return {
    ...actual,
    listChanges: () => mockList(),
    decideChange: (env: string, id: number, d: string) => mockDecide(env, id, d),
    applyChange: (c: PendingChange) => mockApply(c),
  };
});

const base: PendingChange = {
  id: 1, created_at: '2026-11-17T10:00:00Z', action: 'santa: update config client_mode=MONITOR', method: 'PUT',
  path: '/api/v1/santa/dev/config', body: '{"client_mode":"MONITOR"}', requested_by: 'alice', status: 'pending',
  expires_at: '2026-11-18T10:00:00Z', mine: false,
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}><ChangesTab env="dev" /></QueryClientProvider>);
}

describe('ChangesTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockDecide.mockResolvedValue({});
    mockApply.mockResolvedValue({});
  });

  it('lets another admin approve or deny, not withdraw', async () => {
    mockList.mockResolvedValue([base]);
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve 1' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 1, 'approve'));
    expect(screen.getByRole('button', { name: 'Deny 1' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Withdraw 1' })).not.toBeInTheDocument();
  });

  it('lets the requester withdraw a pending change and apply an approved one', async () => {
    const approved = { ...base, id: 2, status: 'approved' as const, mine: true, decided_by: 'bob' };
    mockList.mockResolvedValue([{ ...base, mine: true }, approved]);
    renderTab();
    expect(await screen.findByRole('button', { name: 'Withdraw 1' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve 1' })).not.toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Apply 2' }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledWith(approved));
  });

  it('shows the token of an applied rotation', async () => {
    mockList.mockResolvedValue([{ ...base, id: 3, status: 'approved', mine: true, method: 'POST', path: '/api/v1/santa/dev/token', body: '' }]);
    mockApply.mockResolvedValue({ token: 'tok-123' });
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Apply 3' }));
    expect(await screen.findByText(/tok-123/)).toBeInTheDocument();
  });
});
