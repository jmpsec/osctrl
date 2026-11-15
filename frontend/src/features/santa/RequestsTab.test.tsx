import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SantaDecision, SantaRequest } from '$/api/santa';
import { RequestsTab } from './RequestsTab';

const mockList = vi.fn<(env: string, status: string) => Promise<SantaRequest[]>>();
const mockDecide = vi.fn<(env: string, id: number, body: SantaDecision) => Promise<SantaRequest>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    listSantaRequests: (env: string, status: string) => mockList(env, status),
    decideSantaRequest: (env: string, id: number, body: SantaDecision) => mockDecide(env, id, body),
    listSantaMachines: () => Promise.resolve([{ machine_id: 'M-1', hostname: 'ada-mbp' }]),
    getSantaBinary: (env: string, sha256: string) => mockBinary(env, sha256),
  };
});
const mockBinary = vi.fn<(env: string, sha256: string) => Promise<never>>(() => Promise.reject(new Error('no events for this file')));

function request(id: number, over: Partial<SantaRequest> = {}): SantaRequest {
  return {
    id, file_sha256: `${id}`.repeat(64).slice(0, 64), machine_id: 'M-1', status: 'pending', created_at: '2026-11-13T10:00:00Z',
    justification: `why ${id}`, reason: '', file_name: `tool-${id}`, file_path: `/Applications/tool-${id}`, signing_id: '', team_id: '',
    executing_user: 'ada', requester: `user${id}`, decided_by: '', decided_at: null, rule_id: 0, kind: '', monitor_hours: 0, ...over,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RequestsTab env="dev" />
    </QueryClientProvider>,
  );
}

describe('RequestsTab', () => {
  beforeEach(() => {
    mockList.mockReset().mockResolvedValue([request(1), request(2), request(3, { status: 'denied', decided_by: 'alice', reason: 'no' })]);
    mockDecide.mockReset().mockImplementation((_env, id) => Promise.resolve(request(id)));
  });

  it('lists pending requests first with their context, and only pending ones can be decided', async () => {
    renderTab();
    expect(await screen.findByText('tool-1')).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith('dev', 'pending');
    expect(screen.getAllByText('ada-mbp')).toHaveLength(3);
    expect(screen.getByText('why 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve tool-1' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve tool-3' })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'tool-3' })).not.toBeInTheDocument();
  });

  it('searches and filters by status', async () => {
    renderTab();
    await screen.findByText('tool-1');
    await userEvent.type(screen.getByRole('searchbox'), 'USER2');
    expect(screen.queryByText('tool-1')).not.toBeInTheDocument();
    expect(screen.getByText('tool-2')).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Status' }), 'denied');
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith('dev', 'denied'));
  });

  it('approves one request for the requesting machine by default', async () => {
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve tool-1' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 1, { decision: 'approve', scope: 'node', scope_value: '', reason: '' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('opens the binary details from the file name', async () => {
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Binary details: tool-1' }));
    expect(await screen.findByRole('dialog', { name: 'Binary details' })).toBeInTheDocument();
    expect(mockBinary).toHaveBeenCalledWith('dev', request(1).file_sha256);
  });

  it('approves a MONITOR request without a rule scope', async () => {
    mockList.mockResolvedValue([request(4, { kind: 'monitor', monitor_hours: 8, file_sha256: '', file_name: '', file_path: '' })]);
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve MONITOR mode for 8 h' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByLabelText('Scope')).not.toBeInTheDocument();
    expect(within(dialog).getByText(/switches the machine to MONITOR/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 4, { decision: 'approve', scope: 'node', scope_value: '', reason: '' }));
  });

  it('denies the selected requests in bulk and needs a reason', async () => {
    renderTab();
    await screen.findByText('tool-1');
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));
    await userEvent.click(screen.getByRole('button', { name: 'Deny (2)' }));
    const dialog = screen.getByRole('dialog');
    const deny = within(dialog).getByRole('button', { name: 'Deny' });
    expect(deny).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'not allowed');
    await userEvent.click(deny);
    await waitFor(() => expect(mockDecide).toHaveBeenCalledTimes(2));
    expect(mockDecide).toHaveBeenCalledWith('dev', 2, { decision: 'deny', reason: 'not allowed' });
  });

  it('approves for a tag, and keeps the dialog open with the error when one fails', async () => {
    mockDecide.mockImplementation((_env, id) => (id === 2 ? Promise.reject(new Error('rule in the way')) : Promise.resolve(request(id))));
    renderTab();
    await screen.findByText('tool-1');
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));
    await userEvent.click(screen.getByRole('button', { name: 'Approve (2)' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText('Scope'), 'tag');
    await userEvent.type(within(dialog).getByLabelText(/Tag/), 'dev');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('1/2: rule in the way');
    expect(mockDecide).toHaveBeenCalledWith('dev', 1, { decision: 'approve', scope: 'tag', scope_value: 'dev', reason: '' });
  });
});
