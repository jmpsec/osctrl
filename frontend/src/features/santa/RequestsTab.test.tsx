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
    carveSantaEvent: (env: string, id: number) => mockCarve(env, id),
  };
});
const mockBinary = vi.fn<(env: string, sha256: string) => Promise<never>>(() => Promise.reject(new Error('no events for this file')));
const mockCarve = vi.fn<(env: string, id: number) => Promise<{ query_name: string }>>();
vi.mock('$/api/carves', () => ({ getCarve: () => Promise.reject(new Error('no access')) }));
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, params }: { children: React.ReactNode; params: { name: string } }) => <a href={`/carves/${params.name}`}>{children}</a>,
}));
const onBinary = vi.fn<(sha256: string) => void>();

function request(id: number, over: Partial<SantaRequest> = {}): SantaRequest {
  return {
    id, file_sha256: `${id}`.repeat(64).slice(0, 64), machine_id: 'M-1', status: 'pending', created_at: '2026-11-13T10:00:00Z',
    justification: `why ${id}`, reason: '', file_name: `tool-${id}`, file_path: `/Applications/tool-${id}`, signing_id: '', team_id: '',
    executing_user: 'ada', requester: `user${id}`, decided_by: '', decided_at: null, rule_id: 0, kind: '', monitor_hours: 0, risk_override: false, event_id: 100 + id, ...over,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RequestsTab env="dev" onBinary={onBinary} />
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

  it('lets an admin approve with the team ID of a signed file', async () => {
    mockList.mockResolvedValue([request(1, { team_id: 'EQHXZ8M8AV', signing_id: 'EQHXZ8M8AV:com.example.tool', cert_sha256: 'c'.repeat(64) })]);
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve tool-1' }));
    const dialog = screen.getByRole('dialog');
    const allow = within(dialog).getByRole('combobox', { name: 'Allow' });
    expect(within(allow).getAllByRole('option').map((o) => o.getAttribute('value'))).toEqual(['BINARY', 'SIGNINGID', 'TEAMID', 'CERTIFICATE']);
    await userEvent.selectOptions(allow, 'TEAMID');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 1, expect.objectContaining({ decision: 'approve', rule_type: 'TEAMID' })));
  });

  it('lets an admin allow the whole bundle, and approvers only the file', async () => {
    mockList.mockResolvedValue([request(1, { bundle_binaries: 3 })]);
    const { unmount } = renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve tool-1' }));
    let dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByRole('combobox', { name: 'Allow' })).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Also allow the other 3 binaries of its bundle' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 1, expect.objectContaining({ bundle: true })));
    unmount();

    mockList.mockResolvedValue([request(1, { bundle_binaries: 3, team_id: 'EQHXZ8M8AV' })]);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><RequestsTab env="dev" admin={false} /></QueryClientProvider>);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve tool-1' }));
    dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByRole('combobox', { name: 'Allow' })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
  });

  it('opens the binary details from the file name', async () => {
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Binary details: tool-1' }));
    expect(onBinary).toHaveBeenCalledWith(request(1).file_sha256);
  });

  it('carves the file from the queue, and again once carved', async () => {
    mockList.mockResolvedValue([request(1), request(2, { carve: 'carve-old' })]);
    mockCarve.mockResolvedValue({ query_name: 'carve-new' });
    renderTab();
    await userEvent.click((await screen.findAllByRole('button', { name: 'Retrieve file' }))[0]);
    await waitFor(() => expect(mockCarve).toHaveBeenCalledWith('dev', 101));
    expect(await screen.findAllByRole('link', { name: 'View carve' })).toHaveLength(2);
    await userEvent.click(screen.getAllByRole('button', { name: 'Retrieve again' })[1]);
    await waitFor(() => expect(mockCarve).toHaveBeenCalledWith('dev', 102));
  });

  it('offers no carve to approvers who are not admins', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><RequestsTab env="dev" admin={false} /></QueryClientProvider>);
    await screen.findByRole('button', { name: 'Approve tool-1' });
    expect(screen.queryByRole('button', { name: 'Retrieve file' })).not.toBeInTheDocument();
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

  it('shows risk verdicts and needs a reasoned override to approve a flagged file', async () => {
    mockList.mockResolvedValue([
      request(1, { risk: { verdict: 'flagged', checks: [{ check: 'virustotal', verdict: 'flagged', detail: '12 of 70 engines flag it', checked_at: '', expires_at: '' }] } }),
      request(2, { risk: { verdict: 'error', checks: null } }),
    ]);
    renderTab();
    expect(await screen.findByText('Flagged')).toHaveAttribute('title', 'virustotal: 12 of 70 engines flag it');
    expect(screen.getByText('Check failed')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Approve tool-1' }));
    const dialog = screen.getByRole('dialog');
    const approve = within(dialog).getByRole('button', { name: 'Approve' });
    expect(within(dialog).getByText(/A risk check flagged this file/)).toBeInTheDocument();
    expect(approve).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox', { name: /Override the risk verdict/ }));
    expect(approve).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'in-house build');
    await userEvent.click(approve);
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 1, {
      decision: 'approve', scope: 'node', scope_value: '', reason: 'in-house build', override: true,
    }));
  });

  it('approves a file whose check failed without an override', async () => {
    mockList.mockResolvedValue([request(2, { risk: { verdict: 'error', checks: null } })]);
    renderTab();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve tool-2' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('dev', 2, { decision: 'approve', scope: 'node', scope_value: '', reason: '' }));
  });
});
