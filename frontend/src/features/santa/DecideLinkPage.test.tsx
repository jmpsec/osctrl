import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError } from '$/api/client';
import type { SantaDecision, SantaRequest } from '$/api/santa';
import { takeSantaDecideTarget } from '$/routes/santa.decide.$env';
import { DecideLinkPage } from './DecideLinkPage';

const mockGet = vi.fn<(env: string, id: number) => Promise<SantaRequest>>();
const mockDecide = vi.fn<(env: string, token: string, body: SantaDecision) => Promise<SantaRequest>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    getSantaRequest: (env: string, id: number) => mockGet(env, id),
    decideSantaRequestByLink: (env: string, token: string, body: SantaDecision) => mockDecide(env, token, body),
  };
});

const pending: SantaRequest = {
  id: 7, file_sha256: 'ab'.repeat(32), machine_id: 'M-1', status: 'pending', created_at: '2026-11-13T10:00:00Z',
  justification: 'I need it', reason: '', file_name: 'tool', file_path: '/Applications/tool', signing_id: '', team_id: '',
  executing_user: 'ada', requester: 'dave', decided_by: '', decided_at: null, rule_id: 0, kind: '', monitor_hours: 0,
};

function renderPage(approve: boolean, token = 'TOKEN', requestId = 7) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <DecideLinkPage env="ENV-UUID" requestId={requestId} approve={approve} token={token} />
    </QueryClientProvider>,
  );
}

describe('DecideLinkPage', () => {
  beforeEach(() => {
    mockGet.mockReset().mockResolvedValue(pending);
    mockDecide.mockReset();
  });

  it('shows the request and approves only after the approver confirms', async () => {
    mockDecide.mockResolvedValue({ ...pending, status: 'approved', decided_by: 'alice' });
    renderPage(true);
    expect(await screen.findByText('tool')).toBeInTheDocument();
    expect(screen.getByText('I need it')).toBeInTheDocument();
    expect(mockDecide).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('ENV-UUID', 'TOKEN', { decision: 'approve', scope: 'node', scope_value: '', reason: '' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Status: Approved (alice)');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('denies with a reason', async () => {
    mockDecide.mockResolvedValue({ ...pending, status: 'denied' });
    renderPage(false);
    const deny = await screen.findByRole('button', { name: 'Deny' });
    expect(deny).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Reason/), 'not allowed');
    await userEvent.click(deny);
    await waitFor(() => expect(mockDecide).toHaveBeenCalledWith('ENV-UUID', 'TOKEN', { decision: 'deny', reason: 'not allowed' }));
  });

  it('says so when the link was used or has expired', async () => {
    mockDecide.mockRejectedValue(new ApiError('gone', 410));
    renderPage(true);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('already used or has expired');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('offers nothing to decide for a request that is not pending', async () => {
    mockGet.mockResolvedValue({ ...pending, status: 'denied', decided_by: 'bob' });
    renderPage(true);
    expect(await screen.findByRole('status')).toHaveTextContent('Status: Denied (bob)');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('refuses a link without a token or a request', () => {
    renderPage(true, '');
    expect(screen.getByRole('alert')).toHaveTextContent('already used or has expired');
    expect(mockGet).not.toHaveBeenCalled();
  });
});

describe('takeSantaDecideTarget', () => {
  it('returns the stored link once and ignores anything else in storage', () => {
    const key = 'osctrl.santaDecide';
    sessionStorage.setItem(key, JSON.stringify({ env: 'e', request: 7, action: 'approve', token: 't', to: 'https://evil.example' }));
    expect(takeSantaDecideTarget()).toEqual({ env: 'e', request: 7, action: 'approve', token: 't' });
    expect(takeSantaDecideTarget()).toBeNull();
    // Anything but "approve" is a deny link; the server holds the token to its own action anyway.
    sessionStorage.setItem(key, JSON.stringify({ env: 'e', request: '7', action: 'whatever', token: 't' }));
    expect(takeSantaDecideTarget()).toEqual({ env: 'e', request: 7, action: 'deny', token: 't' });
    for (const bad of ['not json', JSON.stringify({ env: 'e', request: 7, action: 'approve' }), JSON.stringify({ env: 'e', request: -1, token: 't' })]) {
      sessionStorage.setItem(key, bad);
      expect(takeSantaDecideTarget()).toBeNull();
    }
  });
});
