import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SantaOwnRequest, SantaVoteStatus } from '$/api/santa';
import { takeSantaRequestTarget } from '$/routes/santa.request.$env';
import { RequestPage } from './RequestPage';

const mockCreate = vi.fn<(env: string, body: unknown) => Promise<SantaOwnRequest>>();
const mockMine = vi.fn<() => Promise<SantaOwnRequest[]>>();
const mockVotes = vi.fn<(env: string, sha256: string) => Promise<SantaVoteStatus>>();
const mockVote = vi.fn<(env: string, body: unknown) => Promise<SantaVoteStatus>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    createSantaRequest: (env: string, body: unknown) => mockCreate(env, body),
    listMySantaRequests: () => mockMine(),
    getSantaVotes: (env: string, sha256: string) => mockVotes(env, sha256),
    voteSantaFile: (env: string, body: unknown) => mockVote(env, body),
  };
});

const OFF: SantaVoteStatus = { votes: 0, local_threshold: 0, global_threshold: 0, voted: false, allowed: '' };

const SHA = 'ab'.repeat(32);
const MACHINE = '22222222-2222-4222-8222-222222222222';
const own: SantaOwnRequest = {
  id: 1, file_sha256: SHA, machine_id: MACHINE, status: 'pending', created_at: '2026-11-13T10:00:00Z', justification: 'I need it', reason: '', kind: '', monitor_hours: 0,
};

function renderPage(sha256 = SHA, machineId = MACHINE) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RequestPage env="ENV-UUID" sha256={sha256} machineId={machineId} />
    </QueryClientProvider>,
  );
}

describe('RequestPage', () => {
  beforeEach(() => {
    mockCreate.mockReset();
    mockMine.mockReset().mockResolvedValue([]);
    mockVotes.mockReset().mockResolvedValue(OFF);
    mockVote.mockReset();
  });

  it('requests temporary MONITOR mode for the machine', async () => {
    mockCreate.mockResolvedValue({ ...own, file_sha256: '', kind: 'monitor', monitor_hours: 4 });
    renderPage();
    await userEvent.selectOptions(screen.getByLabelText('Duration'), '4');
    await userEvent.type(screen.getByLabelText(/Why do you need it/, { selector: '#santa-monitor-why' }), 'debugging a build');
    await userEvent.click(screen.getByRole('button', { name: 'Request MONITOR mode' }));
    await waitFor(() => expect(mockCreate).toHaveBeenCalledWith('ENV-UUID', { kind: 'monitor', machine_id: MACHINE, hours: 4, justification: 'debugging a build' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Status: Pending');
  });

  it('lists a MONITOR request by its hours', async () => {
    mockMine.mockResolvedValue([{ ...own, file_sha256: '', kind: 'monitor', monitor_hours: 2 }]);
    renderPage();
    expect(await screen.findByText('MONITOR mode for 2 h')).toBeInTheDocument();
  });

  it('hides voting while the environment has no threshold', async () => {
    renderPage();
    await waitFor(() => expect(mockVotes).toHaveBeenCalledWith('ENV-UUID', SHA));
    expect(screen.queryByRole('button', { name: 'Vote to allow' })).not.toBeInTheDocument();
  });

  it('casts a vote with the hash and machine from the link', async () => {
    mockVotes.mockResolvedValue({ ...OFF, votes: 1, local_threshold: 2, global_threshold: 5 });
    mockVote.mockResolvedValue({ votes: 2, local_threshold: 2, global_threshold: 5, voted: true, allowed: 'node' });
    renderPage();
    expect(await screen.findByText(/Votes so far: 1\. At 2 votes .* At 5 votes/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Vote to allow' }));
    await waitFor(() => expect(mockVote).toHaveBeenCalledWith('ENV-UUID', { sha256: SHA, machine_id: MACHINE }));
    expect(await screen.findByRole('status')).toHaveTextContent('allowed on your machine');
    expect(screen.getByRole('button', { name: 'You voted' })).toBeDisabled();
  });

  it('shows why a vote was refused', async () => {
    mockVotes.mockResolvedValue({ ...OFF, global_threshold: 5 });
    mockVote.mockRejectedValue(new Error('this file is blocked by a rule and cannot be voted for'));
    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: 'Vote to allow' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('blocked by a rule');
  });

  it('sends the hash and machine from the link with the justification', async () => {
    mockCreate.mockResolvedValue(own);
    renderPage();
    const submit = screen.getByRole('button', { name: 'Send request' });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Why do you need it/, { selector: '#santa-request-why' }), 'I need it');
    await userEvent.click(submit);
    await waitFor(() => expect(mockCreate).toHaveBeenCalledWith('ENV-UUID', { sha256: SHA, machine_id: MACHINE, justification: 'I need it' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Your request was sent. Status: Pending');
  });

  it('says so when the file was already requested by someone else', async () => {
    mockCreate.mockResolvedValue({ ...own, justification: '' });
    renderPage();
    await userEvent.type(screen.getByLabelText(/Why do you need it/, { selector: '#santa-request-why' }), 'me too');
    await userEvent.click(screen.getByRole('button', { name: 'Send request' }));
    expect(await screen.findByRole('status')).toHaveTextContent('already requested');
  });

  it('shows the API error and keeps the form', async () => {
    mockCreate.mockRejectedValue(new Error('no blocked execution found'));
    renderPage();
    await userEvent.type(screen.getByLabelText(/Why do you need it/, { selector: '#santa-request-why' }), 'why');
    await userEvent.click(screen.getByRole('button', { name: 'Send request' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('no blocked execution found');
    expect(screen.getByRole('button', { name: 'Send request' })).toBeInTheDocument();
  });

  it('refuses a link without the hash or the machine', () => {
    renderPage('', MACHINE);
    expect(screen.getByRole('alert')).toHaveTextContent('incomplete');
    expect(screen.queryByRole('button', { name: 'Send request' })).not.toBeInTheDocument();
  });

  it('lists the caller’s own requests', async () => {
    mockMine.mockResolvedValue([{ ...own, status: 'denied', reason: 'not company software' }]);
    renderPage();
    expect(await screen.findByText('Denied')).toBeInTheDocument();
    expect(screen.getByText('not company software')).toBeInTheDocument();
  });
});

describe('takeSantaRequestTarget', () => {
  it('returns the stored link once and ignores anything else in storage', () => {
    sessionStorage.setItem('osctrl.santaRequest', JSON.stringify({ env: 'e', sha256: SHA, machine_id: MACHINE, to: 'https://evil.example' }));
    expect(takeSantaRequestTarget()).toEqual({ env: 'e', sha256: SHA, machine_id: MACHINE });
    expect(takeSantaRequestTarget()).toBeNull();
    sessionStorage.setItem('osctrl.santaRequest', 'not json');
    expect(takeSantaRequestTarget()).toBeNull();
    sessionStorage.setItem('osctrl.santaRequest', JSON.stringify({ sha256: SHA }));
    expect(takeSantaRequestTarget()).toBeNull();
  });
});
