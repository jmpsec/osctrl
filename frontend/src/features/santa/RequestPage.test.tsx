import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SantaOwnRequest } from '$/api/santa';
import { takeSantaRequestTarget } from '$/routes/santa.request.$env';
import { RequestPage } from './RequestPage';

const mockCreate = vi.fn<(env: string, body: unknown) => Promise<SantaOwnRequest>>();
const mockMine = vi.fn<() => Promise<SantaOwnRequest[]>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    createSantaRequest: (env: string, body: unknown) => mockCreate(env, body),
    listMySantaRequests: () => mockMine(),
  };
});

const SHA = 'ab'.repeat(32);
const MACHINE = '22222222-2222-4222-8222-222222222222';
const own: SantaOwnRequest = {
  id: 1, file_sha256: SHA, machine_id: MACHINE, status: 'pending', created_at: '2026-11-13T10:00:00Z', justification: 'I need it',
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
  });

  it('sends the hash and machine from the link with the justification', async () => {
    mockCreate.mockResolvedValue(own);
    renderPage();
    const submit = screen.getByRole('button', { name: 'Send request' });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Why do you need it/), 'I need it');
    await userEvent.click(submit);
    await waitFor(() => expect(mockCreate).toHaveBeenCalledWith('ENV-UUID', { sha256: SHA, machine_id: MACHINE, justification: 'I need it' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Your request was sent. Status: Pending');
  });

  it('says so when the file was already requested by someone else', async () => {
    mockCreate.mockResolvedValue({ ...own, justification: '' });
    renderPage();
    await userEvent.type(screen.getByLabelText(/Why do you need it/), 'me too');
    await userEvent.click(screen.getByRole('button', { name: 'Send request' }));
    expect(await screen.findByRole('status')).toHaveTextContent('already requested');
  });

  it('shows the API error and keeps the form', async () => {
    mockCreate.mockRejectedValue(new Error('no blocked execution found'));
    renderPage();
    await userEvent.type(screen.getByLabelText(/Why do you need it/), 'why');
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
    mockMine.mockResolvedValue([{ ...own, status: 'denied' }]);
    renderPage();
    expect(await screen.findByText('Denied')).toBeInTheDocument();
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
