import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { SantaReport } from '$/api/santa';
import { ReportsTab } from './ReportsTab';

const mockReport = vi.fn<(env: string, days: number) => Promise<SantaReport>>();
const mockBinary = vi.fn<(env: string, sha256: string) => Promise<never>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    getSantaReport: (env: string, days: number) => mockReport(env, days),
    getSantaBinary: (env: string, sha256: string) => mockBinary(env, sha256),
  };
});

const SHA = 'ab'.repeat(32);
const report: SantaReport = {
  days: 14,
  since: '2026-11-01T00:00:00Z',
  lockdown_ready: [
    { machine_id: 'M-1', hostname: 'quiet', mode_source: 'env', last_sync_at: '2026-11-15T10:00:00Z', would_block: 0, ready: true },
    { machine_id: 'M-2', hostname: 'gone', mode_source: 'env', last_sync_at: null, would_block: 0, ready: false },
    { machine_id: 'M-3', hostname: 'noisy', mode_source: 'tag', last_sync_at: '2026-11-15T10:00:00Z', would_block: 7, ready: false },
  ],
  top_blocked: [{ sha256: SHA, file_name: 'tool', team_id: 'ABCDE12345', events: 9, machines: 4 }],
  top_blocked_teams: [{ team_id: 'ABCDE12345', events: 9, machines: 4, binaries: 2 }],
  coverage_gaps: null,
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ReportsTab env="dev" />
    </QueryClientProvider>,
  );
}

describe('ReportsTab', () => {
  beforeEach(() => {
    mockReport.mockReset().mockResolvedValue(report);
    mockBinary.mockReset().mockRejectedValue(new Error('no events for this file'));
  });

  it('shows which MONITOR machines are ready, and why the others are not', async () => {
    renderTab();
    expect(await screen.findByText('1 of 3 machines in MONITOR are ready.')).toBeInTheDocument();
    expect(mockReport).toHaveBeenCalledWith('dev', 14);
    expect(within(screen.getByText('quiet').closest('tr')!).getByText('Ready')).toBeInTheDocument();
    expect(within(screen.getByText('gone').closest('tr')!).getByText('No recent sync')).toBeInTheDocument();
    const noisy = screen.getByText('noisy').closest('tr')!;
    expect(within(noisy).getByText('7')).toBeInTheDocument();
    expect(within(noisy).getByText('Not ready')).toBeInTheDocument();
  });

  it('ranks blocked binaries and team IDs, and says when a list is empty', async () => {
    renderTab();
    const blocked = (await screen.findByRole('heading', { name: 'Top blocked binaries' })).closest('section')!;
    expect(within(blocked).getByRole('button', { name: 'Binary details: tool' })).toBeInTheDocument();
    const teams = screen.getByRole('heading', { name: 'Top blocked team IDs' }).closest('section')!;
    expect(within(teams.querySelector('tbody')!).getByText('ABCDE12345').closest('tr')).toHaveTextContent('942');
    const gaps = screen.getByRole('heading', { name: 'Rule coverage gaps' }).closest('section')!;
    expect(within(gaps).getByText('Nothing in this window.')).toBeInTheDocument();
  });

  it('changes the window and opens binary details', async () => {
    const user = userEvent.setup();
    renderTab();
    await user.selectOptions(await screen.findByLabelText('Window'), '30');
    await waitFor(() => expect(mockReport).toHaveBeenLastCalledWith('dev', 30));
    await user.click(screen.getByRole('button', { name: 'Binary details: tool' }));
    expect(await screen.findByRole('dialog', { name: 'Binary details' })).toBeInTheDocument();
    expect(mockBinary).toHaveBeenCalledWith('dev', SHA);
  });

  it('shows the API error', async () => {
    mockReport.mockRejectedValue(new Error('days must be 1 to 30'));
    renderTab();
    expect(await screen.findByRole('alert')).toHaveTextContent('days must be 1 to 30');
  });
});
