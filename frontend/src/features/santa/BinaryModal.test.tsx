import type { ReactNode } from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import userEvent from '@testing-library/user-event';
import type { SantaBinary, SantaRisk } from '$/api/santa';
import { BinaryModal } from './BinaryModal';

const mockBinary = vi.fn<(env: string, sha256: string) => Promise<SantaBinary>>();
const mockCheck = vi.fn<(env: string, sha256: string) => Promise<SantaRisk>>();

vi.mock('$/api/santa', async () => {
  const actual = await vi.importActual<typeof import('$/api/santa')>('$/api/santa');
  return {
    ...actual,
    getSantaBinary: (env: string, sha256: string) => mockBinary(env, sha256),
    checkSantaRisk: (env: string, sha256: string) => mockCheck(env, sha256),
    carveSantaEvent: (env: string, id: number) => mockCarve(env, id),
  };
});
const mockCarve = vi.fn<(env: string, id: number) => Promise<{ query_name: string }>>();
vi.mock('$/api/carves', () => ({ getCarve: () => Promise.reject(new Error('no access')) }));
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
}));

const SHA = 'ab'.repeat(32);
const binary: SantaBinary = {
  sha256: SHA, file_name: 'tool', file_path: '/Applications/Tool.app/Contents/MacOS', team_id: 'ABCDE12345',
  signing_id: 'ABCDE12345:com.example.tool', cd_hash: '0123', bundle_id: 'com.example.tool', bundle_name: 'Tool',
  bundle_version: '1.2.3', bundle_path: '/Applications/Tool.app',
  signing_chain: [
    { sha256: 'c3'.repeat(32), cn: 'Developer ID Application: Example Inc', org: 'Example Inc', ou: 'ABCDE12345', valid_from: '2024-01-01T00:00:00Z', valid_until: '2029-01-01T00:00:00Z' },
    { sha256: 'd4'.repeat(32), cn: 'Developer ID Certification Authority', org: 'Apple Inc.', ou: '', valid_from: '2012-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' },
  ],
  first_seen: '2026-11-01T10:00:00Z', last_seen: '2026-11-14T10:00:00Z', events: 12, blocked: 3, machines: 5,
  rules: [{
    id: 9, identifier: 'ABCDE12345', rule_type: 'TEAMID', policy: 'BLOCKLIST', cel_expr: '', custom_msg: '', custom_url: '',
    scope: 'tag', scope_value: 'dev', created_at: '2026-11-01T10:00:00Z', created_by: 'alice',
  }],
  latest_event_id: 0, latest_machine_id: '', latest_carve: '',
};

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <BinaryModal env="dev" sha256={SHA} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe('BinaryModal', () => {
  // Braces matter: a function returned from beforeEach runs as a teardown.
  beforeEach(() => {
    mockBinary.mockReset();
  });

  it('shows the identity, prevalence, signing chain and matching rules', async () => {
    mockBinary.mockResolvedValue(binary);
    renderModal();
    const dialog = await screen.findByRole('dialog', { name: 'Binary details' });
    expect(await within(dialog).findByText('Tool 1.2.3')).toBeInTheDocument();
    expect(mockBinary).toHaveBeenCalledWith('dev', SHA);
    expect(within(dialog).getByText(SHA)).toBeInTheDocument();
    expect(within(dialog).getByText('ABCDE12345:com.example.tool')).toBeInTheDocument();
    expect(within(dialog).getByText('Machines').nextSibling).toHaveTextContent('5');
    expect(within(dialog).getByText('Executions').nextSibling).toHaveTextContent('12');
    expect(within(dialog).getByText('Blocked').nextSibling).toHaveTextContent('3');
    expect(within(dialog).getAllByRole('listitem')).toHaveLength(2);
    expect(within(dialog).getByText('Developer ID Application: Example Inc')).toBeInTheDocument();
    const rule = within(dialog).getByText('TEAMID').closest('tr')!;
    expect(within(rule).getByText('BLOCKLIST')).toBeInTheDocument();
    expect(within(rule).getByText('dev')).toBeInTheDocument();
  });

  it('says so when there is no chain and no rule', async () => {
    mockBinary.mockResolvedValue({ ...binary, signing_chain: null, rules: null });
    renderModal();
    expect(await screen.findByText('No signing chain reported.')).toBeInTheDocument();
    expect(screen.getByText(/No rule names this binary/)).toBeInTheDocument();
  });

  it('hides risk checks when none is configured', async () => {
    mockBinary.mockResolvedValue(binary);
    renderModal();
    await screen.findByText('Tool 1.2.3');
    expect(screen.queryByRole('button', { name: 'Check now' })).not.toBeInTheDocument();
  });

  it('runs the risk checks on demand and shows each verdict', async () => {
    mockBinary.mockResolvedValue({ ...binary, risk: { verdict: 'unchecked', checks: null } });
    mockCheck.mockResolvedValue({
      verdict: 'flagged',
      checks: [{ check: 'virustotal', verdict: 'flagged', detail: '12 of 70 engines flag it', checked_at: '', expires_at: '' }],
    });
    renderModal();
    expect(await screen.findByText('Not checked')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Check now' }));
    expect(await screen.findByText('virustotal: Flagged — 12 of 70 engines flag it')).toBeInTheDocument();
    expect(mockCheck).toHaveBeenCalledWith('dev', SHA);
  });

  it('retrieves the file from the machine that last ran it', async () => {
    mockBinary.mockResolvedValue({ ...binary, latest_event_id: 42, latest_machine_id: 'M-9' });
    mockCarve.mockResolvedValue({ query_name: 'carve_x' });
    renderModal();
    expect(await screen.findByText('Last ran on M-9')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retrieve file' }));
    expect(mockCarve).toHaveBeenCalledWith('dev', 42);
    expect(await screen.findByRole('link', { name: 'View carve' })).toBeInTheDocument();
  });

  it('shows the API error', async () => {
    mockBinary.mockRejectedValue(new Error('no events for this file'));
    renderModal();
    expect(await screen.findByRole('alert')).toHaveTextContent('no events for this file');
  });
});
