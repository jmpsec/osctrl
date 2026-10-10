import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PostureProfile } from '$/api/types';
import { VulnProfilePicker } from './VulnProfilePicker';

const mockGetProfiles = vi.fn<() => Promise<PostureProfile[]>>();
vi.mock('$/api/vulnerabilities', () => ({ getVulnProfiles: () => mockGetProfiles() }));

const linux: PostureProfile = {
  id: 'vuln-linux',
  name: 'Vulnerability inventory (Linux)',
  description: 'Daily software inventory snapshots for vulnerability matching.',
  platform: 'linux',
  queries: {
    os: { query_name: 'osctrl:vuln:os', query: 'SELECT name FROM os_version', interval: 86400, platform: 'linux', snapshot: true },
    deb: { query_name: 'osctrl:vuln:deb', query: 'SELECT name FROM deb_packages', interval: 86400, platform: 'linux', snapshot: true },
  },
};

function renderPicker(onPick = vi.fn(), onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <VulnProfilePicker onPick={onPick} onClose={onClose} />
    </QueryClientProvider>,
  );
  return { onPick, onClose };
}

describe('VulnProfilePicker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('lists each profile with its queries and hands the chosen one back', async () => {
    const user = userEvent.setup();
    mockGetProfiles.mockResolvedValue([linux]);
    const { onPick } = renderPicker();
    expect(await screen.findByText('Vulnerability inventory (Linux)')).toBeInTheDocument();
    expect(screen.getByText('osctrl:vuln:deb')).toBeInTheDocument();
    expect(screen.getByText('Linux')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Vulnerability inventory (Linux) to schedule' }));
    expect(onPick).toHaveBeenCalledWith(linux);
  });

  it('tells a load failure apart from an empty list', async () => {
    const user = userEvent.setup();
    // The picker retries once (retry: 1, like the posture picker), so the
    // failure surfaces after the second rejection.
    mockGetProfiles
      .mockRejectedValueOnce(new Error('boom'))
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce([]);
    renderPicker();
    expect(await screen.findByText('Failed to load inventory profiles.', {}, { timeout: 3_000 })).toBeInTheDocument();
    expect(screen.queryByText('No inventory profiles available.')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No inventory profiles available.')).toBeInTheDocument();
  });
});
