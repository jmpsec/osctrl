import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import type { ScimStatus, UserGroups } from '$/api/scim';
import { GroupsModal, ScimModal } from './ScimDialogs';

const mockStatus = vi.fn<() => Promise<ScimStatus>>();
const mockRotate = vi.fn<() => Promise<{ token: string }>>();
const mockRemove = vi.fn<() => Promise<void>>();
const mockGroups = vi.fn<(u: string) => Promise<UserGroups>>();
vi.mock('$/api/scim', async () => {
  const actual = await vi.importActual<typeof import('$/api/scim')>('$/api/scim');
  return {
    ...actual,
    getScimStatus: () => mockStatus(),
    rotateScimToken: () => mockRotate(),
    removeScimToken: () => mockRemove(),
    getUserGroups: (u: string) => mockGroups(u),
  };
});

function wrap(node: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

describe('ScimModal', () => {
  beforeEach(() => vi.clearAllMocks());

  it('says SCIM needs Santa when unavailable', async () => {
    mockStatus.mockResolvedValue({ available: false, enabled: false });
    wrap(<ScimModal onClose={() => {}} />);
    expect(await screen.findByText('SCIM needs Santa enabled on osctrl-api.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create token' })).not.toBeInTheDocument();
  });

  it('creates a token and shows it once with the base URL', async () => {
    mockStatus.mockResolvedValueOnce({ available: true, enabled: false });
    mockStatus.mockResolvedValue({ available: true, enabled: true, token_created_at: '2026-11-18T10:00:00Z' });
    mockRotate.mockResolvedValue({ token: 'scim-tok' });
    wrap(<ScimModal onClose={() => {}} />);
    expect(await screen.findByText('Off. Create a token to turn it on.')).toBeInTheDocument();
    expect(screen.getByText(/\/api\/v1\/scim\/v2$/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByDisplayValue('scim-tok')).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Rotate token' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Remove token…' }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm remove' }));
    expect(mockRemove).toHaveBeenCalled();
  });
});

describe('GroupsModal', () => {
  beforeEach(() => vi.clearAllMocks());

  it('lists the stored groups and where they came from', async () => {
    mockGroups.mockResolvedValue({ groups: ['Finance', 'Engineering'], scim: true, updated_at: '2026-11-18T10:00:00Z' });
    wrap(<GroupsModal username="jdoe" onClose={() => {}} />);
    expect(await screen.findByText('Finance')).toBeInTheDocument();
    expect(screen.getByText('Engineering')).toBeInTheDocument();
    expect(screen.getByText(/Managed by SCIM/)).toBeInTheDocument();
    expect(mockGroups).toHaveBeenCalledWith('jdoe');
  });

  it('says when there are none', async () => {
    mockGroups.mockResolvedValue({ groups: [], scim: false });
    wrap(<GroupsModal username="jdoe" onClose={() => {}} />);
    expect(await screen.findByText('No groups stored.')).toBeInTheDocument();
    expect(screen.getByText('From the last SSO login')).toBeInTheDocument();
  });
});
