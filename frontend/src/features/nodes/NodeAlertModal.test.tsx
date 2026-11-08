import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NodeAlertModal } from './NodeAlertModal';
import type { UserMeResponse } from '$/api/types';

const mockGetMe = vi.fn<() => Promise<UserMeResponse>>();
vi.mock('$/api/users', () => ({ getMe: () => mockGetMe() }));
vi.mock('$/api/alerts', () => ({
  createAlertRule: vi.fn(),
  applyAlerts: vi.fn(),
  listAlertChannels: () => Promise.resolve([]),
}));
vi.mock('$/api/client', () => ({
  AuthError: class AuthError extends Error {},
}));

function makeMe(overrides: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'u', email: '', fullname: 'u', admin: false, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: 'aaaa',
    token_expire: new Date(Date.now() + 86_400_000).toISOString(),
    last_access: new Date().toISOString(), permissions: {}, preferred_language: '',
    ...overrides,
  };
}

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeAlertModal envID={1} envUuid="env-uuid" envName="prod" uuid="node-1" hostname="web01" onClose={() => {}} />
    </QueryClientProvider>,
  );
}

const LOG_KINDS = [/Errors reported by this node/, /Log match on this node/];

describe('NodeAlertModal', () => {
  beforeEach(() => vi.clearAllMocks());

  it('offers only the inactive kind to an alert admin without full query tier', async () => {
    mockGetMe.mockResolvedValue(
      makeMe({
        alert_admin: true,
        permissions: { 'env-uuid': { user: true, query: true, carve: false, query_tier: 'standard', admin: false } },
      }),
    );
    renderModal();
    await vi.waitFor(() => expect(mockGetMe).toHaveBeenCalled());
    expect(await screen.findByRole('radio', { name: /Node goes inactive/ })).toBeInTheDocument();
    for (const name of LOG_KINDS) expect(screen.queryByRole('radio', { name })).not.toBeInTheDocument();
  });

  it('offers the log kinds once the env grants full query tier', async () => {
    mockGetMe.mockResolvedValue(
      makeMe({
        alert_admin: true,
        permissions: { 'env-uuid': { user: true, query: true, carve: false, query_tier: 'full', admin: false } },
      }),
    );
    renderModal();
    for (const name of LOG_KINDS) expect(await screen.findByRole('radio', { name })).toBeInTheDocument();
  });
});
