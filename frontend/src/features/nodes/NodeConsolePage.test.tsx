import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { NodeConsolePanel } from './NodeConsolePage';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  useNavigate: () => vi.fn(),
}));

vi.mock('$/api/console', () => ({
  createConsoleSession: vi.fn(async () => ({
    id: 1,
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
    environment_id: 1,
    node_id: 1,
    node_uuid: 'NODE',
    creator: 'alice',
    cwd: '/',
    platform: 'linux',
    active: true,
  })),
  closeConsoleSession: vi.fn(async () => ({ message: 'closed' })),
  submitConsoleCommand: vi.fn(async () => ({
    command: {
      id: 10,
      created_at: '2026-07-21T00:00:00Z',
      updated_at: '2026-07-21T00:00:00Z',
      session_id: 1,
      status: 'queued',
      input: 'ps',
    },
    parsed: { kind: 'remote', command: 'ps' },
  })),
  getConsoleCommand: vi.fn(async () => ({
    id: 10,
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
    session_id: 1,
    status: 'queued',
    input: 'ps',
  })),
  getConsoleCommandResults: vi.fn(async () => [{ pid: 1, name: 'launchd' }]),
}));

describe('NodeConsolePanel', () => {
  it('shows spinner and disables input while command is pending', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });

    render(
      <QueryClientProvider client={queryClient}>
        <NodeConsolePanel env="env" uuid="NODE" />
      </QueryClientProvider>,
    );

    const input = await screen.findByLabelText(/console input/i);
    await waitFor(() => expect(input).not.toBeDisabled());

    fireEvent.change(input, { target: { value: 'ps' } });
    fireEvent.submit(input.closest('form')!);

    expect(await screen.findByText(/waiting for node/i)).toBeInTheDocument();
    expect(input).toBeDisabled();
  });
});
