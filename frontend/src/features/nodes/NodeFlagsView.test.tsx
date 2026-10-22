import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeFlagsView } from './NodeFlagsView';
import type { NodeFlags } from '$/api/types';

const api = vi.hoisted(() => ({
  getNodeFlags: vi.fn(),
  putNodeFlags: vi.fn(),
  deleteNodeFlags: vi.fn(),
}));

vi.mock('$/api/nodes', () => ({
  getNodeFlags: api.getNodeFlags,
  putNodeFlags: api.putNodeFlags,
  deleteNodeFlags: api.deleteNodeFlags,
}));

// Monaco pulls in a heavy worker — stub it with a textarea.
vi.mock('$/components/forms/CodeEditor', () => ({
  CodeEditor: ({
    value,
    onChange,
    readOnly,
    language,
    'aria-label': label,
  }: {
    value: string;
    onChange?: (v: string) => void;
    readOnly?: boolean;
    language?: string;
    'aria-label'?: string;
  }) => (
    <textarea
      aria-label={label}
      data-language={language}
      value={value}
      readOnly={readOnly}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}));

const ENV_FLAGS = '--verbose=false\n--logger_min_status=1';
const APPLIED_FLAGS = '--verbose=true\n--logger_min_status=1';
const FETCHED = '2026-10-18T10:00:00Z';

function makeFlags(overrides: Partial<NodeFlags> = {}): NodeFlags {
  return {
    environment: ENV_FLAGS,
    override: '',
    applied: ENV_FLAGS,
    expires_at: null,
    expired: false,
    updated_by: '',
    updated_at: null,
    conflicts: [],
    osctrld: {
      last_fetched_at: FETCHED,
      apply_result: 'applied',
      apply_error: '',
      apply_at: null,
      rejected_current: false,
    },
    ...overrides,
  };
}

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeFlagsView env="prod" uuid="uuid-1" hostname="web-prod-07" />
    </QueryClientProvider>,
  );
}

async function unlock(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Edit flags override' }));
  await user.click(screen.getByRole('checkbox'));
  await user.click(screen.getByRole('button', { name: 'Unlock editing' }));
}

describe('NodeFlagsView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getNodeFlags.mockResolvedValue(makeFlags());
    api.putNodeFlags.mockResolvedValue(makeFlags({ override: '--verbose=true' }));
    api.deleteNodeFlags.mockResolvedValue(makeFlags());
  });

  it('shows the applied flags read-only by default as plain text', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ override: '--verbose=true', applied: APPLIED_FLAGS }));
    renderView();
    const editor = await screen.findByLabelText('Applied flags');
    expect(screen.getByRole('button', { name: 'Applied' })).toHaveAttribute('aria-pressed', 'true');
    expect(editor).toHaveValue(APPLIED_FLAGS);
    expect(editor).toHaveAttribute('readonly');
    expect(editor).toHaveAttribute('data-language', 'plaintext');
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Environment' }));
    expect(screen.getByLabelText('Environment flags')).toHaveValue(ENV_FLAGS);
    await user.click(screen.getByRole('button', { name: 'Node override' }));
    expect(screen.getByLabelText('Node override flags')).toHaveValue('--verbose=true');
    await user.click(screen.getByRole('button', { name: 'Diff' }));
    expect(screen.getByText('Environment → Applied')).toBeInTheDocument();
    expect(screen.getByText('--verbose=false')).toBeInTheDocument();
    expect(screen.getByText('--verbose=true')).toBeInTheDocument();
  });

  it('unlock requires the confirmation checkbox', async () => {
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole('button', { name: 'Edit flags override' }));
    const dialog = screen.getByRole('dialog', { name: 'Override flags for web-prod-07?' });
    expect(
      within(dialog).getByText(
        "This changes the flags osquery starts with on this host only. osctrld applies it on its next sync (up to an hour) and restarts osquery; if osquery won't start with it, osctrld restores the environment's flags. Settings that keep the host connected to osctrl can't be overridden. It stays until it is removed or expires.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/No osctrld has been seen/)).not.toBeInTheDocument();
    const unlockBtn = within(dialog).getByRole('button', { name: 'Unlock editing' });
    expect(unlockBtn).toBeDisabled();
    await user.click(
      within(dialog).getByLabelText("I understand this changes osquery on this host and I know what I'm doing"),
    );
    expect(unlockBtn).toBeEnabled();
    await user.click(unlockBtn);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByText('osctrld applies changes on its next sync, up to an hour.')).toBeInTheDocument();
  });

  it('adds a line to the unlock dialog when no osctrld has been seen', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ osctrld: null }));
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole('button', { name: 'Edit flags override' }));
    const dialog = screen.getByRole('dialog', { name: 'Override flags for web-prod-07?' });
    expect(
      within(dialog).getByText(
        "No osctrld has been seen for this host, so this override won't reach it until osctrld manages it.",
      ),
    ).toBeInTheDocument();
  });

  it('saving sends the override and expiry', async () => {
    const user = userEvent.setup();
    renderView();
    await unlock(user);
    expect(screen.getByRole('button', { name: 'Node override' })).toHaveAttribute('aria-pressed', 'true');
    const editor = screen.getByLabelText('Node override flags');
    expect(editor).not.toHaveAttribute('readonly');
    fireEvent.change(editor, { target: { value: '--verbose=true' } });
    fireEvent.change(screen.getByLabelText('Expires (optional)'), { target: { value: '2030-01-02T03:04' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.putNodeFlags).toHaveBeenCalledTimes(1));
    expect(api.putNodeFlags).toHaveBeenCalledWith('prod', 'uuid-1', {
      override: '--verbose=true',
      expires_at: new Date('2030-01-02T03:04').toISOString(),
    });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument());
  });

  it('shows the server error inline and stays unlocked', async () => {
    api.putNodeFlags.mockRejectedValue(new Error('flag "tls_hostname" cannot be overridden'));
    const user = userEvent.setup();
    renderView();
    await unlock(user);
    fireEvent.change(screen.getByLabelText('Node override flags'), { target: { value: '--tls_hostname=x' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('flag "tls_hostname" cannot be overridden');
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByLabelText('Node override flags')).toHaveValue('--tls_hostname=x');
  });

  it('cancel discards and re-locks', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ override: '--verbose=true' }));
    const user = userEvent.setup();
    renderView();
    await unlock(user);
    fireEvent.change(screen.getByLabelText('Node override flags'), { target: { value: 'changed' } });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    const editor = screen.getByLabelText('Node override flags');
    expect(editor).toHaveValue('--verbose=true');
    expect(editor).toHaveAttribute('readonly');
    expect(api.putNodeFlags).not.toHaveBeenCalled();
  });

  it('remove asks for confirmation and calls deleteNodeFlags', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ override: '--verbose=true' }));
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole('button', { name: 'Remove flags override' }));
    const dialog = screen.getByRole('dialog', { name: 'Remove the flags override for web-prod-07?' });
    expect(api.deleteNodeFlags).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Remove flags override' }));
    await waitFor(() => expect(api.deleteNodeFlags).toHaveBeenCalledWith('prod', 'uuid-1'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('hides Remove flags override when there is none', async () => {
    renderView();
    await screen.findByRole('button', { name: 'Edit flags override' });
    expect(screen.queryByRole('button', { name: 'Remove flags override' })).not.toBeInTheDocument();
  });

  it('status line: managed by osctrld', async () => {
    renderView();
    expect(
      await screen.findByText(`Managed by osctrld — last fetched flags ${new Date(FETCHED).toLocaleString()}`),
    ).toBeInTheDocument();
  });

  it('status line: no osctrld seen', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ osctrld: null }));
    renderView();
    expect(
      await screen.findByText('No osctrld seen for this host: a flags override will not reach it.'),
    ).toBeInTheDocument();
  });

  it('status line: rejected override is shown as plain text', async () => {
    const applyAt = '2026-10-18T11:00:00Z';
    api.getNodeFlags.mockResolvedValue(
      makeFlags({
        override: '--bogus',
        osctrld: {
          last_fetched_at: FETCHED,
          apply_result: 'rejected',
          apply_error: '<b>osqueryd exited</b>',
          apply_at: applyAt,
          rejected_current: true,
        },
      }),
    );
    renderView();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(
      `osquery on this host rejected this override on ${new Date(applyAt).toLocaleString()} and osctrld restored the environment's flags: <b>osqueryd exited</b>`,
    );
    expect(alert.querySelector('b')).toBeNull();
  });

  it('warns about flags also set in the configuration options', async () => {
    api.getNodeFlags.mockResolvedValue(makeFlags({ conflicts: ['verbose', 'logger_path'] }));
    renderView();
    expect(
      await screen.findByText(
        "Also set in the configuration's options, which can take precedence: verbose, logger_path",
      ),
    ).toBeInTheDocument();
  });

  it('no conflicts warning when there are none', async () => {
    renderView();
    await screen.findByLabelText('Applied flags');
    expect(screen.queryByText(/Also set in the configuration's options/)).not.toBeInTheDocument();
  });

  it('handles a missing last_fetched_at', async () => {
    api.getNodeFlags.mockResolvedValue(
      makeFlags({
        osctrld: { apply_result: 'applied', apply_error: '', apply_at: null, rejected_current: false },
      }),
    );
    renderView();
    expect(await screen.findByText('Managed by osctrld — no flags fetch seen yet')).toBeInTheDocument();
  });

  it('does not render the osquery down banner itself (shown at page level)', async () => {
    api.getNodeFlags.mockResolvedValue(
      makeFlags({
        osctrld: { last_fetched_at: FETCHED, apply_result: 'applied', apply_error: '', apply_at: null, rejected_current: false, osquery_running: false },
      }),
    );
    renderView();
    await screen.findByLabelText('Applied flags');
    expect(screen.queryByTestId('osquery-down-banner')).not.toBeInTheDocument();
  });
});
