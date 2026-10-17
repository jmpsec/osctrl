import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeExtensionsView } from './NodeExtensionsView';
import type { NodeExtensions } from '$/api/types';

const api = vi.hoisted(() => ({
  getNodeExtensions: vi.fn(),
  assignNodeExtension: vi.fn(),
  unassignNodeExtension: vi.fn(),
}));

vi.mock('$/api/extensions', () => ({
  getNodeExtensions: api.getNodeExtensions,
  assignNodeExtension: api.assignNodeExtension,
  unassignNodeExtension: api.unassignNodeExtension,
}));

const REPORTED = '2026-10-18T10:00:00Z';
const AT = '2026-10-18T09:59:00Z';

function make(o: Partial<NodeExtensions> = {}): NodeExtensions {
  return {
    effective: [
      { name: 'env-ext', source: 'environment', command_execution: false, platforms: ['linux'], available: true },
      { name: 'cmd-ext', source: 'host', command_execution: true, platforms: ['linux'], available: false },
    ],
    assignments: [
      { extension_id: 9, name: 'cmd-ext', expires_at: null, expired: false, created_by: 'root', created_at: '2026-10-01T10:00:00Z' },
    ],
    status: [
      { name: 'env-ext', sha256: 'aa', result: 'ok', error: '', at: AT, reported_at: REPORTED },
      { name: 'cmd-ext', sha256: 'bb', result: 'rejected', error: '<b>boom</b>', at: AT, reported_at: REPORTED },
    ],
    library: null,
    ...o,
  };
}

const LIBRARY = [
  { id: 9, name: 'cmd-ext', description: '', version: '1.0', command_execution: true, platforms: ['linux'] },
  { id: 10, name: 'shell-ext', description: '', version: '2.0', command_execution: true, platforms: ['linux'] },
];

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={qc}>
      <NodeExtensionsView env="prod" uuid="uuid-1" hostname="web-prod-07" />
    </QueryClientProvider>,
  );
  return { qc, ...view };
}

describe('NodeExtensionsView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getNodeExtensions.mockResolvedValue(make());
    api.assignNodeExtension.mockResolvedValue(make());
    api.unassignNodeExtension.mockResolvedValue(make({ assignments: [] }));
  });

  it('lists effective extensions with source, availability and last status', async () => {
    renderView();
    const envRow = (await screen.findByText('env-ext')).closest('li') as HTMLElement;
    expect(within(envRow).getByText('Environment')).toBeInTheDocument();
    expect(within(envRow).getByText('ok')).toBeInTheDocument();
    expect(within(envRow).queryByText(/No file for this platform/)).not.toBeInTheDocument();
    const cmdRow = screen.getByText('cmd-ext', { selector: 'span' }).closest('li') as HTMLElement;
    expect(within(cmdRow).getByText('This host')).toBeInTheDocument();
    expect(within(cmdRow).getByText('No file for this platform')).toBeInTheDocument();
    expect(api.getNodeExtensions).toHaveBeenCalledWith('prod', 'uuid-1');
  });

  it('renders a rejected status as plain text with its time', async () => {
    renderView();
    const row = (await screen.findByText('cmd-ext', { selector: 'span' })).closest('li') as HTMLElement;
    expect(row).toHaveTextContent(`rejected ${new Date(AT).toLocaleString()}: <b>boom</b>`);
    expect(row.querySelector('b')).toBeNull();
  });

  it('shows the note on an ok status, e.g. extensions disabled by flags', async () => {
    api.getNodeExtensions.mockResolvedValue(
      make({ status: [{ name: 'env-ext', sha256: 'aa', result: 'ok', error: 'extensions are disabled by flags', at: AT, reported_at: REPORTED }] }),
    );
    renderView();
    const row = (await screen.findByText('env-ext')).closest('li') as HTMLElement;
    expect(row).toHaveTextContent('ok: extensions are disabled by flags');
  });

  it('lists a removed command-execution extension still on the host, as plain text', async () => {
    api.getNodeExtensions.mockResolvedValue(
      make({
        effective: [],
        assignments: [],
        status: [
          { name: 'gone-ext', sha256: 'cc', result: 'kept', error: '<b>busy</b>', at: AT, reported_at: REPORTED, lingering: true },
          { name: 'old-ext', sha256: 'dd', result: 'ok', error: '', at: AT, reported_at: REPORTED, lingering: false },
        ],
      }),
    );
    renderView();
    const heading = await screen.findByText('Removed but still on this host');
    const list = heading.parentElement as HTMLElement;
    const row = within(list).getByText('gone-ext').closest('li') as HTMLElement;
    expect(row).toHaveTextContent(`kept ${new Date(AT).toLocaleString()}: <b>busy</b>`);
    expect(row.querySelector('b')).toBeNull();
    expect(within(list).queryByText('old-ext')).not.toBeInTheDocument();
  });

  it('shows a removed status as muted and a kept one as a failure', async () => {
    api.getNodeExtensions.mockResolvedValue(
      make({
        status: [
          { name: 'env-ext', sha256: 'aa', result: 'removed', error: '', at: AT, reported_at: REPORTED },
          { name: 'cmd-ext', sha256: 'bb', result: 'kept', error: 'busy', at: AT, reported_at: REPORTED },
        ],
      }),
    );
    renderView();
    const removed = await screen.findByText(`removed ${new Date(AT).toLocaleString()}`);
    expect(removed.className).not.toMatch(/danger/);
    const kept = screen.getByText(`kept ${new Date(AT).toLocaleString()}: busy`);
    expect(kept.className).toMatch(/danger/);
  });

  it('explains that osctrld has not reported when there is no status', async () => {
    api.getNodeExtensions.mockResolvedValue(make({ status: [] }));
    renderView();
    expect(
      await screen.findByText(
        'osctrld has not reported on extensions for this host yet. It reports after its next sync (up to an hour).',
      ),
    ).toBeInTheDocument();
  });

  it('hides command-execution controls from an environment admin', async () => {
    renderView();
    await screen.findByText('env-ext');
    expect(screen.queryByRole('button', { name: 'Allow command execution' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Remove cmd-ext/ })).not.toBeInTheDocument();
  });

  describe('as a super admin', () => {
    beforeEach(() => {
      api.getNodeExtensions.mockResolvedValue(make({ assignments: [], library: LIBRARY }));
    });

    async function openDialog(user: ReturnType<typeof userEvent.setup>) {
      await user.click(await screen.findByRole('button', { name: 'Allow command execution' }));
      return screen.getByRole('dialog', { name: 'Allow command execution on web-prod-07?' });
    }

    it('requires the checkbox and sends the chosen expiry', async () => {
      const user = userEvent.setup();
      renderView();
      const dialog = await openDialog(user);
      expect(
        within(dialog).getByText(
          'This installs an extension that lets anyone who can query this host run commands on it as root. osctrld installs it on its next sync (up to an hour) and restarts osquery. It stays until it is removed or expires.',
        ),
      ).toBeInTheDocument();
      const confirm = within(dialog).getByRole('button', { name: 'Allow command execution' });
      expect(confirm).toBeDisabled();
      await user.selectOptions(within(dialog).getByLabelText('Extension'), 'shell-ext 2.0');
      expect(confirm).toBeDisabled();
      await user.click(
        within(dialog).getByLabelText(
          "I understand this allows running commands on this host and I know what I'm doing",
        ),
      );
      fireEvent.change(within(dialog).getByLabelText('Expires (optional)'), { target: { value: '2030-01-02T03:04' } });
      expect(confirm).toBeEnabled();
      await user.click(confirm);
      await waitFor(() => expect(api.assignNodeExtension).toHaveBeenCalledTimes(1));
      expect(api.assignNodeExtension).toHaveBeenCalledWith(
        'prod',
        'uuid-1',
        10,
        new Date('2030-01-02T03:04').toISOString(),
      );
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    });

    it('sends a null expiry when none is chosen', async () => {
      const user = userEvent.setup();
      renderView();
      const dialog = await openDialog(user);
      await user.selectOptions(within(dialog).getByLabelText('Extension'), 'cmd-ext 1.0');
      await user.click(within(dialog).getByRole('checkbox'));
      await user.click(within(dialog).getByRole('button', { name: 'Allow command execution' }));
      await waitFor(() => expect(api.assignNodeExtension).toHaveBeenCalledWith('prod', 'uuid-1', 9, null));
    });

    it('Cancel closes without assigning', async () => {
      const user = userEvent.setup();
      renderView();
      const dialog = await openDialog(user);
      await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(api.assignNodeExtension).not.toHaveBeenCalled();
    });

    it('shows the server error inline and keeps the dialog open', async () => {
      api.assignNodeExtension.mockRejectedValue(new Error('expires_at must be in the future'));
      const user = userEvent.setup();
      renderView();
      const dialog = await openDialog(user);
      await user.selectOptions(within(dialog).getByLabelText('Extension'), 'cmd-ext 1.0');
      await user.click(within(dialog).getByRole('checkbox'));
      await user.click(within(dialog).getByRole('button', { name: 'Allow command execution' }));
      expect(await within(dialog).findByRole('alert')).toHaveTextContent('expires_at must be in the future');
    });

    it('removes an assignment after its own confirmation', async () => {
      api.getNodeExtensions.mockResolvedValue(make({ library: LIBRARY }));
      const user = userEvent.setup();
      renderView();
      await user.click(await screen.findByRole('button', { name: 'Remove cmd-ext' }));
      const dialog = screen.getByRole('dialog', { name: 'Remove command execution from web-prod-07?' });
      expect(api.unassignNodeExtension).not.toHaveBeenCalled();
      await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
      await waitFor(() => expect(api.unassignNodeExtension).toHaveBeenCalledWith('prod', 'uuid-1', 9));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    });

    it('notes an empty library', async () => {
      api.getNodeExtensions.mockResolvedValue(make({ assignments: [], library: [] }));
      renderView();
      expect(await screen.findByText('No command-execution extensions are available in the library.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Allow command execution' })).not.toBeInTheDocument();
    });
  });
});
