import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeConfigTab } from './NodeConfigTab';
import type { NodeConfig } from '$/api/types';

const api = vi.hoisted(() => ({
  getNodeConfig: vi.fn(),
  putNodeConfig: vi.fn(),
  deleteNodeConfig: vi.fn(),
  getNodeFlags: vi.fn(),
  getNodeExtensions: vi.fn(),
}));

vi.mock('$/api/nodes', () => ({
  getNodeConfig: api.getNodeConfig,
  putNodeConfig: api.putNodeConfig,
  deleteNodeConfig: api.deleteNodeConfig,
  getNodeFlags: api.getNodeFlags,
}));

vi.mock('$/api/extensions', () => ({
  getNodeExtensions: api.getNodeExtensions,
}));

// Monaco pulls in a heavy worker — stub it with a textarea.
vi.mock('$/components/forms/CodeEditor', () => ({
  CodeEditor: ({
    value,
    onChange,
    readOnly,
    'aria-label': label,
  }: {
    value: string;
    onChange?: (v: string) => void;
    readOnly?: boolean;
    'aria-label'?: string;
  }) => (
    <textarea
      aria-label={label}
      value={value}
      readOnly={readOnly}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}));

const ENV_CFG = '{"options":{"a":"1"}}';
const APPLIED_CFG = '{"options":{"a":"2"}}';

function makeConfig(overrides: Partial<NodeConfig> = {}): NodeConfig {
  return {
    environment: ENV_CFG,
    override: '',
    applied: ENV_CFG,
    expires_at: null,
    expired: false,
    updated_by: '',
    updated_at: null,
    ...overrides,
  };
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeConfigTab env="prod" uuid="uuid-1" hostname="web-prod-07" />
    </QueryClientProvider>,
  );
}

async function unlock(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Edit override' }));
  await user.click(screen.getByRole('checkbox'));
  await user.click(screen.getByRole('button', { name: 'Unlock editing' }));
}

describe('NodeConfigTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getNodeConfig.mockResolvedValue(makeConfig());
    api.putNodeConfig.mockResolvedValue(makeConfig({ override: '{"x":1}' }));
    api.deleteNodeConfig.mockResolvedValue(makeConfig());
  });

  it('shows the applied configuration read-only by default', async () => {
    api.getNodeConfig.mockResolvedValue(makeConfig({ override: '{"o":1}', applied: APPLIED_CFG }));
    renderTab();
    const editor = await screen.findByLabelText('Applied configuration');
    expect(screen.getByRole('button', { name: 'Applied' })).toHaveAttribute('aria-pressed', 'true');
    expect(editor).toHaveValue(APPLIED_CFG);
    expect(editor).toHaveAttribute('readonly');
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Environment' }));
    expect(screen.getByLabelText('Environment configuration')).toHaveValue(ENV_CFG);
    await user.click(screen.getByRole('button', { name: 'Node override' }));
    expect(screen.getByLabelText('Node override configuration')).toHaveValue('{"o":1}');
    await user.click(screen.getByRole('button', { name: 'Diff' }));
    expect(screen.getByText('Environment → Applied')).toBeInTheDocument();
    // Both sides are canonicalized (pretty-printed, keys sorted) before diffing.
    expect(screen.getByText('"a": "1"')).toBeInTheDocument();
    expect(screen.getByText('"a": "2"')).toBeInTheDocument();
  });

  it('diff view ignores key order and formatting differences', async () => {
    api.getNodeConfig.mockResolvedValue(
      makeConfig({
        environment: '{"options":{"b":1,"a":2},"schedule":{}}',
        applied: '{\n  "schedule": {},\n  "options": {\n    "a": 2,\n    "b": 1\n  }\n}',
      }),
    );
    renderTab();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Diff' }));
    expect(screen.getByText('No changes.')).toBeInTheDocument();
  });

  it('diff view falls back to the raw text when a side is not valid JSON', async () => {
    api.getNodeConfig.mockResolvedValue(makeConfig({ environment: 'not json', applied: '{"a":1}' }));
    renderTab();
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Diff' }));
    expect(screen.getByText('not json')).toBeInTheDocument();
    expect(screen.getByText('{"a":1}')).toBeInTheDocument();
  });

  it('unlock requires the confirmation checkbox', async () => {
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole('button', { name: 'Edit override' }));
    const dialog = screen.getByRole('dialog', { name: 'Override configuration for web-prod-07?' });
    expect(
      within(dialog).getByText(
        "This changes what osquery runs on this host only, on top of the environment's configuration. Settings that keep the host connected to osctrl can't be overridden, but a heavy override can still affect the host. It stays until it is removed or expires. Options you set here that the environment doesn't set stay in effect on the host until osquery restarts, even after the override is removed or expires.",
      ),
    ).toBeInTheDocument();
    const unlockBtn = within(dialog).getByRole('button', { name: 'Unlock editing' });
    expect(unlockBtn).toBeDisabled();
    await user.click(
      within(dialog).getByLabelText(
        "I understand this changes osquery on this host and I know what I'm doing",
      ),
    );
    expect(unlockBtn).toBeEnabled();
    await user.click(unlockBtn);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByText('Changes reach the host on its next configuration fetch.')).toBeInTheDocument();
  });

  it('saving sends the override and expiry', async () => {
    const user = userEvent.setup();
    renderTab();
    await unlock(user);
    expect(screen.getByRole('button', { name: 'Node override' })).toHaveAttribute('aria-pressed', 'true');
    const editor = screen.getByLabelText('Node override configuration');
    expect(editor).not.toHaveAttribute('readonly');
    fireEvent.change(editor, { target: { value: '{"x":1}' } });
    fireEvent.change(screen.getByLabelText('Expires (optional)'), { target: { value: '2030-01-02T03:04' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.putNodeConfig).toHaveBeenCalledTimes(1));
    expect(api.putNodeConfig).toHaveBeenCalledWith('prod', 'uuid-1', {
      override: '{"x":1}',
      expires_at: new Date('2030-01-02T03:04').toISOString(),
    });
    // saved: re-locks
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument());
  });

  it('shows the server error inline and stays unlocked', async () => {
    api.putNodeConfig.mockRejectedValue(new Error('option "enroll_secret" cannot be overridden'));
    const user = userEvent.setup();
    renderTab();
    await unlock(user);
    fireEvent.change(screen.getByLabelText('Node override configuration'), { target: { value: '{"x":1}' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('option "enroll_secret" cannot be overridden');
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByLabelText('Node override configuration')).toHaveValue('{"x":1}');
  });

  it('cancel discards and re-locks', async () => {
    api.getNodeConfig.mockResolvedValue(makeConfig({ override: '{"o":1}' }));
    const user = userEvent.setup();
    renderTab();
    await unlock(user);
    fireEvent.change(screen.getByLabelText('Node override configuration'), { target: { value: 'changed' } });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
    const editor = screen.getByLabelText('Node override configuration');
    expect(editor).toHaveValue('{"o":1}');
    expect(editor).toHaveAttribute('readonly');
    expect(api.putNodeConfig).not.toHaveBeenCalled();
  });

  it('remove asks for confirmation and calls deleteNodeConfig', async () => {
    api.getNodeConfig.mockResolvedValue(makeConfig({ override: '{"o":1}' }));
    const user = userEvent.setup();
    renderTab();
    await user.click(await screen.findByRole('button', { name: 'Remove override' }));
    const dialog = screen.getByRole('dialog', {
      name: 'Remove the configuration override for web-prod-07?',
    });
    expect(
      within(dialog).getByText(
        "The host goes back to the environment's configuration on its next configuration fetch. Options the environment doesn't set keep their overridden value until osquery restarts.",
      ),
    ).toBeInTheDocument();
    expect(api.deleteNodeConfig).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Remove override' }));
    await waitFor(() => expect(api.deleteNodeConfig).toHaveBeenCalledWith('prod', 'uuid-1'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('hides Remove override when there is none', async () => {
    renderTab();
    await screen.findByRole('button', { name: 'Edit override' });
    expect(screen.queryByRole('button', { name: 'Remove override' })).not.toBeInTheDocument();
  });

  it('switches between the Configuration and Flags views', async () => {
    api.getNodeFlags.mockResolvedValue({
      environment: '--verbose=false',
      override: '',
      applied: '--verbose=false',
      expires_at: null,
      expired: false,
      updated_by: '',
      updated_at: null,
      conflicts: [],
      osctrld: null,
    });
    const user = userEvent.setup();
    renderTab();
    expect(await screen.findByLabelText('Applied configuration')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Configuration' })).toHaveAttribute('aria-pressed', 'true');
    expect(api.getNodeFlags).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Flags' }));
    expect(await screen.findByLabelText('Applied flags')).toHaveValue('--verbose=false');
    expect(screen.queryByLabelText('Applied configuration')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Configuration' }));
    expect(await screen.findByLabelText('Applied configuration')).toBeInTheDocument();
  });

  it('has an Extensions view alongside Configuration and Flags', async () => {
    api.getNodeExtensions.mockResolvedValue({ effective: [], assignments: [], status: [], library: null });
    const user = userEvent.setup();
    renderTab();
    await screen.findByLabelText('Applied configuration');
    expect(api.getNodeExtensions).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Extensions' }));
    expect(screen.getByRole('button', { name: 'Extensions' })).toHaveAttribute('aria-pressed', 'true');
    expect(await screen.findByText('No extensions apply to this host.')).toBeInTheDocument();
    expect(api.getNodeExtensions).toHaveBeenCalledWith('prod', 'uuid-1');
  });
});
