import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NodeOsqueryView } from './NodeOsqueryView';
import type { NodeOsquery } from '$/api/types';

const api = vi.hoisted(() => ({ getNodeOsquery: vi.fn(), pinNodeOsquery: vi.fn(), unpinNodeOsquery: vi.fn() }));
vi.mock('$/api/osqueryVersions', () => api);

function make(o: Partial<NodeOsquery> = {}): NodeOsquery {
  return {
    pin: null,
    target: { version: '5.13.0', source: 'environment' },
    installed_version: '5.12.1',
    upgrade: null,
    available: ['5.12.1', '5.13.0', '5.14.0'],
    platform_unsupported: false,
    ...o,
  };
}

function upgrade(o: Partial<NonNullable<NodeOsquery['upgrade']>> = {}): NodeOsquery['upgrade'] {
  return { result: 'rejected', version: '5.13.0', reason: 'install_failed', request_id: 'r', reported_at: '2026-10-18T10:00:00Z', ...o };
}

function renderView() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NodeOsqueryView env="prod" uuid="uuid-1" hostname="web-prod-07" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getNodeOsquery.mockResolvedValue(make());
  api.pinNodeOsquery.mockResolvedValue(make());
  api.unpinNodeOsquery.mockResolvedValue(make());
});

describe('NodeOsqueryView', () => {
  it('shows installed version and the effective target with its source', async () => {
    renderView();
    expect(await screen.findByText('Installed version')).toBeInTheDocument();
    expect(screen.getByTestId('installed')).toHaveTextContent('5.12.1');
    expect(screen.getByTestId('target')).toHaveTextContent('5.13.0');
    expect(screen.getByTestId('target')).toHaveTextContent('environment');
  });

  it.each([
    ['no_target', 'No target version is set for this environment.'],
    ['ahead_of_target', 'This host already runs the target version or newer.'],
    ['no_digest_for_target', "Add the SHA-256 for osquery 5.13.0 (for this host's platform and architecture) to the library."],
    ['no_digest_for_installed', 'Add the SHA-256 for the installed version 5.12.1 to the library so the host can be rolled back safely.'],
    ['unsupported_platform', 'Upgrades are not supported on this platform yet.'],
    ['previous_unavailable', "The previous version's package could not be downloaded, so the upgrade was not started."],
    ['target_unavailable', "The target version's package could not be downloaded."],
    ['digest_mismatch', 'A downloaded package did not match its SHA-256.'],
    ['version_not_reported', "The new version never reported to osctrl (check that the environment's osquery configuration carries the version decorator); the host was rolled back."],
    ['osqueryd_not_running', 'osquery was not running, so the upgrade was skipped.'],
    ['install_failed', 'The package install failed.'],
    ['config_changed', "The install changed osquery's configuration files; the host was rolled back."],
    ['rolled_back', 'The host was rolled back to its previous version.'],
  ])('words the reason %s', async (reason, text) => {
    api.getNodeOsquery.mockResolvedValue(make({ upgrade: upgrade({ reason }) }));
    renderView();
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it('names the target version from the node, not the report, for a missing target digest', async () => {
    api.getNodeOsquery.mockResolvedValue(
      make({ target: { version: '5.14.0', source: 'pin' }, upgrade: upgrade({ result: 'skipped', version: '5.13.0', reason: 'no_digest_for_target' }) }),
    );
    renderView();
    expect(
      await screen.findByText("Add the SHA-256 for osquery 5.14.0 (for this host's platform and architecture) to the library."),
    ).toBeInTheDocument();
  });

  it('explains how to retry a rejected version under the pin control', async () => {
    renderView();
    expect(
      await screen.findByText('Pinning the same version with the same expiry retries a version this host rejected.'),
    ).toBeInTheDocument();
  });

  it('says upgrades are unsupported on a Windows host without a report', async () => {
    api.getNodeOsquery.mockResolvedValue(make({ platform_unsupported: true }));
    renderView();
    expect(await screen.findByText('Upgrades are not supported on this platform yet.')).toBeInTheDocument();
  });

  it('shows the upgrade report, not the platform note, when one exists', async () => {
    api.getNodeOsquery.mockResolvedValue(make({ platform_unsupported: true, upgrade: upgrade({ reason: 'install_failed' }) }));
    renderView();
    expect(await screen.findByText('The package install failed.')).toBeInTheDocument();
    expect(screen.queryByText('Upgrades are not supported on this platform yet.')).not.toBeInTheDocument();
  });

  it('shows no platform note on a supported host', async () => {
    renderView();
    await screen.findByText('Installed version');
    expect(screen.queryByText('Upgrades are not supported on this platform yet.')).not.toBeInTheDocument();
  });

  it('shows a rejected report with its version and result badge', async () => {
    api.getNodeOsquery.mockResolvedValue(make({ upgrade: upgrade({ reason: 'digest_mismatch' }) }));
    renderView();
    const box = await screen.findByTestId('upgrade');
    expect(box).toHaveTextContent('rejected');
    expect(box).toHaveTextContent('5.13.0');
    expect(box).toHaveTextContent('A downloaded package did not match its SHA-256.');
  });

  it('renders host-reported strings as text, never HTML', async () => {
    api.getNodeOsquery.mockResolvedValue(
      make({ installed_version: '<b>1.0</b>', upgrade: upgrade({ reason: '<img src=x onerror=alert(1)>', version: '<i>v</i>' }) }),
    );
    const { container } = renderView();
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(container.querySelector('img, b, i')).toBeNull();
  });

  it('pins only after the confirmation, which names version and host', async () => {
    const user = userEvent.setup();
    renderView();
    const pick = await screen.findByLabelText('Version to pin');
    expect(pick).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Edit pin' }));
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByRole('button', { name: 'Unlock editing' }));
    await user.selectOptions(screen.getByLabelText('Version to pin'), '5.14.0');
    await user.click(screen.getByRole('button', { name: 'Pin version' }));
    expect(api.pinNodeOsquery).not.toHaveBeenCalled();
    expect(screen.getByText('Pin osquery 5.14.0 on web-prod-07?')).toBeInTheDocument();
    expect(screen.getByText(/rolls back automatically/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Pin osquery 5.14.0' }));
    await waitFor(() => expect(api.pinNodeOsquery).toHaveBeenCalledWith('prod', 'uuid-1', '5.14.0', undefined));
  });

  it('removes a pin', async () => {
    api.getNodeOsquery.mockResolvedValue(
      make({
        pin: { version: '5.14.0', request_id: 'r', expires_at: null, updated_by: 'bob', updated_at: '2026-10-01T10:00:00Z' },
        target: { version: '5.14.0', source: 'pin' },
      }),
    );
    const user = userEvent.setup();
    renderView();
    expect(await screen.findByTestId('target')).toHaveTextContent('pin');
    await user.click(screen.getByRole('button', { name: 'Remove pin' }));
    await waitFor(() => expect(api.unpinNodeOsquery).toHaveBeenCalledWith('prod', 'uuid-1'));
  });

  it.each([
    ['rollout_pending', /not in the current rollout stage yet/],
    ['rollout_paused', /rollout of this version is paused, so this host is not upgrading/],
  ])('renders the %s reason in words', async (reason, text) => {
    api.getNodeOsquery.mockResolvedValue(make({ upgrade: upgrade({ result: 'skipped', reason }) }));
    renderView();
    expect(await screen.findByTestId('upgrade')).toHaveTextContent(text);
  });
});
