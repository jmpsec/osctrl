import type { NodeOsquery } from '$/api/types';

export const REASONS: Record<string, (d?: NodeOsquery) => string> = {
  no_target: () => 'No target version is set for this environment.',
  ahead_of_target: () => 'This host already runs the target version or newer.',
  no_digest_for_target: (d) =>
    `Add the SHA-256 for ${d?.target ? `osquery ${d.target.version}` : 'the target version'} (for this host's platform and architecture) to the library.`,
  no_digest_for_installed: (d) =>
    `Add the SHA-256 for ${d?.installed_version ? `the installed version ${d.installed_version}` : 'the previous version'} to the library so the host can be rolled back safely.`,
  unsupported_platform: () => 'Upgrades are not supported on this platform yet.',
  previous_unavailable: () => "The previous version's package could not be downloaded, so the upgrade was not started.",
  target_unavailable: () => "The target version's package could not be downloaded.",
  digest_mismatch: () => 'A downloaded package did not match its SHA-256.',
  version_not_reported: () =>
    "The new version never reported to osctrl (check that the environment's osquery configuration carries the version decorator); the host was rolled back.",
  osqueryd_not_running: () => 'osquery was not running, so the upgrade was skipped.',
  install_failed: () => 'The package install failed.',
  config_changed: () => "The install changed osquery's configuration files; the host was rolled back.",
  rolled_back: () => 'The host was rolled back to its previous version.',
  rollout_pending: () =>
    'This host is not in the current rollout stage yet; it joins when the next stage opens (see the environment Osquery tab).',
  rollout_paused: () => 'The rollout of this version is paused, so this host is not upgrading.',
};

/** Host-reported: unknown codes render as the plain code. */
export const reasonText = (reason: string, d?: NodeOsquery) => (Object.hasOwn(REASONS, reason) ? REASONS[reason](d) : reason);
