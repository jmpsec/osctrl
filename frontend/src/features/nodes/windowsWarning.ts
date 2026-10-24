/** Shown wherever a Windows upgrade is offered: MSI upgrades have no automatic rollback. */
export const WINDOWS_UPGRADE_WARNING =
  'If a Windows upgrade fails, the host cannot be recovered automatically. A failure pauses the rollout and the host needs manual repair.';

// Keep in sync with platformsByBucket["windows"] in pkg/nodes/utils.go.
const WINDOWS_PLATFORMS = ['windows', 'win', 'win32', 'win64'];

export const isWindows = (platform?: string) => WINDOWS_PLATFORMS.includes(platform?.toLowerCase() ?? '');
