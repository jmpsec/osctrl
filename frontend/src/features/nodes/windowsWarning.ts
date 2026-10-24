/** Shown wherever a Windows upgrade is offered: MSI upgrades have no automatic rollback. */
export const WINDOWS_UPGRADE_WARNING =
  'If a Windows upgrade fails, the host cannot be recovered automatically. A failure pauses the rollout and the host needs manual repair.';

export const isWindows = (platform?: string) => platform?.toLowerCase() === 'windows';
