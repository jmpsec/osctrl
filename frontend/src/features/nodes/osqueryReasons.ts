import type { NodeOsquery } from '$/api/types';

/** "1 h 20 min", "25 min", "less than a minute". */
export function span(ms: number): string {
  const min = Math.floor(ms / 60_000);
  if (min < 1) return 'less than a minute';
  const h = Math.floor(min / 60);
  const m = min % 60;
  return h === 0 ? `${m} min` : m === 0 ? `${h} h` : `${h} h ${m} min`;
}

/** "the 50% stage" for the host's stage, or '' when the response has no (valid) stage. */
const stageLabel = (d?: NodeOsquery) => {
  const r = d?.rollout;
  const pct = r ? r.stages[r.stage - 1] : undefined;
  return pct === undefined ? '' : `the ${pct}% stage`;
};

const rolloutPending = (d?: NodeOsquery) => {
  const stage = stageLabel(d);
  if (!stage) {
    return 'This host is not in the current rollout stage yet; it joins when the next stage opens (see the environment Osquery tab).';
  }
  if (d?.rollout?.state === 'running' && !d.rollout.eligible_at) {
    // The report is older than the stage opening: do not claim the host is still blocked.
    return `The rollout has reached this host's stage (${d.rollout.stages[d.rollout.stage - 1]}%); it will upgrade at its next sync.`;
  }
  const at = d?.rollout?.eligible_at ? new Date(d.rollout.eligible_at).getTime() : NaN;
  const left = at - Date.now();
  const when = isNaN(left) ? '' : left < 60_000 ? ', which opens shortly' : `, which opens in about ${span(left)}`;
  return `Not in the rollout yet: this host is in ${stage}${when}.`;
};

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
  rollout_pending: rolloutPending,
  rollout_paused: (d) => {
    const stage = stageLabel(d);
    return `The rollout of this version is paused, so this host is not upgrading.${stage ? ` It is in ${stage}.` : ''}`;
  },
};

/** Host-reported: unknown codes render as the plain code. */
export const reasonText = (reason: string, d?: NodeOsquery) => (Object.hasOwn(REASONS, reason) ? REASONS[reason](d) : reason);
