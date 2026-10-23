import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getNodeOsquery, pinNodeOsquery, unpinNodeOsquery } from '$/api/osqueryVersions';
import type { NodeOsquery } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { plainBtn, warnBtn } from './overrideShared';

const fmt = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
};

const REASONS: Record<string, (installed: string) => string> = {
  no_target: () => 'No target version is set for this environment.',
  ahead_of_target: () => 'This host already runs the target version or newer.',
  no_digest_for_target: () => "Add the SHA-256 for the target version (for this host's platform) to the library.",
  no_digest_for_installed: (v) =>
    `Add the SHA-256 for the installed version ${v} to the library so the host can be rolled back safely.`,
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
};

/** Host-reported: unknown codes render as the plain code. */
const reasonText = (reason: string, installed: string) =>
  Object.hasOwn(REASONS, reason) ? REASONS[reason](installed) : reason;

/** Per-node osquery version: effective target, last upgrade report, and a pin (confirm-to-unlock). */
export function NodeOsqueryView({ env, uuid, hostname }: { env: string; uuid: string; hostname: string }) {
  const qc = useQueryClient();
  const queryKey = ['node-osquery', env, uuid];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getNodeOsquery(env, uuid),
    staleTime: 10_000,
  });

  const [unlockOpen, setUnlockOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [editing, setEditing] = useState(false);
  const [pick, setPick] = useState('');
  const [expiry, setExpiry] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const done = (resp: NodeOsquery) => qc.setQueryData(queryKey, resp);

  const pin = useMutation({
    mutationFn: () => pinNodeOsquery(env, uuid, pick, expiry ? new Date(expiry).toISOString() : undefined),
    onSuccess: (resp) => {
      done(resp);
      setConfirmOpen(false);
      setEditing(false);
      setPick('');
      setExpiry('');
      setActionError(null);
    },
    onError: (e: Error) => {
      setConfirmOpen(false);
      setActionError(e.message);
    },
  });
  const unpin = useMutation({
    mutationFn: () => unpinNodeOsquery(env, uuid),
    onSuccess: (resp) => {
      done(resp);
      setActionError(null);
    },
    onError: (e: Error) => setActionError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading osquery version…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load osquery version'}
      </p>
    );
  }

  const available = data.available ?? [];
  const up = data.upgrade;

  function closeUnlock() {
    setUnlockOpen(false);
    setAcknowledged(false);
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <dl className="grid grid-cols-[10rem_1fr] gap-y-1 text-sm">
        <dt className="text-[color:var(--text-3)]">Installed version</dt>
        <dd data-testid="installed" className="text-[color:var(--text-1)]">{data.installed_version || '—'}</dd>
        <dt className="text-[color:var(--text-3)]">Target version</dt>
        <dd data-testid="target" className="text-[color:var(--text-1)]">
          {data.target ? `${data.target.version} (from ${data.target.source})` : 'None'}
        </dd>
        {data.pin && (
          <>
            <dt className="text-[color:var(--text-3)]">Pin</dt>
            <dd className="text-[color:var(--text-1)]">
              {`${data.pin.version}, set by ${data.pin.updated_by} on ${fmt(data.pin.updated_at)}`}
              {data.pin.expires_at ? `, expires ${fmt(data.pin.expires_at)}` : ''}
            </dd>
          </>
        )}
      </dl>

      {up && (
        <div data-testid="upgrade" className="space-y-1 border border-[color:var(--border)] rounded-md px-3 py-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={
                up.result === 'ok'
                  ? 'text-xs font-medium text-[color:var(--success)]'
                  : up.result === 'rejected'
                    ? 'text-xs font-medium text-[color:var(--danger)]'
                    : 'text-xs font-medium text-[color:var(--warning)]'
              }
            >
              {up.result}
            </span>
            <span className="text-[color:var(--text-1)]">{up.version}</span>
            <span className="ml-auto text-xs text-[color:var(--text-3)]">{`reported ${fmt(up.reported_at)}`}</span>
          </div>
          {up.reason && <p className="text-xs text-[color:var(--text-2)]">{reasonText(up.reason, data.installed_version)}</p>}
        </div>
      )}
      {!up && data.platform_unsupported && (
        <p className="text-sm text-[color:var(--text-2)]">{REASONS.unsupported_platform('')}</p>
      )}

      <p className="text-xs text-[color:var(--text-3)]">
        A pin overrides the environment&apos;s target for this host only. osctrld applies it on its next sync (up to an hour).
      </p>

      {actionError && (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {actionError}
        </p>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs text-[color:var(--text-2)]">
          Version to pin
          <select
            value={pick}
            disabled={!editing}
            onChange={(e) => setPick(e.target.value)}
            className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)] disabled:opacity-40"
          >
            <option value="">Select a version…</option>
            {available.map((v) => (
              <option key={v} value={v}>{v}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-[color:var(--text-2)]">
          Expires (optional)
          <input
            type="datetime-local"
            value={expiry}
            disabled={!editing}
            onChange={(e) => setExpiry(e.target.value)}
            className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)] disabled:opacity-40"
          />
        </label>
        {editing ? (
          <>
            <button
              type="button"
              className={buttonClasses({ variant: 'primary', size: 'md' })}
              disabled={pick === '' || pin.isPending}
              onClick={() => setConfirmOpen(true)}
            >
              Pin version
            </button>
            <button type="button" className={buttonClasses({ variant: 'ghost', size: 'md' })} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" className={buttonClasses({ variant: 'ghost', size: 'md' })} onClick={() => setUnlockOpen(true)}>
            Edit pin
          </button>
        )}
        {data.pin && !editing && (
          <button
            type="button"
            className={buttonClasses({ variant: 'danger', size: 'md' })}
            disabled={unpin.isPending}
            onClick={() => unpin.mutate()}
          >
            Remove pin
          </button>
        )}
      </div>

      {unlockOpen && (
        <ModalShell
          title={`Pin an osquery version on ${hostname}?`}
          titleId="node-osquery-unlock-title"
          onClose={closeUnlock}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              A pin makes this host follow its own osquery version instead of the environment&apos;s target. It stays until it is
              removed or expires.
            </p>
            <label className="flex items-start gap-2 text-sm text-[color:var(--text-1)]">
              <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} className="mt-0.5" />
              I understand this changes osquery on this host and I know what I&apos;m doing
            </label>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={closeUnlock} className={plainBtn}>
                Cancel
              </button>
              <button
                type="button"
                disabled={!acknowledged}
                className={warnBtn}
                onClick={() => {
                  closeUnlock();
                  setEditing(true);
                }}
              >
                Unlock editing
              </button>
            </div>
          </div>
        </ModalShell>
      )}

      {confirmOpen && (
        <ModalShell
          title={`Pin osquery ${pick} on ${hostname}?`}
          titleId="node-osquery-pin-title"
          onClose={() => setConfirmOpen(false)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              osctrld upgrades this host to that version on its next sync (up to an hour), verifies it, and rolls back automatically
              if osquery does not come up and report the new version.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={() => setConfirmOpen(false)} disabled={pin.isPending} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={() => pin.mutate()} disabled={pin.isPending} className={warnBtn}>
                {`Pin osquery ${pick}`}
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}
