import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { clearEnvOsquery, getEnvOsquery, setEnvOsquery } from '$/api/osqueryVersions';
import type { EnvOsquery } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { RolloutPanel } from './RolloutPanel';
import { plainBtn, warnBtn } from '$/features/nodes/overrideShared';

const fmt = (iso: string) => {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
};

/** The osquery version osctrld rolls every host of the environment to. */
export function EnvOsqueryTab({ env }: { env: string }) {
  const qc = useQueryClient();
  const queryKey = ['env-osquery', env];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getEnvOsquery(env),
    staleTime: 10_000,
  });
  const [pick, setPick] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const done = (resp: EnvOsquery) => {
    qc.setQueryData(queryKey, resp);
    setPick('');
    setActionError(null);
  };
  const set = useMutation({
    mutationFn: (version: string) => setEnvOsquery(env, version),
    onSuccess: (resp) => {
      setConfirmOpen(false);
      done(resp);
    },
    onError: (e: Error) => {
      setConfirmOpen(false);
      setActionError(e.message);
    },
  });
  const clear = useMutation({
    mutationFn: () => clearEnvOsquery(env),
    onSuccess: done,
    onError: (e: Error) => setActionError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading osquery versions…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load osquery versions'}
      </p>
    );
  }

  const { target } = data;
  const counts = data.counts ?? [];
  const available = data.available ?? [];
  const busy = set.isPending || clear.isPending;
  const hosts = counts.reduce((n, c) => n + c.count, 0);
  const hostsText = hosts === 0 ? 'all hosts in this environment' : `${hosts} ${hosts === 1 ? 'host' : 'hosts'} in this environment`;

  return (
    <section className="space-y-4 max-w-2xl">
      <p className="text-xs text-[color:var(--text-3)]">
        osctrld upgrades each host to the target on its next sync (up to an hour), verifies it, and rolls back
        automatically if osquery does not come up and report the new version. Hosts already on that version or newer are left alone.
      </p>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        {target ? (
          <>
            <span className="text-[color:var(--text-1)]">
              Target version: <strong>{target.version}</strong>
            </span>
            <span className="text-xs text-[color:var(--text-3)]">{`set by ${target.updated_by} on ${fmt(target.updated_at)}`}</span>
            <button
              type="button"
              disabled={busy}
              onClick={() => clear.mutate()}
              className={buttonClasses({ variant: 'danger', size: 'sm', className: 'ml-auto' })}
            >
              Clear target
            </button>
          </>
        ) : (
          <span className="text-[color:var(--text-2)]">No target version is set.</span>
        )}
      </div>
      {data.rollout && <RolloutPanel env={env} rollout={data.rollout} />}
      {actionError && (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {actionError}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <select
          aria-label="Target version to set"
          value={pick}
          onChange={(e) => setPick(e.target.value)}
          className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
        >
          <option value="">Select a version…</option>
          {available.map((v) => (
            <option key={v} value={v}>{v}</option>
          ))}
        </select>
        <button
          type="button"
          disabled={pick === '' || busy}
          onClick={() => setConfirmOpen(true)}
          className={buttonClasses({ variant: 'primary', size: 'sm' })}
        >
          Set target
        </button>
        {available.length === 0 && (
          <span className="text-xs text-[color:var(--text-3)]">No versions in the library yet; a super admin adds them.</span>
        )}
      </div>
      {confirmOpen && (
        <ModalShell
          title={`Set the osquery target to ${pick}?`}
          titleId="env-osquery-target-title"
          onClose={() => setConfirmOpen(false)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              {`This rolls ${hostsText} out to osquery ${pick}. The rollout starts at the first stage (1%) and widens in steps. osctrld upgrades each host on its next sync (up to an hour), verifies it, and rolls back automatically on failure.`}
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={() => setConfirmOpen(false)} disabled={set.isPending} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={() => set.mutate(pick)} disabled={set.isPending} className={warnBtn}>
                {`Set target ${pick}`}
              </button>
            </div>
          </div>
        </ModalShell>
      )}
      {counts.length > 0 && (
        <table className="w-full text-sm border border-[color:var(--border)] rounded-md">
          <thead>
            <tr className="text-left text-xs text-[color:var(--text-3)]">
              <th className="px-3 py-1 font-medium">Version</th>
              <th className="px-3 py-1 font-medium">Hosts</th>
            </tr>
          </thead>
          <tbody>
            {counts.map((c) => (
              <tr key={c.version} className="border-t border-[color:var(--border)]">
                <td className="px-3 py-1">{c.version}</td>
                <td className="px-3 py-1">{c.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
