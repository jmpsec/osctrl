import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { abortEnvRollout, resumeEnvRollout } from '$/api/osqueryVersions';
import type { EnvOsquery, EnvOsqueryRollout } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { reasonText, span } from '$/features/nodes/osqueryReasons';
import { plainBtn, warnBtn } from '$/features/nodes/overrideShared';

const ago = (iso: string) => {
  const t = new Date(iso).getTime();
  return isNaN(t) ? iso : `${span(Date.now() - t)} ago`;
};

type Action = 'resume' | 'abort';

/** Staged rollout of the environment target: progress, pause/resume and abort. */
export function RolloutPanel({ env, rollout: r }: { env: string; rollout: EnvOsqueryRollout }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: (a: Action) => (a === 'resume' ? resumeEnvRollout(env) : abortEnvRollout(env)),
    onSuccess: (resp: EnvOsquery) => {
      qc.setQueryData(['env-osquery', env], resp);
      setError(null);
      setConfirm(null);
    },
    onError: (e: Error) => {
      setError(e.message);
      setConfirm(null);
      void qc.invalidateQueries({ queryKey: ['env-osquery', env] });
    },
  });

  if (r.state === 'completed') {
    return <p className="text-sm text-[color:var(--text-2)]">{`Rollout to ${r.version} completed.`}</p>;
  }
  if (r.state === 'aborted') {
    return <p className="text-sm text-[color:var(--text-2)]">{`Rollout to ${r.version} was aborted.`}</p>;
  }

  const isPaused = r.state === 'paused';
  const stages = r.stages ?? [];
  const stagePct = stages[r.stage - 1] ?? r.stage;
  // Fall back to the host that paused the rollout when the list is empty.
  const hosts = r.rolled_back_hosts?.length ? r.rolled_back_hosts : r.paused ? [r.paused] : [];
  const rolledBack = Math.max(r.counts.rolled_back, hosts.length, 1);
  const next = stages[r.stage]; // stage is 1-based, so this is the following stage
  const nextAt = r.next_stage_at ? new Date(r.next_stage_at).getTime() : NaN;
  const counts = [
    [r.counts.eligible, 'eligible now'],
    [r.counts.upgraded, 'upgraded'],
    [r.counts.waiting, 'waiting to sync'],
    [r.counts.rolled_back, 'rolled back'],
  ] as const;

  return (
    <div className="space-y-3 border border-[color:var(--border)] rounded-md px-3 py-3">
      {isPaused && (
        <p role="status" className="text-sm text-[color:var(--warning)]">
          <strong>{`Paused at ${stagePct}%.`}</strong>{' '}
          {`${rolledBack} ${rolledBack === 1 ? 'host' : 'hosts'} rolled back, so the rollout stopped widening.`}
        </p>
      )}
      <p className="text-sm text-[color:var(--text-1)]">{`Rolling out osquery ${r.version}`}</p>
      <ol className="grid grid-flow-col auto-cols-fr gap-1 text-xs">
        {stages.map((pct, i) => {
          const n = i + 1;
          const state = n < r.stage ? 'done' : n === r.stage ? (isPaused ? 'paused' : 'now') : '';
          return (
            <li
              key={n}
              className={`rounded px-2 py-1 border border-[color:var(--border)] ${
                n < r.stage ? 'text-[color:var(--success)]' : n === r.stage ? 'font-medium text-[color:var(--text-1)]' : 'text-[color:var(--text-3)]'
              }`}
            >
              {state ? `${pct}% · ${state}` : `${pct}%`}
            </li>
          );
        })}
      </ol>
      <dl className="grid grid-cols-4 gap-2 text-sm">
        {counts.map(([n, label]) => (
          <div key={label}>
            <dt className="text-xs text-[color:var(--text-3)]">{label}</dt>
            <dd className="text-lg text-[color:var(--text-1)]">{n}</dd>
          </div>
        ))}
      </dl>
      {!isPaused && next !== undefined && !isNaN(nextAt) && (
        <p className="text-xs text-[color:var(--text-3)]">
          {nextAt <= Date.now() || nextAt - Date.now() < 60_000
            ? `Widens to ${next}% shortly if nothing rolls back.`
            : `Widens to ${next}% in about ${span(nextAt - Date.now())} if nothing rolls back.`}
        </p>
      )}
      {isPaused && hosts.length > 0 && (
        <table className="w-full text-sm">
          <caption className="text-left text-xs font-medium text-[color:var(--text-2)] pb-1">Rolled back</caption>
          <thead>
            <tr className="text-left text-xs text-[color:var(--text-3)]">
              <th className="py-1 font-medium">Host</th>
              <th className="py-1 font-medium">Reason</th>
              <th className="py-1 font-medium">When</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => (
              <tr key={`${h.host}-${i}`} className="border-t border-[color:var(--border)]">
                <td className="py-1 pr-2 break-all">{h.host}</td>
                <td className="py-1 pr-2">{reasonText(h.reason)}</td>
                <td className="py-1">{ago(h.at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {error && (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        {isPaused && (
          <button type="button" onClick={() => setConfirm('resume')} className={buttonClasses({ variant: 'primary', size: 'sm' })}>
            Resume rollout
          </button>
        )}
        <button type="button" onClick={() => setConfirm('abort')} className={buttonClasses({ variant: 'danger', size: 'sm' })}>
          Abort rollout
        </button>
      </div>
      {confirm && (
        <ModalShell
          title={confirm === 'resume' ? `Resume the rollout of ${r.version}?` : `Abort the rollout of ${r.version}?`}
          titleId="env-osquery-rollout-title"
          onClose={() => setConfirm(null)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              {confirm === 'resume'
                ? `The rollout continues at the ${stagePct}% stage and its wait starts over.`
                : `Hosts already upgraded stay as they are. The remaining hosts never move to ${r.version}.`}
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button type="button" onClick={() => setConfirm(null)} disabled={run.isPending} className={plainBtn}>
                Cancel
              </button>
              <button type="button" onClick={() => run.mutate(confirm)} disabled={run.isPending} className={warnBtn}>
                {confirm === 'resume' ? 'Resume rollout' : 'Abort rollout'}
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}
