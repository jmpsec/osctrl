import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { assignEnvExtension, getEnvExtensions, unassignEnvExtension } from '$/api/extensions';
import type { EnvExtensions } from '$/api/types';
import { buttonClasses } from '$/components/atoms/Button';

/** Ordinary (non command-execution) extensions assigned to every host in an environment. */
export function EnvExtensionsTab({ env }: { env: string }) {
  const qc = useQueryClient();
  const queryKey = ['env-extensions', env];
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => getEnvExtensions(env),
    staleTime: 10_000,
  });
  const [pick, setPick] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const done = (resp: EnvExtensions) => {
    qc.setQueryData(queryKey, resp);
    setPick('');
    setActionError(null);
  };
  const assign = useMutation({
    mutationFn: (id: number) => assignEnvExtension(env, id),
    onSuccess: done,
    onError: (e: Error) => setActionError(e.message),
  });
  const unassign = useMutation({
    mutationFn: (id: number) => unassignEnvExtension(env, id),
    onSuccess: done,
    onError: (e: Error) => setActionError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading extensions…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load extensions'}
      </p>
    );
  }

  const assigned = data.assigned ?? [];
  const available = data.available ?? [];
  const busy = assign.isPending || unassign.isPending;

  return (
    <section className="space-y-3 max-w-2xl">
      <p className="text-xs text-[color:var(--text-3)]">
        Hosts get these extensions from osctrld on its next sync (up to an hour).
      </p>
      {assigned.length === 0 ? (
        <p className="text-sm text-[color:var(--text-2)]">No extensions assigned to this environment.</p>
      ) : (
        <ul className="divide-y divide-[color:var(--border)] border border-[color:var(--border)] rounded-md">
          {assigned.map((x) => (
            <li key={x.id} className="flex items-center gap-3 px-3 py-2 text-sm">
              <span className="font-medium text-[color:var(--text-1)]">{x.name}</span>
              <span className="text-xs text-[color:var(--text-3)]">{x.version}</span>
              <span className="text-xs text-[color:var(--text-3)]">{x.platforms.join(', ')}</span>
              <button
                type="button"
                aria-label={`Remove ${x.name}`}
                disabled={busy}
                onClick={() => unassign.mutate(x.id)}
                className={buttonClasses({ variant: 'danger', size: 'sm', className: 'ml-auto' })}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {actionError && (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {actionError}
        </p>
      )}
      {available.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Extension to add"
            value={pick}
            onChange={(e) => setPick(e.target.value)}
            className="h-8 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
          >
            <option value="">Select an extension…</option>
            {available.map((x) => (
              <option key={x.id} value={x.id}>{`${x.name} ${x.version}`}</option>
            ))}
          </select>
          <button
            type="button"
            disabled={pick === '' || busy}
            onClick={() => assign.mutate(Number(pick))}
            className={buttonClasses({ variant: 'primary', size: 'sm' })}
          >
            Add extension
          </button>
        </div>
      )}
    </section>
  );
}
