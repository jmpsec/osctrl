import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { addSensitivePath, deleteSensitivePath, listSensitivePaths } from '$/api/environments';
import { buttonClasses } from '$/components/atoms/Button';
import { envCaps } from '$/lib/access';
import { useMe } from '$/lib/useMe';

/** Carve paths hidden from users below full carve tier. Read-only unless the viewer can manage the environment. */
export function EnvSensitivePathsTab({ env, envUuid }: { env: string; envUuid: string }) {
  const qc = useQueryClient();
  const queryKey = ['sensitive-paths', env];
  const { data: me } = useMe();
  const canManage = envCaps(me, envUuid).manage;
  const { data, isLoading, error } = useQuery({
    queryKey,
    queryFn: () => listSensitivePaths(env),
    staleTime: 10_000,
  });
  const [path, setPath] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = () => {
    setActionError(null);
    return qc.invalidateQueries({ queryKey });
  };
  const add = useMutation({
    mutationFn: (p: string) => addSensitivePath(env, { path: p }),
    onSuccess: () => {
      setPath('');
      return refresh();
    },
    onError: (e: Error) => setActionError(e.message),
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteSensitivePath(env, id),
    onSuccess: refresh,
    onError: (e: Error) => setActionError(e.message),
  });

  if (isLoading) return <p className="text-sm text-[color:var(--text-3)]">Loading sensitive paths…</p>;
  if (error || !data) {
    return (
      <p role="alert" className="text-sm text-[color:var(--danger)]">
        {error instanceof Error ? error.message : 'Failed to load sensitive paths'}
      </p>
    );
  }

  const busy = add.isPending || remove.isPending;

  return (
    <section className="space-y-3 max-w-2xl">
      <p className="text-xs text-[color:var(--text-3)]">
        Users below full carve tier cannot carve these paths, anything under them, or any parent directory, and cannot see
        existing carves of them.
      </p>
      {data.length === 0 ? (
        <p className="text-sm text-[color:var(--text-2)]">No sensitive paths in this environment.</p>
      ) : (
        <ul className="divide-y divide-[color:var(--border)] border border-[color:var(--border)] rounded-md">
          {data.map((p) => (
            <li key={p.id} className="flex items-center gap-3 px-3 py-2 text-sm">
              <span className="font-mono text-[color:var(--text-1)]">{p.path}</span>
              <span className="text-xs text-[color:var(--text-3)]">added by {p.created_by}</span>
              {canManage && (
                <button
                  type="button"
                  aria-label={`Remove ${p.path}`}
                  disabled={busy}
                  onClick={() => remove.mutate(p.id)}
                  className={buttonClasses({ variant: 'danger', size: 'sm', className: 'ml-auto' })}
                >
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {canManage && (
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate(path.trim());
          }}
        >
          <input
            aria-label="Sensitive path"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/etc/shadow"
            className="h-8 w-72 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] px-2 font-mono text-sm text-[color:var(--text-1)]"
          />
          <button
            type="submit"
            disabled={path.trim() === '' || busy}
            className={buttonClasses({ variant: 'primary', size: 'sm' })}
          >
            Add path
          </button>
        </form>
      )}
      {actionError && (
        <p role="alert" className="text-xs text-[color:var(--danger)]">
          {actionError}
        </p>
      )}
    </section>
  );
}
