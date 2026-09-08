import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Save } from 'lucide-react';
import { AuthError } from '$/api/client';
import { resetEnvironmentInactiveHours, setEnvironmentInactiveHours } from '$/api/environments';
import { getMe } from '$/api/users';
import { useInactiveHours, invalidateNodeStatusQueries } from '$/lib/node-status';
import { buttonClasses } from '$/components/atoms/Button';

export function InactiveHoursSetting({ env, envUuid }: { env: string; envUuid: string }) {
  const qc = useQueryClient();
  const query = useInactiveHours(env);
  const { data: me } = useQuery({ queryKey: ['users-me'], queryFn: getMe, staleTime: 60_000 });
  const canEdit = me?.admin === true || me?.permissions?.[envUuid]?.admin === true;
  const [draft, setDraft] = useState<{ useGlobal: boolean; hours: string } | null>(null);
  const value = draft ?? {
    useGlobal: query.data?.override_hours == null,
    hours: String(query.data?.inactive_hours ?? ''),
  };
  const hours = Number(value.hours);
  const valid = value.useGlobal || (Number.isInteger(hours) && hours >= 1 && hours <= 2562047);
  const dirty = query.data && (value.useGlobal
    ? query.data.override_hours !== null
    : hours !== query.data.override_hours);
  const mutation = useMutation({
    mutationFn: () => value.useGlobal
      ? resetEnvironmentInactiveHours(env)
      : setEnvironmentInactiveHours(env, hours),
    onSuccess: async (data) => {
      qc.setQueryData(['inactive-hours', env], data);
      setDraft(null);
      await invalidateNodeStatusQueries(qc);
    },
    onError: (error) => {
      if (error instanceof AuthError) window.location.href = '/login';
    },
  });
  const error = mutation.error ?? query.error;

  return (
    <section aria-labelledby="inactive-hours-heading" className="border-t border-[color:var(--border)] py-4 space-y-3">
      <h2 id="inactive-hours-heading" className="font-display text-sm font-semibold text-[color:var(--text-1)]">
        Node inactivity
      </h2>
      {query.isPending && <p role="status" className="text-xs text-[color:var(--text-3)]">Loading inactive hours...</p>}
      {query.data && (
        <form className="flex flex-wrap items-center gap-4 text-xs" onSubmit={(event) => {
          event.preventDefault();
          if (canEdit && dirty && valid && !mutation.isPending) mutation.mutate();
        }}>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={value.useGlobal} disabled={!canEdit || mutation.isPending}
              onChange={(event) => { setDraft({ ...value, useGlobal: event.target.checked }); mutation.reset(); }} />
            Use global default
          </label>
          <label className="flex items-center gap-2">
            Inactive hours
            <input type="number" min={1} max={2562047} step={1} required value={value.hours}
              disabled={!canEdit || value.useGlobal || mutation.isPending}
              onChange={(event) => { setDraft({ ...value, hours: event.target.value }); mutation.reset(); }}
              className="w-28 rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] px-2 py-1.5 tabular-nums disabled:opacity-50" />
          </label>
          <span className="text-[color:var(--text-3)]">Effective: {query.data.inactive_hours}h ({query.data.source})</span>
          {canEdit && <button type="submit" aria-label="Save inactive hours"
            disabled={!dirty || !valid || mutation.isPending} className={buttonClasses({ variant: 'primary' })}>
            <Save className="h-3.5 w-3.5" aria-hidden="true" />
            {mutation.isPending ? 'Saving...' : 'Save'}
          </button>}
        </form>
      )}
      {error && <p role="alert" className="text-xs text-[color:var(--danger)]">{error.message}</p>}
      {query.isError && <button type="button" aria-label="Retry inactive hours" disabled={query.isFetching}
        onClick={() => void query.refetch()} className={buttonClasses({ variant: 'ghost' })}>Retry</button>}
    </section>
  );
}
