import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getCarve } from '$/api/carves';
import { carveSantaEvent, santaQueryKey } from '$/api/santa';
import { Button } from '$/components/atoms/Button';
import { CarveStatusBadge } from '$/features/carves/CarveDetailPage';
import { errorText } from './table';

/**
 * Retrieves an event's file from its machine with an osquery carve, then shows
 * that carve's status with a link to it. Carve access is checked by the API.
 */
export function CarveRetrieve({ env, eventId, carve }: { env: string; eventId: number; carve: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [started, setStarted] = useState('');
  const name = started || carve;
  const start = useMutation({
    mutationFn: () => carveSantaEvent(env, eventId),
    onSuccess: (r) => {
      setStarted(r.query_name);
      void qc.invalidateQueries({ queryKey: santaQueryKey(env, 'events') });
      void qc.invalidateQueries({ queryKey: santaQueryKey(env, 'binaries') });
      void qc.invalidateQueries({ queryKey: santaQueryKey(env, 'requests') });
    },
  });
  const error = start.isError && <span role="alert" className="text-xs text-[color:var(--danger)]">{errorText(start.error)}</span>;
  // A caller without carve read access gets an error here: the link stays.
  const status = useQuery({ queryKey: ['carve', env, name], queryFn: () => getCarve(env, name), enabled: !!name, retry: false });

  if (name) {
    return (
      <span className="inline-flex items-center gap-1.5">
        {status.data?.query.carve_status && <CarveStatusBadge status={status.data.query.carve_status} />}
        <Link to="/_app/env/$env/carves/$name" params={{ env, name }} className="text-xs text-[color:var(--accent)] underline">
          {t('santa.carve.view')}
        </Link>
        <Button size="sm" variant="ghost" disabled={start.isPending} onClick={() => start.mutate()}>
          {t('santa.carve.again')}
        </Button>
        {error}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <Button size="sm" variant="ghost" disabled={start.isPending} onClick={() => start.mutate()}>
        {t('santa.carve.retrieve')}
      </Button>
      {error}
    </span>
  );
}
