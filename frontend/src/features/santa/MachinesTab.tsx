import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { listSantaMachines, santaQueryKey } from '$/api/santa';
import { EmptyState } from '$/components/data/EmptyState';
import { SkeletonRow } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

export function MachinesTab({ env }: { env: string }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const machines = useQuery({ queryKey: santaQueryKey(env, 'machines'), queryFn: () => listSantaMachines(env) });
  const rows = machines.data ?? [];

  return (
    <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
      {machines.isLoading ? (
        <table className={TABLE}><tbody>{Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={5} />)}</tbody></table>
      ) : machines.isError ? (
        <EmptyState icon={<ShieldCheck />} title={t('santa.loadError')} description={errorText(machines.error)} />
      ) : rows.length === 0 ? (
        <EmptyState icon={<ShieldCheck />} title={t('santa.noMachines')} />
      ) : (
        <div className="overflow-x-auto">
          <table className={TABLE}>
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                <th scope="col" className={TH}>{t('santa.hostname')}</th>
                <th scope="col" className={TH}>{t('santa.mode')}</th>
                <th scope="col" className={TH}>{t('santa.ruleCount')}</th>
                <th scope="col" className={TH}>{t('santa.santaVersion')}</th>
                <th scope="col" className={TH}>{t('santa.lastSync')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => (
                <tr key={m.machine_id} className={ROW}>
                  <td className={TD}>
                    <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{m.hostname}</div>
                    <div className={`${MONO} text-xs text-[color:var(--text-3)]`}>{m.serial_number || m.machine_id}</div>
                  </td>
                  <td className={TD}>
                    {m.assigned_mode || m.client_mode}
                    {(m.mode_source === 'tag' || m.mode_source === 'node') && (
                      <div className="text-xs text-[color:var(--text-3)]">{t(`santa.modeFrom.${m.mode_source}`)}</div>
                    )}
                  </td>
                  <td className={TD}>{m.rule_count}</td>
                  <td className={TD}>{m.santa_version}</td>
                  <td className={`${TD} whitespace-nowrap`}>
                    {m.last_sync_at ? formatDateTime(new Date(m.last_sync_at)) : t('santa.never')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
