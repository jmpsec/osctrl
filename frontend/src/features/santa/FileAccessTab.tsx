import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { FileLock } from 'lucide-react';
import { listSantaFileAccessEvents, santaQueryKey, SANTA_EVENTS_PAGE_SIZE, type SantaFileAccessFilter } from '$/api/santa';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SkeletonRow } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { FilterBar } from './FilterBar';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

/** Violations of the file access rules deployed to the clients through MDM. */
export function FileAccessTab({ env }: { env: string }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<SantaFileAccessFilter>({});
  const events = useQuery({
    queryKey: santaQueryKey(env, 'file-access', page, filter),
    queryFn: () => listSantaFileAccessEvents(env, page, filter),
    placeholderData: (previous) => previous,
  });
  const rows = events.data?.events ?? [];
  const total = events.data?.total ?? 0;

  return (
    <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
      <FilterBar
        id="santa-file-access-filter"
        fields={[
          { key: 'target', label: t('santa.filters.path') },
          { key: 'process', label: t('santa.filters.process') },
          {
            key: 'decision',
            label: t('santa.decision'),
            options: [
              { value: '', label: t('santa.filters.anyDecision') },
              ...['DENIED', 'DENIED_INVALID_SIGNATURE', 'AUDIT_ONLY'].map((d) => ({ value: d, label: d })),
            ],
          },
          { key: 'machine_id', label: t('santa.filters.machine') },
        ]}
        onApply={(f) => {
          setFilter(f);
          setPage(1);
        }}
      />
      {events.isLoading ? (
        <table className={TABLE}><tbody>{Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={5} />)}</tbody></table>
      ) : events.isError ? (
        <EmptyState icon={<FileLock />} title={t('santa.loadError')} description={errorText(events.error)} />
      ) : rows.length === 0 ? (
        <EmptyState icon={<FileLock />} title={t('santa.fileAccess.none')} description={t('santa.fileAccess.noneHint')} />
      ) : (
        <div className="overflow-x-auto">
          <table className={TABLE}>
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                <th scope="col" className={TH}>{t('santa.time')}</th>
                <th scope="col" className={TH}>{t('santa.fileAccess.rule')}</th>
                <th scope="col" className={TH}>{t('santa.fileAccess.target')}</th>
                <th scope="col" className={TH}>{t('santa.fileAccess.process')}</th>
                <th scope="col" className={TH}>{t('santa.decision')}</th>
              </tr>
            </thead>
            <tbody>
              {/* Every value below is reported by clients: React text only. */}
              {rows.map((e) => {
                const [proc, ...parents] = e.process_chain ?? [];
                return (
                  <tr key={e.id} className={ROW}>
                    <td className={`${TD} whitespace-nowrap`}>{formatDateTime(new Date(e.accessed_at))}</td>
                    <td className={TD}>
                      {e.rule_name}
                      {e.rule_version && <div className="text-xs text-[color:var(--text-3)]">{e.rule_version}</div>}
                    </td>
                    <td className={`${TD} ${MONO} [overflow-wrap:anywhere]`}>{e.target}</td>
                    <td className={TD}>
                      {proc && (
                        <div className={`${MONO} [overflow-wrap:anywhere]`}>
                          {proc.file_path} <span className="text-[color:var(--text-3)]">({proc.pid})</span>
                        </div>
                      )}
                      {parents.length > 0 && (
                        <div className={`${MONO} text-xs text-[color:var(--text-3)] [overflow-wrap:anywhere]`}>
                          {parents.map((p) => p.file_path).join(' ← ')}
                        </div>
                      )}
                    </td>
                    <td className={TD}>{e.decision}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {total > 0 && (
        <Pagination
          page={page}
          pageSize={SANTA_EVENTS_PAGE_SIZE}
          totalItems={total}
          totalPages={Math.max(1, Math.ceil(total / SANTA_EVENTS_PAGE_SIZE))}
          onPageChange={setPage}
        />
      )}
    </section>
  );
}
