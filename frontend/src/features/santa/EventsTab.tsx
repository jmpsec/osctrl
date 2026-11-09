import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { listSantaEvents, santaQueryKey, SANTA_EVENTS_PAGE_SIZE, type SantaEvent, type SantaRuleInput } from '$/api/santa';
import { Button } from '$/components/atoms/Button';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { SkeletonRow } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { EMPTY_RULE } from './RulesTab';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

/** An event's binary hash, turned into a ready-to-review environment-wide rule. */
function ruleFor(e: SantaEvent, policy: SantaRuleInput['policy']): SantaRuleInput {
  return { ...EMPTY_RULE, identifier: e.file_sha256, rule_type: 'BINARY', policy, scope: 'env' };
}

export function EventsTab({ env, onRule }: { env: string; onRule: (rule: SantaRuleInput) => void }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const [page, setPage] = useState(1);
  const events = useQuery({
    queryKey: santaQueryKey(env, 'events', page),
    queryFn: () => listSantaEvents(env, page),
    placeholderData: (previous) => previous,
  });
  const rows = events.data?.events ?? [];
  const total = events.data?.total ?? 0;

  return (
    <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
      {events.isLoading ? (
        <table className={TABLE}><tbody>{Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={5} />)}</tbody></table>
      ) : events.isError ? (
        <EmptyState icon={<ShieldCheck />} title={t('santa.loadError')} description={errorText(events.error)} />
      ) : rows.length === 0 ? (
        <EmptyState icon={<ShieldCheck />} title={t('santa.noEvents')} />
      ) : (
        <div className="overflow-x-auto">
          <table className={TABLE}>
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                <th scope="col" className={TH}>{t('santa.time')}</th>
                <th scope="col" className={TH}>{t('santa.file')}</th>
                <th scope="col" className={TH}>{t('santa.user')}</th>
                <th scope="col" className={TH}>{t('santa.decision')}</th>
                <th scope="col" className={TH}><span className="sr-only">{t('santa.actions')}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className={ROW}>
                  <td className={`${TD} whitespace-nowrap`}>{formatDateTime(new Date(e.executed_at))}</td>
                  {/* File names, paths and hashes are reported by clients: React text only. */}
                  <td className={TD}>
                    <div className="text-[color:var(--text-1)] [overflow-wrap:anywhere]">{e.file_name || e.file_path}</div>
                    <div className={`${MONO} text-xs text-[color:var(--text-3)]`}>{e.file_sha256}</div>
                  </td>
                  <td className={TD}>{e.executing_user}</td>
                  <td className={TD}>{e.decision}</td>
                  <td className={`${TD} whitespace-nowrap text-end`}>
                    <div className="flex justify-end gap-1.5">
                      <Button size="sm" disabled={!e.file_sha256} onClick={() => onRule(ruleFor(e, 'ALLOWLIST'))}>
                        {t('santa.allow')}
                      </Button>
                      <Button size="sm" variant="danger" disabled={!e.file_sha256} onClick={() => onRule(ruleFor(e, 'BLOCKLIST'))}>
                        {t('santa.block')}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
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
