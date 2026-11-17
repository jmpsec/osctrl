import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { applyChange, changesQueryKey, decideChange, listChanges, type PendingChange } from '$/api/changes';
import { Button } from '$/components/atoms/Button';
import { EmptyState } from '$/components/data/EmptyState';
import { SkeletonRow } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { TokenDialog } from './SettingsTab';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

export function ChangesTab({ env }: { env: string }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const qc = useQueryClient();
  const changes = useQuery({ queryKey: changesQueryKey(env), queryFn: () => listChanges(env) });
  // A token rotation applied from here shows its token once, like in Settings.
  const [token, setToken] = useState<string | null>(null);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: changesQueryKey(env) });
    void qc.invalidateQueries({ queryKey: ['santa', env] });
  };
  const decide = useMutation({
    mutationFn: ({ c, decision }: { c: PendingChange; decision: 'approve' | 'deny' }) => decideChange(env, c.id, decision),
    onSettled: refresh,
  });
  const apply = useMutation({
    mutationFn: (c: PendingChange) => applyChange(c),
    onSuccess: (res) => {
      const tok = (res as { token?: string } | undefined)?.token;
      if (tok) setToken(tok);
    },
    onSettled: refresh,
  });
  const rows = changes.data ?? [];
  const error = decide.error ?? apply.error;

  return (
    <section className="space-y-3">
      <p className="text-sm text-[color:var(--text-3)]">{t('santa.changes.hint')}</p>
      {error && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(error)}</p>}
      <div className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
        {changes.isLoading ? (
          <table className={TABLE}><tbody>{Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} cells={4} />)}</tbody></table>
        ) : changes.isError ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.loadError')} description={errorText(changes.error)} />
        ) : rows.length === 0 ? (
          <EmptyState icon={<ShieldCheck />} title={t('santa.changes.empty')} />
        ) : (
          <div className="overflow-x-auto">
            <table className={TABLE}>
              <thead>
                <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                  <th scope="col" className={TH}>{t('santa.changes.action')}</th>
                  <th scope="col" className={TH}>{t('santa.changes.requestedBy')}</th>
                  <th scope="col" className={TH}>{t('santa.changes.status')}</th>
                  <th scope="col" className={TH}><span className="sr-only">{t('santa.changes.actions')}</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id} className={ROW}>
                    <td className={`${TD} ${MONO} text-xs [overflow-wrap:anywhere]`}>{c.action}</td>
                    <td className={TD}>
                      {c.requested_by}
                      <div className="text-xs text-[color:var(--text-3)]">{formatDateTime(new Date(c.created_at))}</div>
                    </td>
                    <td className={TD}>
                      {t(`santa.changes.statuses.${c.status}`)}
                      {c.decided_by && <div className="text-xs text-[color:var(--text-3)]">{c.decided_by}</div>}
                    </td>
                    <td className={`${TD} whitespace-nowrap text-right`}>
                      <div className="flex justify-end gap-2">
                        {c.status === 'pending' && !c.mine && (
                          <Button size="sm" disabled={decide.isPending} aria-label={`${t('santa.changes.approve')} ${c.id}`}
                            onClick={() => decide.mutate({ c, decision: 'approve' })}>{t('santa.changes.approve')}</Button>
                        )}
                        {c.status === 'approved' && c.mine && (
                          <Button size="sm" disabled={apply.isPending} aria-label={`${t('santa.changes.apply')} ${c.id}`}
                            onClick={() => apply.mutate(c)}>{t('santa.changes.apply')}</Button>
                        )}
                        {c.status === 'pending' && (
                          <Button size="sm" variant="danger" disabled={decide.isPending}
                            aria-label={`${t(c.mine ? 'santa.changes.withdraw' : 'santa.changes.deny')} ${c.id}`}
                            onClick={() => decide.mutate({ c, decision: 'deny' })}>
                            {t(c.mine ? 'santa.changes.withdraw' : 'santa.changes.deny')}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {token && <TokenDialog token={token} onClose={() => setToken(null)} />}
    </section>
  );
}
