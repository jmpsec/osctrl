import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { RefreshCw } from 'lucide-react';
import { getVulnFeeds, requestVulnSync, type VulnSyncState } from '$/api/vulnerabilities';
import { Button } from '$/components/atoms/Button';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';

/** The source has an error newer than its last success. Timestamps are
 * compared as dates: RFC 3339 strings with different fraction lengths do
 * not sort correctly as text. */
function failing(src: VulnSyncState): boolean {
  if (!src.last_error_at) return false;
  if (!src.last_success) return true;
  return Date.parse(src.last_error_at) > Date.parse(src.last_success);
}

/** Feed status and "Sync now". Super admin only: the caller decides. */
export function FeedsCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const feeds = useQuery({
    queryKey: ['vuln-feeds'],
    queryFn: () => getVulnFeeds(),
    staleTime: 30_000,
    // While a requested sync is pending, poll so the button re-enables when
    // the worker picks it up.
    refetchInterval: (query) => (query.state.data?.sync_requested_at ? 15_000 : false),
  });
  const sync = useMutation({
    mutationFn: () => requestVulnSync(),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['vuln-feeds'] }),
  });
  const requested = Boolean(feeds.data?.sync_requested_at);

  return (
    <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
      <div className="flex items-center justify-between gap-3 border-b border-[color:var(--border)] bg-[color:var(--bg-2)] px-4 py-3">
        <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('vulns.feedsTitle')}</h2>
        <Button type="button" variant="ghost" size="sm" disabled={sync.isPending || requested} onClick={() => sync.mutate()}>
          <RefreshCw className={cn('h-3.5 w-3.5', sync.isPending && 'animate-spin')} aria-hidden="true" />
          {t('vulns.syncNow')}
        </Button>
      </div>
      {requested && (
        <p role="status" className="border-b border-[color:var(--border)] px-4 py-2 text-xs text-[color:var(--text-2)]">
          {t('vulns.syncRequested')}
        </p>
      )}
      {sync.isError && (
        <p role="alert" className="border-b border-[color:var(--border)] px-4 py-2 text-xs text-[color:var(--danger)]">
          {sync.error instanceof Error ? sync.error.message : t('vulns.loadError')}
        </p>
      )}
      {feeds.isError ? (
        <p className="px-4 py-3 text-xs text-[color:var(--danger)]">
          {feeds.error instanceof Error ? feeds.error.message : t('vulns.loadError')}
        </p>
      ) : (
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-[color:var(--border)]">
              <th scope="col" className="px-4 py-2 text-start font-medium text-[color:var(--text-2)]">{t('vulns.feedSource')}</th>
              <th scope="col" className="px-4 py-2 text-start font-medium text-[color:var(--text-2)]">{t('vulns.feedLastSuccess')}</th>
              <th scope="col" className="px-4 py-2 text-start font-medium text-[color:var(--text-2)]">{t('vulns.feedLastError')}</th>
            </tr>
          </thead>
          <tbody>
            {(feeds.data?.sources ?? []).map((src) => (
              <tr key={src.source} className="border-b border-[color:var(--border)] last:border-0 align-top">
                <td className="px-4 py-2 font-mono text-[color:var(--text-1)]">{src.source}</td>
                <td className="px-4 py-2 text-[color:var(--text-2)]">
                  {src.last_success ? <span title={src.last_success}>{formatRelative(src.last_success)}</span> : t('vulns.never')}
                </td>
                <td className={cn('px-4 py-2 [overflow-wrap:anywhere]', failing(src) ? 'text-[color:var(--danger)]' : 'text-[color:var(--text-3)]')}>
                  {failing(src) ? src.last_error : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
