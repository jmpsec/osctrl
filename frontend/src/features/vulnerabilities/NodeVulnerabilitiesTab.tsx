import { useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ShieldAlert } from 'lucide-react';
import { getNodeVulns } from '$/api/vulnerabilities';
import { EmptyState } from '$/components/data/EmptyState';
import { Skeleton } from '$/components/data/Skeleton';
import { useLocale } from '$/i18n/useLocale';
import { hasTime, NODE_FINDINGS_LIMIT } from './vulnFormat';
import { FindingsTable } from './FindingsTable';
import { FreshnessBanner } from './FreshnessBanner';
import { AdvisoryModal } from './AdvisoryModal';

export function NodeVulnerabilitiesTab({ env, uuid }: { env: string; uuid: string }) {
  const { t } = useTranslation();
  // Counts are pre-formatted: ICU leaves a plain {count} without separators.
  const { formatNumber } = useLocale();
  const [advisory, setAdvisory] = useState<string | null>(null);
  const closeAdvisory = useCallback(() => setAdvisory(null), []);
  const { data, isLoading, error } = useQuery({
    queryKey: ['node-vulns', env, uuid],
    queryFn: () => getNodeVulns(env, uuid),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
      </div>
    );
  }
  if (error || !data) {
    return (
      <EmptyState
        icon={<ShieldAlert />}
        title={t('vulns.loadError')}
        description={error instanceof Error ? error.message : undefined}
      />
    );
  }

  // Inventory is stored before the worker matches it (and again daily). Until
  // the match catches up, an empty list is not evidence of anything.
  const matchPending =
    !hasTime(data.matched_at) ||
    Date.parse(data.matched_at as string) < Date.parse(data.inventory_at as string);

  return (
    <div className="space-y-4">
      <FreshnessBanner loaded={data.loaded} stale={data.stale} />
      {!hasTime(data.inventory_at) ? (
        <EmptyState icon={<ShieldAlert />} title={t('vulns.nodeNoInventory')} />
      ) : (
        <>
          {data.not_assessed > 0 && (
            <p className="text-xs text-[color:var(--text-3)]" title={t('vulns.notAssessedHint')}>
              {t('vulns.notAssessedCount', { count: formatNumber(data.not_assessed) })}
            </p>
          )}
          {data.findings.length === 0 ? (
            <EmptyState icon={<ShieldAlert />} title={matchPending ? t('vulns.matchPending') : t('vulns.nodeNone')} />
          ) : (
            <div className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
              <FindingsTable env={env} findings={data.findings} onOpenAdvisory={setAdvisory} />
            </div>
          )}
          {data.findings.length >= NODE_FINDINGS_LIMIT && (
            <p role="status" className="text-xs text-[color:var(--warning)]">
              {t('vulns.truncated', { count: formatNumber(NODE_FINDINGS_LIMIT) })}
            </p>
          )}
        </>
      )}
      {advisory && <AdvisoryModal env={env} advisoryId={advisory} onClose={closeAdvisory} />}
    </div>
  );
}
