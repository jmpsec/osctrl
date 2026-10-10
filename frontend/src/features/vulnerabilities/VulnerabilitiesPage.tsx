import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { ShieldAlert } from 'lucide-react';
import {
  getVulnSummary,
  listVulnFindings,
  VULN_PAGE_SIZE,
  type VulnConfidence,
  type VulnFindingFilter,
  type VulnSeverity,
  type VulnState,
  type VulnSummary,
} from '$/api/vulnerabilities';
import { getMe } from '$/api/users';
import { usePageTitle } from '$/lib/usePageTitle';
import { useLocale } from '$/i18n/useLocale';
import { StatCard } from '$/components/data/StatCard';
import { FilterChip } from '$/components/data/FilterChip';
import { Pagination } from '$/components/data/Pagination';
import { EmptyState } from '$/components/data/EmptyState';
import { SkeletonRow } from '$/components/data/Skeleton';
import { SEVERITIES } from './vulnFormat';
import type { VulnSearch } from './search';
import { FindingsTable } from './FindingsTable';
import { FreshnessBanner } from './FreshnessBanner';
import { AdvisoryModal } from './AdvisoryModal';
import { FeedsCard } from './FeedsCard';

/** Open findings of one severity: of one confidence, or of both when none is given. */
function severityCount(summary: VulnSummary, severity: VulnSeverity, confidence?: VulnConfidence): number {
  const counts = summary.by_severity[severity] ?? {};
  if (confidence) return counts[confidence] ?? 0;
  return Object.values(counts).reduce((n, v) => n + (v ?? 0), 0);
}

export function VulnerabilitiesPage() {
  const { t } = useTranslation();
  const { formatNumber } = useLocale();
  usePageTitle(t('pageTitle.vulnerabilities'));
  const { env } = useParams({ from: '/_app/env/$env/vulnerabilities' });
  // Filters and page live in the URL (see ./search): Back restores them, and
  // an environment switch, which drops the search, starts from page 1.
  const search = useSearch({ from: '/_app/env/$env/vulnerabilities' });
  const navigate = useNavigate({ from: '/_app/env/$env/vulnerabilities' });
  const severity = search.severity;
  const confidence = search.confidence;
  const state: VulnState = search.state ?? 'open';
  const kevOnly = search.kev === true;
  const page = search.page ?? 1;
  const [advisory, setAdvisory] = useState<string | null>(null);
  const closeAdvisory = useCallback(() => setAdvisory(null), []);

  const { data: me } = useQuery({ queryKey: ['users-me'], queryFn: () => getMe(), staleTime: 5 * 60_000 });
  const summary = useQuery({
    queryKey: ['vuln-summary', env],
    queryFn: () => getVulnSummary(env),
    staleTime: 30_000,
  });
  const filter: VulnFindingFilter = { severity, confidence, state, kev: kevOnly, page, page_size: VULN_PAGE_SIZE };
  const findings = useQuery({
    queryKey: ['vuln-findings', env, filter],
    queryFn: () => listVulnFindings(env, filter),
    staleTime: 30_000,
    // Keep the previous page on screen while the next one loads, but never
    // another environment's rows: their node links would point at this one.
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[1] === env ? previous : undefined),
  });

  // Defaults are dropped from the URL so a fresh page has a clean address.
  function updateSearch(patch: Partial<VulnSearch>) {
    void navigate({
      search: (prev: VulnSearch) => {
        const next: VulnSearch = { ...prev, ...patch };
        if (next.state === 'open') delete next.state;
        if (!next.kev) delete next.kev;
        if (next.page === undefined || next.page <= 1) delete next.page;
        if (next.severity === undefined) delete next.severity;
        if (next.confidence === undefined) delete next.confidence;
        return next;
      },
    });
  }

  // Every filter change starts from the first page: staying on page 7 of a
  // result that now has two pages would show an empty table.
  function changeFilter(patch: Partial<VulnSearch>) {
    updateSearch({ ...patch, page: undefined });
  }

  const s = summary.data;
  const rows = findings.data?.findings ?? [];
  const total = findings.data?.total ?? 0;
  const openTotal = s ? SEVERITIES.reduce((n, sev) => n + severityCount(s, sev, 'confirmed'), 0) : 0;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 sm:px-6">
      <header>
        <h1 className="flex items-center gap-2 font-display text-xl font-semibold text-[color:var(--text-1)]">
          <ShieldAlert className="h-5 w-5 text-[color:var(--text-3)]" aria-hidden="true" />
          {t('vulns.title')}
        </h1>
        <p className="mt-1 text-sm text-[color:var(--text-3)]">{t('vulns.description')}</p>
      </header>

      {s && <FreshnessBanner loaded={s.loaded} stale={s.stale} />}

      {s && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label={t('vulns.openFindings')}
            value={openTotal}
            halo="warning"
            sublabel={s.possible > 0 ? t('vulns.possibleExcluded', { count: formatNumber(s.possible) }) : undefined}
          />
          <StatCard label={t('vulns.kev')} value={s.kev} halo="danger" />
          <StatCard label={t('vulns.affectedNodes')} value={s.affected_nodes} halo="info" />
          <StatCard label={t('vulns.notAssessed')} value={s.not_assessed} sublabel={t('vulns.notAssessedHint')} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <FilterChip
          label={t('vulns.allSeverities')}
          selected={severity === undefined}
          onClick={() => changeFilter({ severity: undefined })}
        />
        {SEVERITIES.map((sev) => (
          <FilterChip
            key={sev}
            label={t(`vulns.severity.${sev}`)}
            count={s ? severityCount(s, sev, confidence) : undefined}
            selected={severity === sev}
            onClick={() => changeFilter({ severity: sev })}
          />
        ))}
        <label className="ms-auto flex items-center gap-1.5 text-xs text-[color:var(--text-2)]">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => changeFilter({ kev: e.target.checked })}
          />
          {t('vulns.kevOnly')}
        </label>
        <label className="flex items-center gap-1.5 text-xs text-[color:var(--text-2)]">
          {t('vulns.filterConfidence')}
          <select
            value={confidence ?? ''}
            onChange={(e) => changeFilter({ confidence: (e.target.value || undefined) as VulnConfidence | undefined })}
            className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-3)] px-2 py-1 text-xs text-[color:var(--text-1)]"
          >
            <option value="">{t('vulns.confidenceAll')}</option>
            <option value="confirmed">{t('vulns.confidence.confirmed')}</option>
            <option value="possible">{t('vulns.confidence.possible')}</option>
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs text-[color:var(--text-2)]">
          {t('vulns.filterState')}
          <select
            value={state}
            onChange={(e) => changeFilter({ state: e.target.value as VulnState })}
            className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-3)] px-2 py-1 text-xs text-[color:var(--text-1)]"
          >
            <option value="open">{t('vulns.stateOpen')}</option>
            <option value="resolved">{t('vulns.stateResolved')}</option>
            <option value="all">{t('vulns.stateAll')}</option>
          </select>
        </label>
      </div>

      <section className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]">
        {findings.isLoading ? (
          <table className="w-full">
            <tbody>{Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}</tbody>
          </table>
        ) : findings.isError ? (
          <EmptyState
            icon={<ShieldAlert />}
            title={t('vulns.loadError')}
            description={findings.error instanceof Error ? findings.error.message : undefined}
          />
        ) : rows.length === 0 ? (
          <EmptyState icon={<ShieldAlert />} title={t('vulns.empty')} />
        ) : (
          <FindingsTable env={env} findings={rows} onOpenAdvisory={setAdvisory} showNode />
        )}
      </section>

      {total > 0 && (
        <Pagination
          page={page}
          pageSize={VULN_PAGE_SIZE}
          totalItems={total}
          totalPages={Math.max(1, Math.ceil(total / VULN_PAGE_SIZE))}
          onPageChange={(p) => updateSearch({ page: p })}
        />
      )}

      {me?.admin === true && <FeedsCard />}

      {advisory && <AdvisoryModal env={env} advisoryId={advisory} onClose={closeAdvisory} />}
    </div>
  );
}
