import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpCircle, ChevronDown, Cpu, HeartPulse, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { getHealthStatus, type HealthComponent, type HealthStatusValue } from '$/api/health';
import { usePageTitle } from '$/lib/usePageTitle';
import { formatLocaleDateTime, formatLocaleNumber, useLocale } from '$/i18n/useLocale';
import { StatusBadge } from '$/components/data/StatusBadge';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';

/** Status → badge variant. Stale is a warning, not a failure: the service may
 * be fine and simply not reporting. */
const VARIANTS: Record<HealthStatusValue, 'success' | 'warning' | 'danger' | 'dim'> = {
  operational: 'success',
  degraded: 'warning',
  down: 'danger',
  stale: 'warning',
  unknown: 'dim',
};

const PAGE_CLASS = 'mx-auto w-full max-w-5xl space-y-6 px-4 py-8 sm:px-6 sm:py-10';
const CARD_CLASS = 'min-w-0 overflow-hidden rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)]';

/** Byte counts are unreadable raw; the runtime card is mostly byte counts. */
function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const decimals = value >= 10 || unit === 0 ? 0 : 1;
  return `${formatLocaleNumber(value, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })} ${units[unit]}`;
}

const BYTE_FIELDS = new Set([
  'alloc', 'total_alloc', 'sys', 'heap_alloc', 'heap_sys', 'heap_idle', 'heap_inuse',
  'heap_released', 'stack_inuse', 'stack_sys', 'mspan_inuse', 'mspan_sys',
  'mcache_inuse', 'mcache_sys', 'buck_hash_sys', 'gc_sys', 'other_sys', 'next_gc',
]);

function formatValue(key: string, value: unknown, t: TFunction): string {
  if (typeof value === 'number' && BYTE_FIELDS.has(key)) return formatBytes(value);
  if (typeof value === 'number') return formatLocaleNumber(value);
  if (typeof value === 'boolean') return t(value ? 'commonExt.yes' : 'commonExt.no');
  if (value === null || value === undefined) return '—';
  if ((key === 'checked_at' || key === 'reported_at') && typeof value === 'string' && !Number.isNaN(Date.parse(value))) {
    return formatLocaleDateTime(new Date(value), { dateStyle: 'medium', timeStyle: 'medium' });
  }
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function label(key: string): string {
  return key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

function DetailRows({ details }: { details: Record<string, unknown> }) {
  const { t } = useTranslation();
  return (
    <dl className="space-y-3 px-5 py-4 text-xs">
      {Object.entries(details)
        .filter(([key]) => key !== 'runtime')
        .map(([key, value]) => (
          <div key={key} className="grid grid-cols-2 items-baseline gap-4">
            <dt className="break-words text-[color:var(--text-2)]">{t(`health.fields.${key}`, { defaultValue: label(key) })}</dt>
            <dd className="min-w-0 text-end tabular-nums text-[color:var(--text-1)] [overflow-wrap:anywhere]">{formatValue(key, value, t)}</dd>
          </div>
        ))}
    </dl>
  );
}

function ComponentRow({ component }: { component: HealthComponent }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const details = component.details;
  const hasDetails = details && Object.keys(details).some((key) => key !== 'runtime');
  return (
    <div className="border-b border-[color:var(--border)] last:border-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={!hasDetails}
        aria-expanded={hasDetails ? open : undefined}
        className="flex w-full items-center gap-3 px-5 py-4 text-start text-sm transition-colors enabled:hover:bg-[color:var(--bg-2)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[color:var(--accent)]"
      >
        <span className="min-w-0 flex-1">
          <span className="block break-words font-medium text-[color:var(--text-1)]">{t(`health.components.${component.id}`, { defaultValue: component.name })}</span>
          <span className="mt-1 block text-xs leading-relaxed text-[color:var(--text-3)] [overflow-wrap:anywhere]">{component.summary}</span>
        </span>
        <span className="ms-auto flex-shrink-0">
          <StatusBadge variant={VARIANTS[component.status]} label={t(`health.statuses.${component.status}`)} />
        </span>
        <ChevronDown aria-hidden="true" className={cn('h-3.5 w-3.5 shrink-0 text-[color:var(--text-3)] transition-transform', open && 'rotate-180', !hasDetails && 'invisible')} />
      </button>
      {open && details && (
        <div className="border-t border-[color:var(--border)] bg-[color:var(--bg-2)]">
          <DetailRows details={details} />
        </div>
      )}
    </div>
  );
}

/**
 * The Go runtime card, one per service that reports runtime detail.
 *
 * osctrl-api's numbers are read while serving this request; osctrl-tls's ride
 * its heartbeat and are up to a minute old. The card says which, so nobody
 * debugs a memory spike against stale numbers.
 */
function RuntimeCard({ component }: { component: HealthComponent }) {
  const { t } = useTranslation();
  const { formatTime } = useLocale();
  const runtime = component.details?.runtime as Record<string, unknown> | undefined;
  if (!runtime) return null;
  const reportedAt = component.details?.reported_at;
  const asOf =
    typeof reportedAt === 'string' && !Number.isNaN(Date.parse(reportedAt))
      ? t('health.asOf', {
          time: formatTime(new Date(reportedAt), {
            hour: 'numeric',
            minute: '2-digit',
            second: '2-digit',
          }),
        })
      : t('health.live');
  return (
    <div className={CARD_CLASS}>
      <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--border)] bg-[color:var(--bg-2)] px-5 py-4 text-sm font-semibold text-[color:var(--text-1)]">
        <Cpu className="h-4 w-4 text-[color:var(--text-3)]" aria-hidden="true" />
        {component.name}
        <span className="ms-auto rounded-full border border-[color:var(--border)] px-2 py-0.5 text-xs font-normal text-[color:var(--text-3)]">
          {asOf}
        </span>
      </div>
      <DetailRows details={runtime} />
    </div>
  );
}

export function HealthPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.health'));
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['health-status'],
    queryFn: () => getHealthStatus(),
    staleTime: 15_000,
  });

  if (isLoading) {
    return (
      <div className={PAGE_CLASS}>
        <Skeleton className="mx-auto h-28 w-64 max-w-full rounded-xl" />
        {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32 w-full rounded-xl" />)}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className={PAGE_CLASS}>
        <EmptyState
          icon={<HeartPulse />}
          title={t('health.unavailable')}
          description={error instanceof Error ? error.message : t('health.loadError')}
        />
      </div>
    );
  }

  const { components, upgrade } = data;

  return (
    <div className={PAGE_CLASS}>
      <header className="flex flex-col items-center pb-2 text-center">
        <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-[color:var(--accent)]/20 bg-[color:var(--accent-soft)] text-[color:var(--accent)]">
          <HeartPulse className="h-6 w-6" aria-hidden="true" />
        </div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-[color:var(--text-1)]">{t('health.title')}</h1>
        <p className="mt-2 text-sm text-[color:var(--text-3)]">{t('health.description')}</p>
        <Button
          type="button"
          variant="ghost"
          size="md"
          className="mt-5"
          disabled={isFetching}
          onClick={() => void refetch()}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', isFetching && 'animate-spin')} aria-hidden="true" />
          {t(isFetching ? 'commonExt.refreshing' : 'commonExt.refresh')}
        </Button>
      </header>

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
        <section className={CARD_CLASS}>
          <div className="border-b border-[color:var(--border)] bg-[color:var(--bg-2)] px-5 py-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--text-1)]"><HeartPulse className="h-4 w-4 text-[color:var(--text-3)]" aria-hidden="true" />{t('health.services')}</h2>
            <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('health.servicesDescription')}</p>
          </div>
          <div>
            {components.map((c) => <ComponentRow key={c.id} component={c} />)}
          </div>
        </section>

        <section className={CARD_CLASS}>
          <div className="border-b border-[color:var(--border)] bg-[color:var(--bg-2)] px-5 py-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-[color:var(--text-1)]"><ArrowUpCircle className="h-4 w-4 text-[color:var(--text-3)]" aria-hidden="true" />{t('health.upgrade')}</h2>
            <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('health.upgradeDescription')}</p>
          </div>
          <div>
            <DetailRows
              details={
                upgrade.checked
                  ? {
                      current: upgrade.current,
                      suggested: upgrade.suggested ?? '—',
                      latest: upgrade.latest ?? '—',
                      up_to_date: upgrade.up_to_date,
                      checked_at: upgrade.checked_at ?? t('health.never'),
                    }
                  : {
                      current: upgrade.current,
                      status: t('health.notChecked'),
                    }
              }
            />
            {upgrade.skew && (
              <p className="border-t border-[color:var(--border)] bg-[color:var(--warning)]/5 px-5 py-3 text-xs leading-relaxed text-[color:var(--warning)]">
                {t('health.versionMismatch', { api: upgrade.api_version, tls: upgrade.tls_version })}
              </p>
            )}
          </div>
        </section>
      </div>

      <section>
        <div className="mb-4">
          <h2 className="font-display text-lg font-semibold text-[color:var(--text-1)]">{t('health.system')}</h2>
          <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('health.systemDescription')}</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {components.map((c) => <RuntimeCard key={c.id} component={c} />)}
        </div>
      </section>
    </div>
  );
}
