import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { HeartPulse, RefreshCw } from 'lucide-react';
import { getHealthStatus, type HealthComponent, type HealthStatusValue } from '$/api/health';
import { usePageTitle } from '$/lib/usePageTitle';
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

const LABELS: Record<HealthStatusValue, string> = {
  operational: 'Operational',
  degraded: 'Degraded',
  down: 'Down',
  stale: 'Stale',
  unknown: 'Unknown',
};

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
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

const BYTE_FIELDS = new Set([
  'alloc', 'total_alloc', 'sys', 'heap_alloc', 'heap_sys', 'heap_idle', 'heap_inuse',
  'heap_released', 'stack_inuse', 'stack_sys', 'mspan_inuse', 'mspan_sys',
  'mcache_inuse', 'mcache_sys', 'buck_hash_sys', 'gc_sys', 'other_sys', 'next_gc',
]);

function formatValue(key: string, value: unknown): string {
  if (typeof value === 'number' && BYTE_FIELDS.has(key)) return formatBytes(value);
  if (typeof value === 'number') return value.toLocaleString();
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function label(key: string): string {
  return key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

function DetailRows({ details }: { details: Record<string, unknown> }) {
  return (
    <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1 px-4 py-3 text-xs">
      {Object.entries(details)
        .filter(([key]) => key !== 'runtime')
        .map(([key, value]) => (
          <div key={key} className="contents">
            <dt className="text-[color:var(--text-3)]">{label(key)}</dt>
            <dd className="text-right tabular-nums text-[color:var(--text-1)]">{formatValue(key, value)}</dd>
          </div>
        ))}
    </dl>
  );
}

function ComponentRow({ component }: { component: HealthComponent }) {
  const [open, setOpen] = useState(false);
  const details = component.details;
  return (
    <div className="border-b border-[color:var(--border)] last:border-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-sm hover:bg-[color:var(--bg-2)] transition-colors"
      >
        <span className="font-medium text-[color:var(--text-1)]">{component.name}</span>
        <span className="text-xs text-[color:var(--text-3)] truncate">{component.summary}</span>
        <span className="ml-auto flex-shrink-0">
          <StatusBadge variant={VARIANTS[component.status]} label={LABELS[component.status]} />
        </span>
      </button>
      {open && details && <DetailRows details={details} />}
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
  const runtime = component.details?.runtime as Record<string, unknown> | undefined;
  if (!runtime) return null;
  const reportedAt = component.details?.reported_at;
  const asOf =
    typeof reportedAt === 'string' && !Number.isNaN(Date.parse(reportedAt))
      ? `as of ${new Date(reportedAt).toLocaleTimeString()}`
      : 'live';
  return (
    <div className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)]">
      <div className="flex items-baseline gap-2 px-4 py-2 border-b border-[color:var(--border)] text-xs font-semibold uppercase tracking-wide text-[color:var(--text-2)]">
        {component.name}
        <span className="ml-auto font-normal normal-case tracking-normal text-[color:var(--text-3)]">
          {asOf}
        </span>
      </div>
      <DetailRows details={runtime} />
    </div>
  );
}

export function HealthPage() {
  usePageTitle('Health');
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['health-status'],
    queryFn: () => getHealthStatus(),
    staleTime: 15_000,
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-2">
        {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
      </div>
    );
  }

  if (error || !data) {
    return (
      <EmptyState
        icon={<HeartPulse />}
        title="Health data unavailable"
        description={error instanceof Error ? error.message : 'Could not load deployment health.'}
      />
    );
  }

  const { components, upgrade } = data;

  return (
    <div className="p-6 space-y-8 max-w-4xl">
      <section>
        <div className="flex items-center gap-3 mb-1">
          <h2 className="font-display text-lg font-semibold text-[color:var(--text-1)]">Health Status</h2>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="ml-auto"
            disabled={isFetching}
            onClick={() => void refetch()}
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            {isFetching ? 'Refreshing…' : 'Refresh'}
          </Button>
        </div>
        <p className="text-xs text-[color:var(--text-3)] mb-3">How your deployment is doing</p>
        <div className="rounded-md border border-[color:var(--border)]">
          {components.map((c) => <ComponentRow key={c.id} component={c} />)}
        </div>
      </section>

      <section>
        <h2 className="font-display text-lg font-semibold text-[color:var(--text-1)] mb-1">Upgrade Status</h2>
        <p className="text-xs text-[color:var(--text-3)] mb-3">Version running versus what is available</p>
        <div className="rounded-md border border-[color:var(--border)]">
          <DetailRows
            details={
              upgrade.checked
                ? {
                    current: upgrade.current,
                    suggested: upgrade.suggested ?? '—',
                    latest: upgrade.latest ?? '—',
                    up_to_date: upgrade.up_to_date,
                    checked_at: upgrade.checked_at ?? 'never',
                  }
                : {
                    current: upgrade.current,
                    status: 'Upstream check has not run yet',
                  }
            }
          />
          {upgrade.skew && (
            <p className={cn('px-4 py-2 text-xs border-t border-[color:var(--border)]', 'text-[color:var(--warning)]')}>
              Version mismatch — osctrl-api {upgrade.api_version} / osctrl-tls {upgrade.tls_version}
            </p>
          )}
        </div>
      </section>

      <section>
        <h2 className="font-display text-lg font-semibold text-[color:var(--text-1)] mb-3">System status</h2>
        <div className="grid gap-4 md:grid-cols-2">
          {components.map((c) => <RuntimeCard key={c.id} component={c} />)}
        </div>
      </section>
    </div>
  );
}
