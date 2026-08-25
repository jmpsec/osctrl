/**
 * DashboardPage — cross-env overview of every environment's osquery activity.
 *
 * Data sources:
 *   GET /api/v1/stats                                  (polled every 30s)
 *   GET /api/v1/audit-logs?page_size=8                 (polled every 5m)
 *   GET /api/v1/stats/activity/env-tiles/{env}?days=N  (per env; node activity
 *                                                       line chart: status, result,
 *                                                       config, query read/write)
 */

import { lazy, Suspense, useState, type ReactNode } from 'react';
import { FileSearch, FolderOpen, RotateCcw, RotateCw } from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { usePageTitle } from '$/lib/usePageTitle';
import { useQueries, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import {
  getStats,
  getOsqueryVersionCounts,
  getEnvActivityTiles,
  TILE_CATEGORIES,
  TILE_CATEGORY_LABELS,
  tileCategoryTotal,
  tileLastSeen,
  getEnvErrorNodes,
} from '$/api/stats';
import type { PlatformCounts, NodeTileSeries, ActivityInterval, TileCategory } from '$/api/stats';
import { ModalShell } from '$/components/feedback/ModalShell';
import { listAuditLogs, LOG_TYPE_LABELS } from '$/api/audit';
import { listNodes } from '$/api/nodes';
import { listQueries } from '$/api/queries';
import { listCarves } from '$/api/carves';
import { listEnvironments } from '$/api/environments';
import { AuthError } from '$/api/client';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { StatusPip } from '$/components/data/StatusPip';
import { StatusBadge } from '$/components/data/StatusBadge';
import { cn } from '$/lib/cn';
import { formatRelative } from '$/lib/time';
import { DEFAULT_INACTIVE_HOURS } from '$/lib/node-status';
import type { DistributedQuery } from '$/api/types';

// ---------------------------------------------------------------------------
// Node-activity series, derived from the Redis-backed env-tiles endpoint.
//
// Each env returns a NodeTileSeries with hourly counters for status, result,
// config, query_read, and query_write. When multiple envs are visible we sum
// them into a fleet-wide series. The line chart renders one line per
// category; the KPI sparklines use the total series.
//
// When the tiles endpoint hasn't returned yet (or Redis is unavailable),
// all-zero arrays are returned so the chart renders an empty frame.
// ---------------------------------------------------------------------------
export type ChartCategory = 'status' | 'result' | 'config' | 'query' | 'error';

export interface ActivitySeries {
  status: number[];
  result: number[];
  config: number[];
  query: number[];
  statusError: number[];
  total: number[];
}

function emptySeries(n: number): ActivitySeries {
  return {
    status: new Array<number>(n).fill(0),
    result: new Array<number>(n).fill(0),
    config: new Array<number>(n).fill(0),
    query: new Array<number>(n).fill(0),
    statusError: new Array<number>(n).fill(0),
    total: new Array<number>(n).fill(0),
  };
}

function tileSeriesToActivity(tiles: NodeTileSeries | undefined): ActivitySeries {
  if (!tiles) return emptySeries(0);
  const n = tiles.total.length;
  return {
    status: tiles.status.map((v) => v),
    result: tiles.result.map((v) => v),
    config: tiles.config.map((v) => v),
    query: tiles.query_read.map((v) => v),
    // Tolerate a server that predates the status_error counter.
    statusError: (tiles.status_error ?? []).map((v) => v),
    total: tiles.total.map((v) => v),
  };
}



// ---------------------------------------------------------------------------
// LIVE badge — pulsing signal-teal pip with "LIVE" label.
// ---------------------------------------------------------------------------
function LiveBadge() {
  return (
    <StatusBadge
      variant="signal"
      label="Live"
      live
      ariaLabel="Live — auto-refreshing every 30 seconds"
      className="select-none"
    />
  );
}

function DashboardHeader({ envName }: { envName: string }) {
  return (
    <header className="flex items-start justify-between gap-4">
      <div>
        <h1 className="font-display text-xl/tight font-semibold text-(--text-1)">
          Dashboard
        </h1>
        <p className="mt-1 text-[13px] text-(--text-3)">
          {envName} · osquery activity within the last 24 hours
        </p>
      </div>
      <div className="mt-1 flex shrink-0 items-center gap-2">
        <span
          className="hidden items-center gap-1.5 rounded border border-(--border) bg-(--bg-1) px-2 py-0.5 text-xs font-medium text-(--text-3) tabular-nums sm:inline-flex"
          title="Auto-refresh interval"
        >
          <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden>
            <path d="M21 12a9 9 0 11-3-6.7l3 2.7" />
          </svg>
          30s
        </span>
        <LiveBadge />
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
// Inline SVG sparkline — hand-drawn, no libs.
// ---------------------------------------------------------------------------
interface SparklineProps {
  points: number[];
  color?: string;
  width?: number;
  height?: number;
  fill?: boolean;
}
function InlineSparkline({
  points,
  color = 'var(--signal)',
  width = 96,
  height = 22,
  fill = true,
}: SparklineProps) {
  if (!points.length) return null;
  const minV = Math.min(...points);
  const maxV = Math.max(...points);
  const range = maxV - minV || 1;
  const pad = 2;
  const usableH = height - pad * 2;
  const stepX = (width - 1) / (points.length - 1);
  const coords = points.map((p, i) => ({
    x: i * stepX,
    y: pad + usableH - ((p - minV) / range) * usableH,
  }));
  const linePath = coords
    .map((c, i) => `${i === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
    .join(' ');
  const fillPath = `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${height} L0,${height} Z`;
  const gradId = `spk-${color.replace(/[^a-z0-9]/gi, '')}-${points.length}`;
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      aria-hidden
      className="overflow-visible"
      style={{ display: 'block' }}
    >
      {fill && (
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.18" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
      )}
      {fill && <path d={fillPath} fill={`url(#${gradId})`} />}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Time-series chart category palette.
// Defaults match what was hard-coded in the chart before this hook landed:
//   Config = violet  (chart-local, distinct from --signal so it doesn't
//                     collide with the query series in the green-teal corner)
//   Query  = signal-teal
//   Carve  = warning amber
//   Enroll = info blue
// Stored in localStorage per-browser so operators can re-map colors to match
// their mental model (e.g. "Carve is always red for me").
// ---------------------------------------------------------------------------
export type ChartPalette = Record<ChartCategory, string>;

const DEFAULT_PALETTE: ChartPalette = {
  status:  '#67c0ff', // info blue — status logs
  result:  '#2bc4be', // signal teal — query results
  config:  '#a78bfa', // violet — config fetches (agent heartbeat)
  query:   '#4ade80', // green — distributed query reads
  error:   '#ff4d4f', // bright red — ERROR-severity status logs
};

const CHART_CATEGORY_LABELS: Record<ChartCategory, string> = {
  status: 'Status logs',
  result: 'Query results',
  config: 'Config',
  query: 'Queries',
  error: 'Reported errors',
};

const PALETTE_STORAGE_KEY = 'osctrl.dashboard-chart-palette';

function useChartPalette(): [ChartPalette, (key: ChartCategory, hex: string) => void, () => void] {
  const [palette, setPalette] = useState<ChartPalette>(() => {
    if (typeof window === 'undefined') return DEFAULT_PALETTE;
    try {
      const stored = window.localStorage.getItem(PALETTE_STORAGE_KEY);
      if (!stored) return DEFAULT_PALETTE;
      const parsed = JSON.parse(stored) as Partial<ChartPalette>;
      // Defensive merge — if the user has only set 2 of 4 keys (e.g. from
      // an older build that wrote a subset), the missing ones get the
      // current defaults rather than rendering as undefined.
      return { ...DEFAULT_PALETTE, ...parsed };
    } catch {
      return DEFAULT_PALETTE;
    }
  });

  const update = (key: ChartCategory, hex: string) => {
    setPalette((prev) => {
      const next = { ...prev, [key]: hex };
      try {
        window.localStorage.setItem(PALETTE_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // localStorage blocked — keep the in-memory state; we lose
        // persistence but don't crash the page.
      }
      return next;
    });
  };

  const reset = () => {
    setPalette(DEFAULT_PALETTE);
    try {
      window.localStorage.removeItem(PALETTE_STORAGE_KEY);
    } catch {
      /* ignore */
    }
  };

  return [palette, update, reset];
}

function ChartLegend({
  palette,
  onChange,
  onReset,
}: {
  palette: ChartPalette;
  onChange: (key: ChartCategory, hex: string) => void;
  onReset: () => void;
}) {
  const hasCustomColors = (Object.keys(DEFAULT_PALETTE) as ChartCategory[]).some(
    (key) => palette[key] !== DEFAULT_PALETTE[key],
  );

  return (
    <div
      className="mb-2 flex min-h-7 flex-wrap items-center gap-x-1 gap-y-1"
      aria-label="Chart series. Select a series to change its color."
    >
      {(Object.keys(CHART_CATEGORY_LABELS) as ChartCategory[]).map((key) => (
        <label key={key} className="cursor-pointer">
          <input
            type="color"
            value={palette[key]}
            onChange={(event) => onChange(key, event.target.value)}
            className="peer sr-only"
            aria-label={`Change ${CHART_CATEGORY_LABELS[key]} color`}
          />
          <span
            className={cn(
              'inline-flex h-6 items-center gap-1.5 rounded px-1.5',
              'text-xs font-medium text-[color:var(--text-2)]',
              'transition-colors duration-[100ms] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
              'peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-1 peer-focus-visible:outline-[color:var(--accent)]',
            )}
          >
            <span
              className="h-0.5 w-3.5 rounded-full"
              style={{ backgroundColor: palette[key] }}
              aria-hidden
            />
            {CHART_CATEGORY_LABELS[key]}
          </span>
        </label>
      ))}
      {hasCustomColors && (
        <button
          type="button"
          onClick={onReset}
          className="ml-0.5 flex h-6 w-6 items-center justify-center rounded text-[color:var(--text-3)] transition-colors duration-[100ms] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]"
          aria-label="Reset chart colors"
          title="Reset chart colors"
        >
          <RotateCcw size={12} strokeWidth={1.75} aria-hidden />
        </button>
      )}
    </div>
  );
}

// BKLiT and Visx stay in a dashboard-only chunk so other routes do not pay
// the chart runtime cost during their initial load.
const ActivityLineChart = lazy(() => import('./ActivityLineChart'));

// ---------------------------------------------------------------------------
// Mid 4-KPI card — large stat, %-delta-vs-prior chip, mini sparkline.
// ---------------------------------------------------------------------------
type Halo = 'signal' | 'success' | 'warning' | 'danger' | 'info';
const sparkColor: Record<Halo, string> = {
  signal:  'var(--signal)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger:  'var(--danger)',
  info:    'var(--info)',
};
function computeDeltaPct(points: number[]): number | null {
  if (points.length < 2) return null;
  const first = points[0];
  const last = points[points.length - 1];
  if (first === 0) return last === 0 ? 0 : null;
  return Math.round(((last - first) / first) * 100);
}
function deltaTone(pct: number | null, polarity: 'up-good' | 'up-bad'): Halo {
  if (pct == null || pct === 0) return 'info';
  const isUp = pct > 0;
  if (polarity === 'up-good') return isUp ? 'success' : 'danger';
  return isUp ? 'danger' : 'success';
}

interface KpiCardProps {
  label: string;
  value: number;
  sparkline: number[];
  halo: Halo;
  /** "more is good" or "more is bad" for tinting the delta chip. */
  polarity?: 'up-good' | 'up-bad';
  /** Override the auto-computed delta label. */
  deltaLabel?: string;
  /**
   * Makes the card actionable. When set the card renders as a button so it
   * is reachable by keyboard and announced as interactive, rather than a div
   * with a click handler bolted on.
   */
  onClick?: () => void;
  /** Accessible name for the action; required whenever onClick is set. */
  actionLabel?: string;
}
function KpiCard({
  label,
  value,
  sparkline,
  halo,
  polarity = 'up-good',
  deltaLabel,
  onClick,
  actionLabel,
}: KpiCardProps) {
  const pct = computeDeltaPct(sparkline);
  const tone = deltaTone(pct, polarity);
  const text =
    deltaLabel ??
    (pct == null
      ? 'no trend'
      : pct === 0
        ? 'steady'
        : `${pct > 0 ? '+' : ''}${pct}% vs prior`);
  const interactive = !!onClick;
  const Tag = interactive ? 'button' : 'div';
  return (
    <Tag
      type={interactive ? 'button' : undefined}
      onClick={onClick}
      aria-label={interactive ? actionLabel : undefined}
      className={cn(
        'relative flex min-h-[124px] flex-col bg-[color:var(--bg-1)] px-4 py-3.5',
        'transition-colors duration-[100ms] hover:bg-[color:var(--bg-2)]',
        interactive && [
          'text-left cursor-pointer',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2',
          'focus-visible:outline-[color:var(--signal)]',
        ],
      )}
    >
      <div className="text-xs font-medium text-[color:var(--text-2)] select-none">
        {label}
      </div>
      <div className="font-display text-[30px] font-semibold tabular-nums text-[color:var(--text-1)] leading-none mt-2">
        {value.toLocaleString()}
      </div>
      <div className="flex items-end justify-between mt-auto pt-3">
        <span
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded',
            'text-xs font-medium tabular-nums leading-4',
            tone === 'success' && 'bg-[color:var(--success)]/10 text-[color:var(--success)] border border-[color:var(--success)]/25',
            tone === 'danger'  && 'bg-[color:var(--danger)]/10 text-[color:var(--danger)] border border-[color:var(--danger)]/25',
            tone === 'info'    && 'bg-[color:var(--info)]/10 text-[color:var(--info)] border border-[color:var(--info)]/25',
          )}
        >
          <span aria-hidden>
            {pct == null || pct === 0 ? '→' : pct > 0 ? '↑' : '↓'}
          </span>
          {text}
        </span>
        <InlineSparkline points={sparkline} color={sparkColor[halo]} width={84} height={26} />
      </div>
    </Tag>
  );
}

interface DashboardKpiSetProps {
  loading: boolean;
  activeNodes: number;
  totalNodes: number;
  inactiveNodes: number;
  inactiveHours: number;
  reportedErrors: number;
  onReportedErrorsClick?: () => void;
  activeQueries: number;
  chartSeries: ActivitySeries;
}

function DashboardKpiSet({
  loading,
  activeNodes,
  totalNodes,
  inactiveNodes,
  inactiveHours,
  reportedErrors,
  onReportedErrorsClick,
  activeQueries,
  chartSeries,
}: DashboardKpiSetProps) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--border)] lg:grid-cols-4">
      {loading ? (
        Array.from({ length: 4 }).map((_, index) => (
          <KpiSkeletonCard key={index} />
        ))
      ) : (
        <>
          <KpiCard
            label="Active Nodes"
            value={activeNodes}
            sparkline={chartSeries.config}
            halo="success"
            polarity="up-good"
            deltaLabel={totalNodes > 0 ? `${Math.round((activeNodes / totalNodes) * 100)}% of fleet` : 'no nodes'}
          />
          <KpiCard
            label={`Inactive ≥ ${inactiveHours}h`}
            value={inactiveNodes}
            sparkline={chartSeries.status}
            halo="warning"
            polarity="up-bad"
            deltaLabel={totalNodes > 0 ? `${Math.round((inactiveNodes / totalNodes) * 100)}% of fleet` : 'no nodes'}
          />
          <KpiCard
            label="Reported errors (24h)"
            value={reportedErrors}
            sparkline={chartSeries.statusError}
            halo={reportedErrors > 0 ? 'danger' : 'success'}
            polarity="up-bad"
            deltaLabel={reportedErrors === 0 ? 'all clear' : `${reportedErrors} in 24h — see nodes`}
            onClick={onReportedErrorsClick}
            actionLabel="Show the nodes reporting errors"
          />
          <KpiCard
            label="Active Queries"
            value={activeQueries}
            sparkline={chartSeries.query}
            halo="signal"
            polarity="up-good"
            deltaLabel={`${activeQueries} executing`}
          />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Operational workload — the original two-card stack, with the unused right
// side promoted into a quick-access lane for live work.
// ---------------------------------------------------------------------------
interface OperationalWorkloadCardsProps {
  activeQueries: number;
  activeCarves: number;
  featuredQuery?: ActiveQueryRow;
  recentCarve?: DistributedQuery;
  env: string;
}

type WorkloadKind = 'query' | 'carve';

interface WorkloadEntry {
  kind: WorkloadKind;
  title: string;
  description: string;
  count: number;
  statusVariant: 'success' | 'info' | 'dim';
  statusLabel: string;
  emptyLabel: string;
  name?: string;
  linkEnv: string;
  progress: number;
  progressMeta: string;
  progressColor: string;
}

function WorkloadRouteLink({
  entry,
  className,
  children,
}: {
  entry: WorkloadEntry;
  className: string;
  children: ReactNode;
}) {
  if (entry.name && entry.kind === 'query') {
    return (
      <Link
        to="/_app/env/$env/queries/$name"
        params={{ env: entry.linkEnv, name: entry.name }}
        className={className}
      >
        {children}
      </Link>
    );
  }

  if (entry.name) {
    return (
      <Link
        to="/_app/env/$env/carves/$name"
        params={{ env: entry.linkEnv, name: entry.name }}
        className={className}
      >
        {children}
      </Link>
    );
  }

  return entry.kind === 'query' ? (
    <Link to="/_app/env/$env/queries" params={{ env: entry.linkEnv }} className={className}>
      {children}
    </Link>
  ) : (
    <Link to="/_app/env/$env/carves" params={{ env: entry.linkEnv }} className={className}>
      {children}
    </Link>
  );
}

function WorkloadItemIcon({ kind }: { kind: WorkloadKind }) {
  return kind === 'query' ? (
    <FileSearch size={16} strokeWidth={1.7} className="shrink-0 text-[color:var(--nav-violet)]" aria-hidden />
  ) : (
    <FolderOpen size={16} strokeWidth={1.7} className="shrink-0 text-[color:var(--nav-rose)]" aria-hidden />
  );
}

function progressPercent(executions: number, expected: number): number {
  if (expected <= 0) return 0;
  return Math.min(100, Math.round((executions / expected) * 100));
}

function WorkloadProgress({
  value,
  color,
  label,
}: {
  value: number;
  color: string;
  label: string;
}) {
  return (
    <div
      className="mt-2 h-1.5 overflow-hidden rounded-full bg-[color:var(--bg-3)]"
      role="meter"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full w-full rounded-full transition-transform duration-300"
        style={{
          backgroundColor: color,
          transformOrigin: 'left',
          transform: `scaleX(${value / 100})`,
        }}
      />
    </div>
  );
}

function OperationalWorkloadCards({
  activeQueries,
  activeCarves,
  featuredQuery,
  recentCarve,
  env,
}: OperationalWorkloadCardsProps) {
  const queryProgress = featuredQuery
    ? progressPercent(featuredQuery.executions, featuredQuery.expected)
    : 0;
  const carveProgress = recentCarve
    ? progressPercent(recentCarve.executions, recentCarve.expected)
    : 0;
  const carveReady = recentCarve?.completed || recentCarve?.carve_status === 'COMPLETED';

  const workloads: WorkloadEntry[] = [
    {
      kind: 'query',
      title: 'Queries',
      description: 'Active fleet investigations',
      count: activeQueries,
      statusVariant: activeQueries > 0 ? 'success' : 'dim',
      statusLabel: activeQueries > 0 ? 'Executing' : 'Idle',
      emptyLabel: 'View query history',
      name: featuredQuery?.name,
      linkEnv: featuredQuery?.envUuid ?? env,
      progress: queryProgress,
      progressMeta: featuredQuery
        ? `${featuredQuery.executions.toLocaleString()} of ${featuredQuery.expected.toLocaleString()} responses`
        : '',
      progressColor: featuredQuery?.errors ? 'var(--warning)' : 'var(--info)',
    },
    {
      kind: 'carve',
      title: 'Forensic Carves',
      description: 'File collections in flight',
      count: activeCarves,
      statusVariant: activeCarves > 0 ? 'info' : 'dim',
      statusLabel: activeCarves > 0 ? 'In flight' : 'Idle',
      emptyLabel: 'View carve history',
      name: recentCarve?.name,
      linkEnv: env,
      progress: carveReady ? 100 : carveProgress,
      progressMeta: recentCarve
        ? carveReady
          ? 'Archive ready'
          : `${recentCarve.executions.toLocaleString()} of ${recentCarve.expected.toLocaleString()} nodes`
        : '',
      progressColor: carveReady ? 'var(--success)' : 'var(--info)',
    },
  ];

  return (
    <div
      role="group"
      aria-label="Operational workload"
      className="grid min-h-[240px] grid-rows-2 overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]"
    >
      {workloads.map((entry, index) => (
        <article
          key={entry.kind}
          className={cn(
            '@container grid min-h-0 grid-cols-[minmax(0,2fr)_minmax(0,3fr)] gap-4 px-4 py-3.5',
            index > 0 && 'border-t border-[color:var(--border)]',
          )}
        >
          <div className="flex min-w-0 flex-col">
            <h2 className="truncate font-display text-sm font-semibold text-[color:var(--text-1)]">
              {entry.title}
            </h2>
            <p className="mt-1 text-[13px] text-[color:var(--text-3)]">{entry.description}</p>
            <div className="mt-auto flex items-start gap-3 pt-3">
              <span className="font-display text-[30px] font-semibold tabular-nums text-[color:var(--text-1)]">
                {entry.count.toLocaleString()}
              </span>
              <span className="pt-1">
                <StatusBadge variant={entry.statusVariant} label={entry.statusLabel} />
              </span>
            </div>
          </div>

          <div className="flex min-w-0 flex-col border-l border-[color:var(--border)] pl-4">
            <div className="text-[13px] font-medium text-[color:var(--text-3)]">
              {entry.kind === 'query' ? 'Query in progress' : 'Latest carve'}
            </div>
            <WorkloadRouteLink
              entry={entry}
              className="group mt-2 min-w-0 rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]"
            >
              <span className="flex min-w-0 items-center gap-2">
                {entry.name && <WorkloadItemIcon kind={entry.kind} />}
                <span className="truncate text-[13px] font-medium text-[color:var(--text-1)] group-hover:text-[color:var(--text-link)]">
                  {entry.name ?? entry.emptyLabel}
                </span>
              </span>
              {entry.name && (
                <>
                  <span className="mt-1.5 flex justify-between gap-2 text-[12px] tabular-nums text-[color:var(--text-3)]">
                    <span>{entry.progressMeta}</span>
                    <span>{entry.progress}%</span>
                  </span>
                  <WorkloadProgress
                    value={entry.progress}
                    color={entry.progressColor}
                    label={`${entry.kind === 'query' ? 'Query' : 'Carve'} progress, ${entry.progress}% complete`}
                  />
                </>
              )}
            </WorkloadRouteLink>
          </div>
        </article>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Top platforms — horizontal mini stacked bar + legend rows.
// ---------------------------------------------------------------------------
const PLATFORM_LABEL: Record<keyof PlatformCounts, string> = {
  linux: 'Linux',
  darwin: 'macOS',
  windows: 'Windows',
  other: 'Other',
};
const PLATFORM_COLOR: Record<keyof PlatformCounts, string> = {
  linux: 'var(--plat-linux, var(--warning))',
  darwin: 'var(--plat-mac, var(--info))',
  windows: 'var(--plat-windows, var(--info))',
  other: 'var(--text-3)',
};
function TopPlatformsPanel({ counts, total }: { counts: PlatformCounts; total: number }) {
  const entries = (Object.keys(counts) as (keyof PlatformCounts)[])
    .map((k) => ({ key: k, count: counts[k] }))
    .sort((a, b) => b.count - a.count);
  return (
    <section
      aria-label="Hosts by platform"
      className="rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
    >
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
          Hosts by platform
        </h2>
        <span className="text-xs font-medium text-[color:var(--text-3)] tabular-nums">
          {total.toLocaleString()} total
        </span>
      </div>
      {/* Stacked bar */}
      <div className="h-2 w-full rounded-full overflow-hidden bg-[color:var(--bg-3)] flex" aria-hidden>
        {entries.map(({ key, count }) => {
          const pct = total > 0 ? (count / total) * 100 : 0;
          if (pct === 0) return null;
          return (
            <div
              key={key}
              className="h-full"
              style={{ width: `${pct}%`, background: PLATFORM_COLOR[key] }}
              title={`${PLATFORM_LABEL[key]}: ${count}`}
            />
          );
        })}
      </div>
      {/* Legend */}
      <ul className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5">
        {entries.map(({ key, count }) => {
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <li key={key} className="flex items-center gap-2 text-xs">
              <span
                aria-hidden
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: PLATFORM_COLOR[key] }}
              />
              <span className="text-[color:var(--text-2)] flex-1 truncate">{PLATFORM_LABEL[key]}</span>
              <span className="font-medium text-[color:var(--text-1)] tabular-nums">{count}</span>
              <span className="text-[color:var(--text-3)] tabular-nums w-9 text-right">
                {pct}%
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Activity feed row
// ---------------------------------------------------------------------------
function avatarGradient(username: string): string {
  let h = 0;
  for (let i = 0; i < username.length; i++) h = (h * 31 + username.charCodeAt(i)) % 360;
  const h2 = (h + 40) % 360;
  return `linear-gradient(225deg, hsl(${h},60%,48%), hsl(${h2},70%,38%))`;
}
function initials(username: string): string {
  const parts = username.replace(/_/g, ' ').split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return username.slice(0, 2).toUpperCase();
}
function relativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}
function ActivityRow({
  username, service, logType, line, createdAt,
}: { username: string; service: string; logType: number; line: string; createdAt: string }) {
  const typeLabel = LOG_TYPE_LABELS[logType] ?? 'action';
  const isAuth = logType === 1 || logType === 2;
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
      <div
        className="flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold text-white"
        style={{ background: avatarGradient(username) }}
        aria-hidden
      >
        {initials(username)}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[13px] leading-snug text-[color:var(--text-1)]">
          <span className="font-semibold">{username}</span>
          {' '}
          <span className="text-[color:var(--text-2)]">{isAuth ? typeLabel : `${typeLabel} via`}</span>
          {!isAuth && (
            <span className="text-xs font-medium text-[color:var(--signal)] ml-1 truncate">
              {service}
            </span>
          )}
        </div>
        {line && (
          <div className="text-xs text-[color:var(--text-3)] truncate mt-0.5">
            {line.length > 64 ? `${line.slice(0, 64)}…` : line}
          </div>
        )}
      </div>
      <time
        className="flex-shrink-0 text-xs text-[color:var(--text-3)] mt-0.5 tabular-nums"
        dateTime={createdAt}
        title={new Date(createdAt).toLocaleString()}
      >
        {relativeTime(createdAt)}
      </time>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reported-errors drill-down — which nodes are erroring, worst first.
// ---------------------------------------------------------------------------
function ErrorNodesDialog({
  env,
  onClose,
}: {
  env: string;
  onClose: () => void;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['dashboard-error-nodes', env],
    queryFn: () => getEnvErrorNodes(env, 1),
    staleTime: 30_000,
    retry: 1,
  });
  const rows = data ?? [];

  return (
    <ModalShell
      title="Nodes reporting errors (24h)"
      titleId="error-nodes-title"
      onClose={onClose}
      panelClassName="max-w-lg"
    >
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-9 w-full" />
          ))}
        </div>
      ) : isError ? (
        <p className="text-sm text-[color:var(--danger)]">
          Could not load the erroring nodes.
        </p>
      ) : rows.length === 0 ? (
        <p className="text-sm text-[color:var(--text-3)]">
          No node reported an error in the last 24 hours.
        </p>
      ) : (
        <>
          <p className="mb-3 text-xs text-[color:var(--text-3)]">
            Counting osquery status logs at ERROR severity. Warnings are not
            included.
          </p>
          <ul className="divide-y divide-[color:var(--border)] rounded-md border border-[color:var(--border)]">
            {rows.map((row) => (
              <li key={row.uuid} className="flex items-center justify-between gap-3 px-3 py-2">
                <Link
                  to="/_app/env/$env/nodes/$uuid"
                  params={{ env, uuid: row.uuid }}
                  onClick={onClose}
                  className="min-w-0 text-xs text-[color:var(--text-1)] hover:text-[color:var(--signal)] truncate"
                >
                  {/* A node deleted since it errored has no hostname left;
                      its UUID is still the honest identifier. */}
                  {row.hostname || row.uuid}
                </Link>
                <span
                  className="font-mono-tabular text-xs font-semibold tabular-nums flex-shrink-0"
                  style={{ color: 'var(--error-bright)' }}
                >
                  {row.errors.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Endpoint health — selected-environment osquery endpoint activity.
// ---------------------------------------------------------------------------
const ENDPOINT_HEALTH_TONE: Record<TileCategory, string> = {
  config: 'var(--info)',
  status: 'var(--success)',
  result: 'var(--signal)',
  query_read: 'var(--warning)',
  query_write: 'var(--signal)',
  // Hotter than the --danger used elsewhere: every other row on this panel
  // is normal traffic, so the errors row has to be unmistakable at a glance.
  status_error: 'var(--error-bright)',
};

function EndpointHealthPanel({
  tiles,
  intervalLabel,
  isLoading,
  isFetching,
  hasEnvironment,
  onRefresh,
}: {
  tiles?: NodeTileSeries;
  intervalLabel: string;
  isLoading: boolean;
  isFetching: boolean;
  hasEnvironment: boolean;
  onRefresh: () => void;
}) {
  const rows = TILE_CATEGORIES.map((category) => {
    const total = tiles ? tileCategoryTotal(tiles, category) : 0;
    const lastSeen = tiles ? tileLastSeen(tiles, category) : null;
    return { category, total, lastSeen };
  });
  const anyActivity = rows.some((row) => row.total > 0);

  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
        <div>
          <span className="text-[13px] font-semibold font-display text-[color:var(--text-1)]">
            Endpoint health
          </span>
          <div className="text-xs font-medium text-[color:var(--text-3)] tabular-nums">
            {intervalLabel}
          </div>
        </div>
        <RefreshButton onClick={onRefresh} isPending={isFetching} />
      </div>
      <div className="px-4 flex-1">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="grid grid-cols-[1fr_auto_auto] gap-3 items-center py-2.5 border-b border-[color:var(--border)] last:border-0">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-3 w-14" />
            </div>
          ))
        ) : !hasEnvironment ? (
          <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
            No environment selected.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-[1fr_auto_auto] gap-3 px-0 h-8 items-center border-b border-[color:var(--border)] text-xs font-medium text-[color:var(--text-3)] select-none">
              <span>Endpoint</span>
              <span className="text-right">Events</span>
              <span className="text-right">Last seen</span>
            </div>
            {rows.map((row) => {
              const label = TILE_CATEGORY_LABELS[row.category];
              // The errors row goes fully red once there is something to
              // report. At zero it stays neutral like every other row —
              // a permanently red panel is one nobody reads.
              const alarming = row.category === 'status_error' && row.total > 0;
              const rowColor = alarming
                ? 'var(--error-bright)'
                : 'var(--text-1)';
              return (
                <div
                  key={row.category}
                  className={cn(
                    'grid grid-cols-[1fr_auto_auto] gap-3 items-center py-2.5 border-b border-[color:var(--border)] last:border-0',
                    alarming && 'bg-[rgba(var(--error-bright-r),var(--error-bright-g),var(--error-bright-b),0.07)]',
                  )}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      aria-hidden
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ background: ENDPOINT_HEALTH_TONE[row.category] }}
                    />
                    <span
                      className="text-[13px] font-medium truncate"
                      style={{ color: rowColor }}
                    >
                      {label}
                    </span>
                  </div>
                  <span
                    className={cn(
                      'text-xs font-medium tabular-nums text-right',
                      alarming && 'font-semibold',
                    )}
                    style={{ color: rowColor }}
                  >
                    {row.total.toLocaleString()}
                  </span>
                  {row.lastSeen ? (
                    <time
                      className="text-xs text-[color:var(--text-3)] tabular-nums text-right"
                      dateTime={row.lastSeen}
                      title={new Date(row.lastSeen).toLocaleString()}
                    >
                      {formatRelative(row.lastSeen)}
                    </time>
                  ) : (
                    <span className="text-xs text-[color:var(--text-3)] tabular-nums text-right">
                      none
                    </span>
                  )}
                </div>
              );
            })}
            {!anyActivity && (
              <div className="py-3 text-center text-xs text-[color:var(--text-3)]">
                No endpoint activity in this window.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeletons
// ---------------------------------------------------------------------------
function KpiSkeletonCard() {
  return (
    <div className="flex min-h-[124px] flex-col gap-3 bg-[color:var(--bg-1)] px-4 py-3.5">
      <Skeleton className="h-3 w-20" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-[22px] w-24 mt-auto" />
    </div>
  );
}
function ActivityRowSkeleton() {
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
      <Skeleton className="w-7 h-7 rounded-full flex-shrink-0" />
      <div className="flex-1 space-y-1.5">
        <Skeleton className="h-3 w-3/4" />
        <Skeleton className="h-2.5 w-1/2" />
      </div>
      <Skeleton className="h-2.5 w-10 flex-shrink-0 mt-0.5" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Environments table — replaces the EnvTileRich grid (denser, more data).
// Joins EnvStats with TLSEnvironment by uuid to surface enroll_expire.
// ---------------------------------------------------------------------------
interface EnvTableEnv {
  uuid: string;
  name: string;
  active: number;
  inactive: number;
  active_queries: number;
  active_carves: number;
  /** RFC3339 from TLSEnvironment.enroll_expire; undefined if env list missing. */
  enroll_expire?: string;
}

/** Tint for the enroll-expire cell. Past or <7d → danger, <30d → warning. */
function enrollExpireTone(iso?: string): 'danger' | 'warning' | 'normal' {
  if (!iso) return 'normal';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'normal';
  const diffMs = d.getTime() - Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  if (diffMs < 7 * DAY) return 'danger';
  if (diffMs < 30 * DAY) return 'warning';
  return 'normal';
}

/** Compact relative time for a future timestamp ("in 4d", "in 12h", "expired"). */
function formatExpireRelative(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const diffMs = d.getTime() - Date.now();
  if (diffMs <= 0) return 'expired';
  const HOUR = 60 * 60 * 1000;
  const DAY = 24 * HOUR;
  if (diffMs < HOUR) return `in ${Math.max(1, Math.floor(diffMs / (60 * 1000)))}m`;
  if (diffMs < DAY) return `in ${Math.floor(diffMs / HOUR)}h`;
  return `in ${Math.floor(diffMs / DAY)}d`;
}

function EnvTable({ envs }: { envs: EnvTableEnv[] }) {
  return (
    <div
      className="rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
      role="table"
      aria-label="Environments table"
    >
      <div
        role="row"
        className={cn(
          'grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-9',
          'items-center border-b border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-xs font-medium text-[color:var(--text-3)] select-none',
        )}
      >
        <span>Environment</span>
        <span className="text-right">Active</span>
        <span className="text-right">Inactive</span>
        <span className="text-right">Queries</span>
        <span className="text-right">Carves</span>
        <span className="text-right">Enroll expires</span>
        <span className="text-right">&nbsp;</span>
      </div>
      {envs.map((env) => {
        const tone = enrollExpireTone(env.enroll_expire);
        const isHealthy = env.active > 0;
        const expireText = formatExpireRelative(env.enroll_expire);
        return (
          <div
            key={env.uuid}
            role="row"
            className={cn(
              'grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-11',
              'items-center border-b border-[color:var(--border)] last:border-0',
              'text-[13px] hover:bg-[color:var(--bg-2)]',
              'transition-colors duration-[120ms]',
            )}
          >
            <div className="flex items-center gap-2 min-w-0">
              <StatusPip variant={isHealthy ? 'success' : 'warning'} />
              <span className="font-display font-semibold text-[color:var(--text-1)] truncate">
                {env.name}
              </span>
            </div>
            <span className="tabular-nums text-[color:var(--text-1)] text-right">
              {env.active.toLocaleString()}
            </span>
            <span className="tabular-nums text-[color:var(--text-3)] text-right">
              {env.inactive.toLocaleString()}
            </span>
            <span className="tabular-nums text-[color:var(--text-1)] text-right">
              {env.active_queries.toLocaleString()}
            </span>
            <span className="tabular-nums text-[color:var(--text-1)] text-right">
              {env.active_carves.toLocaleString()}
            </span>
            <span
              className={cn(
                'tabular-nums text-right',
                tone === 'danger' && 'text-[color:var(--danger)]',
                tone === 'warning' && 'text-[color:var(--warning)]',
                tone === 'normal' && 'text-[color:var(--text-2)]',
              )}
              title={env.enroll_expire || undefined}
            >
              {expireText}
            </span>
            <Link
              to="/_app/env/$env/nodes"
              params={{ env: env.uuid }}
              className={cn(
                'text-xs font-medium text-[color:var(--signal)] hover:underline text-right',
                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
                'focus-visible:outline-[color:var(--signal)]',
              )}
            >
              Open →
            </Link>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// osquery versions panel — bars + version + count, with optional UP-TO-DATE
// chip when the most-common version represents >80% of the fleet.
// ---------------------------------------------------------------------------
const VERSION_BAR_COLORS = [
  'var(--signal)',
  'var(--info)',
  'var(--success)',
  'var(--warning)',
] as const;

function OsqueryVersionsPanel({
  versions,
}: {
  versions: { version: string; count: number }[];
}) {
  const total = versions.reduce((s, v) => s + v.count, 0);
  const topPct = total > 0 ? (versions[0]?.count ?? 0) / total : 0;
  const showUpToDate = total > 0 && topPct > 0.8;
  return (
    <section
      aria-label="osquery agent versions"
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden flex flex-col"
    >
      <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
        <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)] flex items-center gap-2">
          osquery versions
          {showUpToDate && (
            <StatusBadge variant="success" label="Up to date" />
          )}
        </h2>
        <span className="text-xs font-medium text-[color:var(--text-3)] tabular-nums">
          {total.toLocaleString()} hosts
        </span>
      </div>
      <div className="px-4 py-3 flex-1">
        {versions.length === 0 ? (
          <div className="py-6 text-center text-sm text-[color:var(--text-3)]">
            No agents reporting yet.
          </div>
        ) : (
          <ul className="flex flex-col gap-2">
            {versions.map((v, i) => (
              <li key={v.version || `unknown-${i}`} className="flex items-center gap-2.5">
                <span
                  aria-hidden
                  className="w-[2px] h-3.5 rounded-sm flex-shrink-0"
                  style={{ background: VERSION_BAR_COLORS[i % VERSION_BAR_COLORS.length] }}
                />
                <span className="text-[12px] text-[color:var(--text-1)] tabular-nums flex-1 truncate">
                  {v.version || 'unknown'}
                </span>
                <span className="text-[12px] text-[color:var(--text-3)] tabular-nums">
                  {v.count.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Active queries with live progress — flattened across envs, capped at 8.
// ---------------------------------------------------------------------------
interface ActiveQueryRow {
  name: string;
  envName: string;
  envUuid: string;
  expected: number;
  executions: number;
  errors: number;
}

function progressTone(row: ActiveQueryRow): 'success' | 'warning' | 'info' {
  if (row.errors > 0) return 'warning';
  if (row.expected > 0 && row.executions >= row.expected) return 'success';
  return 'info';
}

function ActiveQueryRowItem({
  row,
  elapsed,
}: {
  row: ActiveQueryRow;
  elapsed: string;
}) {
  const tone = progressTone(row);
  const pct =
    row.expected > 0
      ? Math.min(100, Math.round((row.executions / row.expected) * 100))
      : 0;
  const done = row.expected > 0 && row.executions >= row.expected;
  const barColor =
    tone === 'warning' ? 'var(--warning)' : tone === 'success' ? 'var(--success)' : 'var(--info)';
  return (
    <Link
      to="/_app/env/$env/queries/$name"
      params={{ env: row.envUuid, name: row.name }}
      className={cn(
        'grid grid-cols-12 gap-3 items-center px-4 h-11 border-b border-[color:var(--border)] last:border-0',
        'text-[13px] hover:bg-[color:var(--bg-2)] transition-colors duration-[120ms]',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px]',
        'focus-visible:outline-[color:var(--signal)]',
      )}
    >
      <div className="col-span-5 flex items-center gap-2.5 min-w-0">
        <StatusPip variant={tone} />
        <span className="font-medium text-[color:var(--text-1)] truncate">
          {row.name}
        </span>
      </div>
      <span
        className={cn(
          'col-span-2 inline-flex items-center justify-center px-1.5 py-0.5 rounded',
          'text-xs font-medium border border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-[color:var(--text-2)] truncate',
        )}
      >
        {row.envName}
      </span>
      <span className="col-span-2 text-xs tabular-nums text-[color:var(--text-3)] text-right">
        {row.executions.toLocaleString()} / {row.expected.toLocaleString()}
        {row.errors > 0 && (
          <>
            {' · '}
            <span className="text-[color:var(--warning)]">{row.errors} err</span>
          </>
        )}
      </span>
      <div
        className="col-span-2 h-1.5 rounded-full bg-[color:var(--bg-3)] overflow-hidden"
        role="meter"
        aria-label={`${pct}% complete`}
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, background: barColor }}
        />
      </div>
      <span className="col-span-1 text-right text-xs text-[color:var(--text-3)] tabular-nums">
        {done ? 'done' : elapsed}
      </span>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Recently seen nodes — compact table below the activity feed.
// ---------------------------------------------------------------------------
interface RecentNodeRow {
  uuid: string;
  hostname: string;
  localname: string;
  platform: string;
  osquery_version: string;
  ip_address: string;
  last_seen: string;
  env: string;
}

function RecentlySeenNodesTable({
  nodes,
  envUuid,
}: {
  nodes: RecentNodeRow[];
  envUuid: string;
}) {
  return (
    <div
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
      role="table"
      aria-label="Recently seen nodes"
    >
      <div
        role="row"
        className={cn(
          'grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-9',
          'items-center border-b border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-xs font-medium text-[color:var(--text-3)] select-none',
        )}
      >
        <span>Hostname</span>
        <span>Platform</span>
        <span>osquery</span>
        <span>IP</span>
        <span>Tags</span>
        <span className="text-right">Last seen</span>
      </div>
      {nodes.map((n) => {
        const display = n.hostname || n.localname || 'unknown';
        return (
          <div
            key={n.uuid}
            role="row"
            className={cn(
              'grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-11',
              'items-center border-b border-[color:var(--border)] last:border-0',
              'text-[13px] hover:bg-[color:var(--bg-2)] transition-colors duration-[120ms]',
            )}
          >
            <div className="flex flex-col gap-0.5 min-w-0">
              <Link
                to="/_app/env/$env/nodes/$uuid"
                params={{ env: envUuid, uuid: n.uuid }}
                className={cn(
                  'text-[color:var(--text-link)] hover:underline truncate',
                  'font-medium text-[13px] leading-tight',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
                  'focus-visible:outline-[color:var(--signal)] rounded',
                )}
              >
                {display}
              </Link>
              <span
                className="text-xs font-mono-tabular text-[color:var(--text-3)] leading-tight"
                title={n.uuid}
              >
                <span className="text-[color:var(--signal)]">{n.uuid.slice(0, 6)}</span>
                <span>…</span>
              </span>
            </div>
            <span className="text-[12px] text-[color:var(--text-2)] truncate uppercase tracking-[0.04em]">
              {n.platform || '—'}
            </span>
            <span className="text-xs text-[color:var(--text-3)] tabular-nums truncate">
              {n.osquery_version || '—'}
            </span>
            <span className="font-mono-tabular text-xs text-[color:var(--text-3)] tabular-nums truncate">
              {n.ip_address || '—'}
            </span>
            <span className="text-xs text-[color:var(--text-3)] truncate">—</span>
            <time
                className="text-xs text-[color:var(--text-3)] tabular-nums text-right"
              dateTime={n.last_seen}
              title={n.last_seen ? new Date(n.last_seen).toLocaleString() : ''}
            >
              {n.last_seen ? formatRelative(n.last_seen) : '—'}
            </time>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RefreshButton — small icon button for manual per-section refresh.
// ---------------------------------------------------------------------------
function RefreshButton({ onClick, isPending }: { onClick: () => void; isPending: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={isPending}
      className={cn(
        'flex-shrink-0 p-1 rounded transition-colors duration-[120ms]',
        'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
        'hover:bg-[color:var(--bg-2)]',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        isPending && 'animate-spin',
      )}
      aria-label="Refresh"
      title="Refresh"
    >
      <RotateCw className="w-3.5 h-3.5" />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export function DashboardPage() {
  usePageTitle('Dashboard');
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const inactiveHours =
    data?.inactive_hours && data.inactive_hours > 0
      ? data.inactive_hours
      : DEFAULT_INACTIVE_HOURS;

  const [palette, setPaletteEntry, resetPalette] = useChartPalette();

  const is401 = isError && error instanceof AuthError;

  const { data: auditData, isLoading: auditLoading, refetch: refetchAudit } = useQuery({
    queryKey: ['dashboard-audit'],
    queryFn: () => listAuditLogs({ page_size: 8 }),
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // Env scope comes from the URL path param (same as nodes/queries/carves).
  // The EnvSwitcher in the sidebar navigates to /_app/env/{envName} which
  // updates this param; the dashboard follows automatically.
  const { env: envParam } = useParams({ from: '/_app/env/$env' });
  const envUuids = (data?.environments ?? []).map((e) => e.uuid);
  // Resolve the env from the URL to its UUID and name for display.
  const envMeta = (data?.environments ?? []).find(
    (e) => e.name === envParam || e.uuid === envParam,
  );
  const effectiveEnv = envMeta?.uuid ?? envUuids[0] ?? '';
  const envName = envMeta?.name ?? envParam;

  // ── Recently seen nodes — pulled from the selected env, lastseen desc ─
  const { data: recentlySeenNodes, isLoading: recentlySeenLoading, refetch: refetchRecentlySeen } = useQuery({
    queryKey: ['dashboard-recently-seen', effectiveEnv],
    queryFn: () =>
      listNodes({
        env: effectiveEnv!,
        sort: 'lastseen',
        dir: 'desc',
        pageSize: 8,
      }),
    enabled: !!effectiveEnv,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Environments list (NEW) — enriches EnvStats rows with enroll_expire.
  //    May 401 / 403 for non-super-admins; we silently fall back to no expire.
  const { data: envList } = useQuery({
    queryKey: ['dashboard-env-list'],
    queryFn: listEnvironments,
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });
  const envExpireByUuid = new Map<string, string>();
  for (const e of envList ?? []) envExpireByUuid.set(e.uuid, e.enroll_expire);

  // ── Node activity series — one Redis-backed env-tiles request per env.
  //    The user picks 12h / 24h / 7d via the chart's tab row. The env
  //    dropdown (effectiveEnv, declared above) drives the chart and the
  //    recent-nodes/recently-seen-nodes sections.
  const [activityInterval, setActivityInterval] = useState<ActivityInterval>('1d');
  // The Redis day-blobs are aligned to UTC midnight, so a trailing 12h/24h
  // window almost always spans TWO calendar days. Fetching a single day made
  // the chart empty right after UTC midnight (only the current hour existed);
  // fetch 2 days and slice the trailing window below instead. 7d fetches the
  // full retention (a trailing 168h window is approximated by the trim+slice).
  const activityDays = activityInterval === '7d' ? 7 : 2;
  const activityQueries = useQueries({
    queries: envUuids.map((uuid) => ({
      queryKey: ['dashboard-env-tiles', uuid, activityDays] as const,
      queryFn: () => getEnvActivityTiles(uuid, activityDays),
      refetchInterval: 30_000,
      refetchIntervalInBackground: false,
      retry: 1,
    })),
  });
  const refetchActivityTiles = () => { activityQueries.forEach((q) => void q.refetch()); };
  // Map env UUID → its tile series (or undefined while loading).
  const tilesByUuid = new Map<string, NodeTileSeries>();
  envUuids.forEach((uuid, i) => {
    if (activityQueries[i]?.data) {
      tilesByUuid.set(uuid, activityQueries[i].data);
    }
  });
  // Build the chart series for the selected environment only.
  // The Redis day-blob is aligned to UTC midnight, so the series always has
  // 24 (or 168 for 7d) hourly buckets — but the current hour is in the
  // middle, with future hours padded as zeros. Trim at the current hour so
  // "now" is always the rightmost data point.
  const rawSeries: ActivitySeries = (() => {
    if (effectiveEnv && tilesByUuid.has(effectiveEnv)) {
      return tileSeriesToActivity(tilesByUuid.get(effectiveEnv));
    }
    return emptySeries(0);
  })();
  const tiles = effectiveEnv ? tilesByUuid.get(effectiveEnv) : undefined;
  const trimmedSeries: ActivitySeries = (() => {
    if (rawSeries.total.length === 0 || !tiles) return rawSeries;
    const startMs = Date.parse(tiles.start);
    if (Number.isNaN(startMs)) return rawSeries;
    const currentHourIdx = Math.floor((Date.now() - startMs) / 3_600_000);
    const cut = Math.max(1, Math.min(currentHourIdx + 1, rawSeries.total.length));
    const trim = (arr: number[]) => arr.slice(0, cut);
    return {
      status: trim(rawSeries.status),
      result: trim(rawSeries.result),
      config: trim(rawSeries.config),
      query: trim(rawSeries.query),
      statusError: trim(rawSeries.statusError),
      total: trim(rawSeries.total),
    };
  })();
  // Slice the trailing window (12h/24h/7d of hourly buckets) from the
  // trimmed series so the chart is a true "last N hours" view regardless of
  // where the UTC day boundary falls.
  const windowHours =
    activityInterval === '7d' ? 168 : activityInterval === '12h' ? 12 : 24;
  const chartSeries: ActivitySeries = (() => {
    if (trimmedSeries.total.length <= windowHours) return trimmedSeries;
    const slice = (arr: number[]) => arr.slice(-windowHours);
    return {
      status: slice(trimmedSeries.status),
      result: slice(trimmedSeries.result),
      config: slice(trimmedSeries.config),
      query: slice(trimmedSeries.query),
      statusError: slice(trimmedSeries.statusError),
      total: slice(trimmedSeries.total),
    };
  })();
  const [showErrorNodes, setShowErrorNodes] = useState(false);

  // ── Reported errors (24h) — status logs the fleet sent at osquery's ERROR
  //    severity, counted at ingest into the activity rollup. Always the last
  //    24 hourly buckets regardless of which interval the chart is showing,
  //    so the tile's meaning does not change when the chart selector does.
  //    Scoped to the selected environment, like every other tile fed by this
  //    series.
  const reportedErrors = trimmedSeries.statusError
    .slice(-24)
    .reduce((sum, n) => sum + n, 0);

  const activityWindowLabel =
    activityInterval === '7d'
      ? 'Last 7 days'
      : activityInterval === '12h'
        ? 'Last 12 hours'
        : 'Last 24 hours';

  const envTableRows: EnvTableEnv[] = (data?.environments ?? []).map((e) => ({
    uuid: e.uuid,
    name: e.name,
    active: e.active,
    inactive: e.inactive,
    active_queries: e.active_queries,
    active_carves: e.active_carves,
    enroll_expire: envExpireByUuid.get(e.uuid),
  }));

  // ── osquery agent versions (NEW) ──────────────────────────────────────
  const { data: versionCounts, isLoading: versionsLoading, refetch: refetchVersions } = useQuery({
    queryKey: ['dashboard-osquery-versions'],
    queryFn: getOsqueryVersionCounts,
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Active queries with live progress (NEW) ───────────────────────────
  //   Parallel one-call-per-env; flattened and sliced to 8.
  const activeQueriesPerEnv = useQueries({
    queries: (data?.environments ?? []).map((e) => ({
      queryKey: ['dashboard-active-queries', e.uuid],
      queryFn: () =>
        listQueries({ env: e.uuid, target: 'active' as const, pageSize: 10 }),
      staleTime: 30_000,
      refetchInterval: 30_000,
      refetchIntervalInBackground: false,
      retry: 1,
    })),
  });
  const envsForActive = data?.environments ?? [];
  const activeQueriesFlat: (ActiveQueryRow & { _createdAt: string })[] =
    activeQueriesPerEnv
      .flatMap((r, i) => {
        const envMeta = envsForActive[i];
        if (!envMeta || !r.data) return [];
        return r.data.items.map((q) => ({
          name: q.name,
          envName: envMeta.name,
          envUuid: envMeta.uuid,
          expected: q.expected,
          executions: q.executions,
          errors: q.errors,
          _createdAt: q.created_at,
        }));
      })
      // Newest first so the top of the panel reflects the freshest work
      .sort(
        (a, b) =>
          new Date(b._createdAt).getTime() - new Date(a._createdAt).getTime(),
      )
      .slice(0, 8);
  const refetchActiveQueries = () => { activeQueriesPerEnv.forEach((q) => void q.refetch()); };
  const activeQueriesLoading =
    activeQueriesPerEnv.length > 0 &&
    activeQueriesPerEnv.some((r) => r.isLoading);
  const featuredQuery =
    activeQueriesFlat.find((query) => query.envUuid === effectiveEnv)
    ?? activeQueriesFlat[0];

  // The carve card uses the newest record, regardless of whether it is still
  // active, so completed archives remain one click away after collection.
  const { data: recentCarvesData } = useQuery({
    queryKey: ['dashboard-recent-carves', effectiveEnv],
    queryFn: () => listCarves({
      env: effectiveEnv,
      target: 'all',
      sort: 'created',
      dir: 'desc',
      page: 1,
      pageSize: 3,
    }),
    enabled: !!effectiveEnv,
    staleTime: 30_000,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });
  const recentCarve = recentCarvesData?.items[0];

  return (
    <div className="flex flex-col gap-4 px-4 py-4 md:px-5 md:py-5 max-w-[1440px] mx-auto w-full">

      <DashboardHeader envName={envName} />

      {/* ── Top row: time-series chart (2 cols) + 2 hero KPIs stacked ───── */}
      <section
        aria-label="24-hour overview"
        aria-busy={isLoading}
        className="grid grid-cols-1 lg:grid-cols-3 gap-4"
      >
        <div className="lg:col-span-2 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[color:var(--border)]">
            <div>
              <div className="text-sm font-display font-semibold text-[color:var(--text-1)]">
                Node activity
              </div>
              <div className="mt-0.5 text-xs font-medium tabular-nums text-[color:var(--text-3)]">
                {activityWindowLabel} · per environment
              </div>
            </div>
            <div className="flex items-center gap-2">
              <RefreshButton onClick={() => void refetchActivityTiles()} isPending={activityQueries.some((q) => q.isFetching)} />
              <div className="flex items-center gap-0.5 rounded-md bg-[color:var(--bg-3)] p-0.5 text-[12px]" role="tablist" aria-label="Time range">
                <button
                  type="button"
                  role="tab"
                  aria-selected={activityInterval === '12h'}
                  onClick={() => setActivityInterval('12h')}
                  className={cn(
                    'h-7 px-2 rounded transition-colors duration-[100ms]',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
                    activityInterval === '12h'
                      ? 'font-semibold bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-[0_0_0_1px_var(--border)]'
                      : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
                  )}
                >
                  12 hours
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activityInterval === '1d'}
                  onClick={() => setActivityInterval('1d')}
                  className={cn(
                    'h-7 px-2 rounded transition-colors duration-[100ms]',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
                    activityInterval === '1d'
                      ? 'font-semibold bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-[0_0_0_1px_var(--border)]'
                      : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
                  )}
                >
                  24 hours
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activityInterval === '7d'}
                  onClick={() => setActivityInterval('7d')}
                  className={cn(
                    'h-7 px-2 rounded transition-colors duration-[100ms]',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
                    activityInterval === '7d'
                      ? 'font-semibold bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-[0_0_0_1px_var(--border)]'
                      : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
                  )}
                >
                  7 days
                </button>
              </div>
            </div>
          </div>
          <div className="p-4">
            <ChartLegend
              palette={palette}
              onChange={setPaletteEntry}
              onReset={resetPalette}
            />
            <Suspense
              fallback={(
                <div className="mt-2 min-h-[200px] animate-pulse rounded-md bg-[color:var(--bg-2)]" aria-label="Loading node activity chart" />
              )}
            >
              <ActivityLineChart
                series={chartSeries}
                intervalLabel={activityInterval === '7d' ? '7d' : activityInterval === '12h' ? '12h' : '24h'}
                palette={palette}
              />
            </Suspense>
          </div>
        </div>

        <OperationalWorkloadCards
          activeQueries={data?.total_active_queries ?? 0}
          activeCarves={data?.total_active_carves ?? 0}
          featuredQuery={featuredQuery}
          recentCarve={recentCarve}
          env={envParam}
        />
      </section>

      {/* ── Mid 4-KPI row ────────────────────────────────────────────────── */}
      <section aria-label="Environment KPIs" aria-busy={isLoading}>
        <DashboardKpiSet
          loading={isLoading || (isError && !is401)}
          activeNodes={data?.active_nodes ?? 0}
          totalNodes={data?.total_nodes ?? 0}
          inactiveNodes={data?.inactive_nodes ?? 0}
          inactiveHours={inactiveHours}
          reportedErrors={reportedErrors}
          onReportedErrorsClick={
            reportedErrors > 0 && effectiveEnv
              ? () => setShowErrorNodes(true)
              : undefined
          }
          activeQueries={data?.total_active_queries ?? 0}
          chartSeries={chartSeries}
        />
      </section>

      {/* ── Active queries with live progress ────────────────────────────── */}
      <section aria-label="Active queries" aria-busy={activeQueriesLoading}>
        <div className="rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
          <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)]">
            <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)] flex items-center gap-2">
              Active queries
              {activeQueriesFlat.length > 0 && (
                <span className="inline-flex items-center gap-2">
                  <StatusBadge variant="signal" label="Live" live />
                  <span className="text-xs font-medium tabular-nums text-[color:var(--text-3)]">
                    {activeQueriesFlat.length}
                  </span>
                </span>
              )}
            </h2>
            <div className="flex items-center gap-2">
              <RefreshButton onClick={() => refetchActiveQueries()} isPending={activeQueriesPerEnv.some((q) => q.isFetching)} />
              {effectiveEnv && (
                <Link
                  to="/_app/env/$env/queries"
                  params={{ env: effectiveEnv }}
              className="text-xs font-medium text-[color:var(--text-link)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--accent)]"
                >
                  View all →
                </Link>
              )}
            </div>
          </div>
          <div>
            {activeQueriesLoading && activeQueriesFlat.length === 0 ?(
              Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="grid grid-cols-12 gap-3 items-center px-4 h-11 border-b border-[color:var(--border)] last:border-0"
                >
                  <Skeleton className="col-span-5 h-3" />
                  <Skeleton className="col-span-2 h-4 rounded-full" />
                  <Skeleton className="col-span-2 h-3" />
                  <Skeleton className="col-span-2 h-1.5 rounded-full" />
                  <Skeleton className="col-span-1 h-3" />
                </div>
              ))
            ) : activeQueriesFlat.length === 0 ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No active queries.
              </div>
            ) : (
              activeQueriesFlat.map((row) => (
                <ActiveQueryRowItem
                  key={`${row.envUuid}-${row.name}`}
                  row={row}
                  elapsed={formatRelative(row._createdAt)}
                />
              ))
            )}
          </div>
        </div>
      </section>

      {/* ── Bottom-mid: Environments (2/3) + Top platforms (1/3) ─────────── */}
      <section aria-label="Environments" aria-busy={isLoading} className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Env table spans 2 columns at lg+ */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
              Environments
            </h2>
            <div className="flex items-center gap-2">
              {data && (
                <span className="text-xs text-[color:var(--text-3)] tabular-nums">
                  {data.environments.length} env{data.environments.length !== 1 ? 's' : ''}
                </span>
              )}
              <RefreshButton onClick={() => void refetch()} isPending={isLoading} />
            </div>
          </div>

          {isLoading ? (
            <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-11 items-center border-b border-[color:var(--border)] last:border-0"
                >
                  <Skeleton className="h-3 w-32" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-16 justify-self-end" />
                  <Skeleton className="h-3 w-10 justify-self-end" />
                </div>
              ))}
            </div>
          ) : isError ? (
            <EmptyState
              icon={
                <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10 text-[color:var(--danger)]">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 8v4M12 16h.01" />
                </svg>
              }
              title={is401 ? 'Session expired. Please log in again.' : 'Failed to load stats.'}
              description={is401 ? undefined : 'Check the API connection and try again.'}
              action={
                !is401 ? (
                  <button
                    onClick={() => void refetch()}
                    className="text-sm font-medium text-[color:var(--signal)] hover:underline"
                  >
                    Retry
                  </button>
                ) : undefined
              }
            />
          ) : data?.environments.length === 0 ? (
            <EmptyState
              icon={
                <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10">
                  <path d="M3 12h6v9H3zM15 3h6v9h-6zM3 3h6v6H3zM15 15h6v6h-6z" />
                </svg>
              }
              title="No environments configured."
              description="Contact your administrator to set up an environment."
            />
          ) : (
            <EnvTable envs={envTableRows} />
          )}
        </div>

        {/* Top platforms — right column */}
        <div>
          {isLoading || isError ? (
            <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-5 min-h-[160px]">
              <Skeleton className="h-4 w-32 mb-3" />
              <Skeleton className="h-2 w-full rounded-full mb-3" />
              <div className="space-y-1.5">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-3 w-full" />
                ))}
              </div>
            </div>
          ) : data ? (
            <TopPlatformsPanel counts={data.platform_counts} total={data.total_nodes} />
          ) : null}
        </div>
      </section>

      {/* ── osquery versions panel ───────────────────────────────────────── */}
      <section aria-label="osquery agent versions">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
            osquery agent versions
          </h2>
          <RefreshButton onClick={() => void refetchVersions()} isPending={versionsLoading} />
        </div>
        {versionsLoading ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-5 min-h-[160px]">
            <Skeleton className="h-4 w-32 mb-3" />
            <div className="space-y-1.5">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-3 w-full" />
              ))}
            </div>
          </div>
        ) : (
          <OsqueryVersionsPanel versions={versionCounts ?? []} />
        )}
      </section>

      {/* ── Activity feed + Endpoint health ────────────────────────────── */}
      <section aria-label="Recent activity and endpoint health" className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Activity feed — 2/3 width on md+ */}
        <div className="md:col-span-2 rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
            <span className="text-[13px] font-semibold font-display text-[color:var(--text-1)]">
              Recent activity
            </span>
            <div className="flex items-center gap-2">
              <RefreshButton onClick={() => void refetchAudit()} isPending={auditLoading} />
              <Link
                to="/_app/audit"
                className="text-xs font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
              >
                View all →
              </Link>
            </div>
          </div>
          <div className="px-4 flex-1">
            {auditLoading ? (
              Array.from({ length: 5 }).map((_, i) => <ActivityRowSkeleton key={i} />)
            ) : !auditData?.items.length ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No audit events yet.
              </div>
            ) : (
              auditData.items.map((entry) => (
                <ActivityRow
                  key={entry.id}
                  username={entry.username}
                  service={entry.service}
                  logType={entry.log_type}
                  line={entry.line}
                  createdAt={entry.created_at}
                />
              ))
            )}
          </div>
        </div>

        <EndpointHealthPanel
          tiles={tiles}
          intervalLabel={activityWindowLabel}
          isLoading={activityQueries.some((q) => q.isLoading) || (!effectiveEnv && isLoading)}
          isFetching={activityQueries.some((q) => q.isFetching)}
          hasEnvironment={!!effectiveEnv}
          onRefresh={() => void refetchActivityTiles()}
        />
      </section>

      {/* ── Recently seen nodes ─────────────────────────────────────────── */}
      <section aria-label="Recently seen nodes" aria-busy={recentlySeenLoading}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
            Recently seen nodes
          </h2>
          <div className="flex items-center gap-2">
            <RefreshButton onClick={() => void refetchRecentlySeen()} isPending={recentlySeenLoading} />
            {effectiveEnv && (
              <Link
                to="/_app/env/$env/nodes"
                params={{ env: effectiveEnv }}
                className="text-xs font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
              >
                View all →
              </Link>
            )}
          </div>
        </div>
        {!effectiveEnv && !isLoading ? (
          <EmptyState
            icon={
              <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10">
                <path d="M3 12h6v9H3zM15 3h6v9h-6zM3 3h6v6H3zM15 15h6v6h-6z" />
              </svg>
            }
            title="No environment available."
            description="Recently seen nodes appear once you have at least one environment."
          />
        ) : recentlySeenLoading || isLoading ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
            {Array.from({ length: 5 }).map((_, i) => (
              <div
                key={i}
                className="grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-11 items-center border-b border-[color:var(--border)] last:border-0"
              >
                <Skeleton className="h-3 w-36" />
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-3 w-12" />
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-3 w-8" />
                <Skeleton className="h-3 w-12 justify-self-end" />
              </div>
            ))}
          </div>
        ) : !recentlySeenNodes?.items.length ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] py-8 text-center text-sm text-[color:var(--text-3)]">
            No nodes have reported in yet.
          </div>
        ) : (
          <RecentlySeenNodesTable
            envUuid={effectiveEnv!}
            nodes={recentlySeenNodes.items.map((n) => ({
              uuid: n.uuid,
              hostname: n.hostname,
              localname: n.localname,
              platform: n.platform,
              osquery_version: n.osquery_version,
              ip_address: n.ip_address,
              last_seen: n.last_seen,
              env: n.environment,
            }))}
          />
        )}
      </section>

      {showErrorNodes && effectiveEnv && (
        <ErrorNodesDialog env={effectiveEnv} onClose={() => setShowErrorNodes(false)} />
      )}
    </div>
  );
}
