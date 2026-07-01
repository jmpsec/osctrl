import { useState, useRef, useEffect, useMemo } from 'react';
import { useParams, Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getNode, listNodeLogs, deleteNode } from '$/api/nodes';
import { getMe } from '$/api/users';
import { listEnvironments } from '$/api/environments';
import {
  getNodeActivity,
  getNodeActivityTiles,
  type ActivityInterval,
  type NodeActivityBucket,
  type NodeTileSeries,
  type TileCategory,
  TILE_CATEGORIES,
  TILE_CATEGORY_LABELS,
  tileLastSeen,
  tileCategoryTotal,
} from '$/api/stats';
import { AuthError } from '$/api/client';
import type { NodeLogEntry } from '$/api/types';
import { formatRelative, formatAbsolute, isWithinHours, formatBucketAgo } from '$/lib/time';
import { cn } from '$/lib/cn';
import { StatusPip } from '$/components/data/StatusPip';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { SearchInput } from '$/components/data/SearchInput';

// NodeHeatmapBucket is the merged per-node activity grid the heatmap renders.
// status/result/query come from the DB-backed logging buckets (full history,
// requested at hourly granularity); config comes from the Redis rollup series
// (hourly, aligned by timestamp). carve is intentionally absent — it is
// replaced by config, which is the rarer-of-the-two-but-now-tracked endpoint.
interface NodeHeatmapBucket {
  bucket_start: string;
  status: number;
  result: number;
  query: number;
  config: number;
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

type Tab = 'details' | 'status-logs' | 'result-logs';

// ---------------------------------------------------------------------------
// Detail field groups
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// KvGrid — compact 2-or-3-column key/value grid that replaces the legacy
// FieldGroup row-stack. Each item declares a label + value; `wide: true`
// spans the row so long UUIDs / hashes stay readable. The grid uses cell
// borders that clip to the rounded container (overflow-hidden) — same
// ruled-table treatment used in the brand guide spec tables.
// ---------------------------------------------------------------------------

type KvItem = {
  label: string;
  value: React.ReactNode;
  wide?: boolean;
};

function KvGrid({
  title,
  items,
  cols = 2,
}: {
  title: string;
  items: KvItem[];
  cols?: 2 | 3;
}) {
  return (
    <section className="mb-5">
      <h3 className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-2 px-1">
        {title}
      </h3>
      <div
        className={cn(
          'border border-[color:var(--border)] rounded-lg overflow-hidden',
          'bg-[color:var(--bg-1)]',
          cols === 3
            ? 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3'
            : 'grid grid-cols-1 sm:grid-cols-2',
        )}
      >
        {items.map(({ label, value, wide }) => (
          <div
            key={label}
            className={cn(
              'px-4 py-2 border-b border-r border-[color:var(--border)]',
              'last:border-b-0',
              wide && 'sm:col-span-2',
              wide && cols === 3 && 'lg:col-span-3',
            )}
          >
            <dt className="text-[10px] font-mono-tabular uppercase tracking-[0.1em] text-[color:var(--text-3)] mb-0.5">
              {label}
            </dt>
            <dd className="text-xs text-[color:var(--text-1)] break-all">{value}</dd>
          </div>
        ))}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// HeroStrip — 5 load-bearing signals above the tabs (status, platform,
// osquery version, last seen, data received). Always visible regardless of
// active tab so an operator can take in the node's "is it healthy / what is
// it / when did I last hear from it" facts in one glance.
// ---------------------------------------------------------------------------

function fmtBytes(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)} GB`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)} KB`;
  return `${n} B`;
}

interface HeroStripProps {
  node: {
    platform: string;
    platform_version: string;
    osquery_version: string;
    last_seen: string;
    bytes_received: number;
  };
  isActive: boolean;
}

function HeroStrip({ node, isActive }: HeroStripProps) {
  const cells: { label: string; value: React.ReactNode }[] = [
    {
      label: 'Status',
      value: (
        <span className="inline-flex items-center gap-1.5">
          <StatusPip variant={isActive ? 'success' : 'dim'} />
          <span
            className={cn(
              'text-xs font-medium',
              isActive ? 'text-[color:var(--success)]' : 'text-[color:var(--text-3)]',
            )}
          >
            {isActive ? 'Active' : 'Inactive'}
          </span>
        </span>
      ),
    },
    {
      label: 'Platform',
      value: (
        <span>
          <span className="text-xs text-[color:var(--text-1)] font-medium capitalize">
            {node.platform}
          </span>
          {node.platform_version && (
            <span className="text-[10px] text-[color:var(--text-3)] ml-1 font-mono-tabular">
              {node.platform_version}
            </span>
          )}
        </span>
      ),
    },
    {
      label: 'osquery',
      value: (
        <span className="text-xs font-mono-tabular text-[color:var(--text-1)]">
          {node.osquery_version}
        </span>
      ),
    },
    {
      label: 'Last seen',
      value: (
        <span className="tnum text-xs">
          <span className="text-[color:var(--text-1)]" title={node.last_seen}>
            {formatRelative(node.last_seen)}
          </span>
          <br />
          <span className="text-[10px] text-[color:var(--text-3)] font-mono-tabular">
            {formatAbsolute(node.last_seen)}
          </span>
        </span>
      ),
    },
    {
      label: 'Data received',
      value: (
        <span className="text-xs font-mono-tabular tnum text-[color:var(--text-1)]">
          {fmtBytes(node.bytes_received)}
        </span>
      ),
    },
  ];

  return (
    <div
      className={cn(
        'mb-5 grid border border-[color:var(--border)] rounded-lg overflow-hidden',
        'grid-cols-2 sm:grid-cols-3 lg:grid-cols-5',
        'bg-[color:var(--bg-1)]',
      )}
    >
      {cells.map(({ label, value }) => (
        <div
          key={label}
          className="px-4 py-3 border-r border-b border-[color:var(--border)] last:border-r-0"
        >
          <div className="text-[10px] font-mono-tabular uppercase tracking-[0.12em] text-[color:var(--text-3)] mb-1">
            {label}
          </div>
          <div>{value}</div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Log viewer
// ---------------------------------------------------------------------------

function LogEntry({
  entry,
  type,
  onSearchColumn,
}: {
  entry: NodeLogEntry;
  type: 'status' | 'result';
  onSearchColumn?: (queryName: string, column: string, value: string) => void;
}) {
  // Try to parse a timestamp from common fields
  const timestamp =
    (entry['created_at'] as string) ??
    (entry['calendarTime'] as string) ??
    (entry['unixTime'] != null ? new Date(Number(entry['unixTime']) * 1000).toISOString() : null);

  // For result rows, pull the structured fields if present. When `columns` is
  // an object we render each [key]: [value] as its own row with a hover-only
  // 🔍 button that builds a "find this everywhere" query (IR workflow).
  const isResult = type === 'result';
  const columnsRaw = isResult ? entry['columns'] : undefined;
  const columns =
    isResult && columnsRaw && typeof columnsRaw === 'object' && !Array.isArray(columnsRaw)
      ? (columnsRaw as Record<string, unknown>)
      : null;
  const queryName =
    typeof entry['name'] === 'string' ? (entry['name'] as string) : '';
  const action =
    typeof entry['action'] === 'string' ? (entry['action'] as string) : '';

  if (isResult && columns) {
    return (
      <div className="border-b border-[color:var(--border)] py-2 px-4">
        <div className="flex items-center gap-3 font-mono-tabular text-[11px] text-[color:var(--text-3)] mb-1.5">
          {queryName && (
            <span className="text-[color:var(--signal)] font-medium">{queryName}</span>
          )}
          {action && <span className="text-[color:var(--text-2)]">{action}</span>}
          {timestamp && (
            <span className="ml-auto tnum" title={timestamp}>
              {formatRelative(timestamp)}
            </span>
          )}
        </div>
        <div className="rounded border border-[color:var(--border)] overflow-hidden">
          {Object.entries(columns).map(([col, val]) => {
            const valueStr =
              val == null
                ? ''
                : typeof val === 'string'
                  ? val
                  : JSON.stringify(val);
            return (
              <div
                key={col}
                className={cn(
                  'group flex items-start gap-2 px-3 py-1 text-xs font-mono-tabular',
                  'border-b border-[color:var(--border)] last:border-b-0',
                  'hover:bg-[color:var(--bg-2)] transition-colors',
                )}
              >
                <span className="text-[color:var(--text-3)] min-w-[140px] flex-shrink-0">
                  {col}
                </span>
                <span className="text-[color:var(--text-1)] break-all flex-1">
                  {valueStr || <span className="text-[color:var(--text-3)] italic">empty</span>}
                </span>
                {onSearchColumn && valueStr && (
                  <button
                    type="button"
                    aria-label={`Search ${col} across env`}
                    title={`Search this ${col} value across the env`}
                    onClick={() => onSearchColumn(queryName, col, valueStr)}
                    className={cn(
                      'flex-shrink-0 px-1 rounded',
                      'text-[color:var(--text-3)] hover:text-[color:var(--signal)]',
                      'opacity-0 group-hover:opacity-100 transition-opacity',
                      'focus-visible:opacity-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                    )}
                  >
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      className="w-3.5 h-3.5"
                      aria-hidden
                    >
                      <circle cx="11" cy="11" r="8" />
                      <path d="M21 21l-4.35-4.35" />
                    </svg>
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  const message = JSON.stringify(entry, null, 2);

  return (
    <div className="border-b border-[color:var(--border)] py-2 px-4 group">
      {timestamp && (
        <div className="font-mono-tabular text-xs text-[color:var(--text-3)] mb-1">
          {formatAbsolute(timestamp as string)}
        </div>
      )}
      <pre className="text-xs text-[color:var(--text-2)] font-mono-tabular whitespace-pre-wrap break-all leading-relaxed">
        {message}
      </pre>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SQL builder for the "search across env" IR workflow.
// Maps a query name → likely osquery source table by suffix-matching against
// the starter sample set in $/api/samples. When we can't guess, we fall back
// to a placeholder SELECT the operator can edit before submit.
// ---------------------------------------------------------------------------

function buildSearchSQL(
  queryName: string,
  column: string,
  value: string,
): { sql: string; label: string } {
  const tableGuess = (() => {
    const n = queryName.toLowerCase();
    if (n.includes('processes')) return 'processes';
    if (n.includes('users')) return 'users';
    if (n.includes('listening_ports')) return 'listening_ports';
    if (n.includes('logged_in')) return 'logged_in_users';
    if (n.includes('cert')) return 'certificates';
    if (n.includes('crontab')) return 'crontab';
    if (n.includes('systemd')) return 'systemd_units';
    if (n.includes('launchd')) return 'launchd';
    if (n.includes('startup')) return 'startup_items';
    if (n.includes('scheduled_task')) return 'scheduled_tasks';
    if (n.includes('services_windows') || n.includes('service')) return 'services';
    if (n.includes('packages')) return 'deb_packages';
    if (n.includes('apps')) return 'apps';
    if (n.includes('programs')) return 'programs';
    if (n.includes('hosts')) return 'etc_hosts';
    if (n.includes('uptime')) return 'uptime';
    if (n.includes('kernel')) return 'kernel_info';
    if (n.includes('os_version') || n.includes('host_overview')) return 'os_version';
    return null;
  })();
  const escapedValue = value.replace(/'/g, "''");
  const truncated = value.slice(0, 24);
  if (tableGuess) {
    return {
      sql: `SELECT * FROM ${tableGuess} WHERE ${column} LIKE '%${escapedValue}%';`,
      label: `find ${column}~${truncated} (${tableGuess})`,
    };
  }
  return {
    sql:
      `-- adjust FROM clause; column "${column}" came from result "${queryName}"\n` +
      `SELECT * FROM <TABLE> WHERE ${column} LIKE '%${escapedValue}%';`,
    label: `find ${column}~${truncated}`,
  };
}

function LogsTab({
  env,
  uuid,
  type,
  onSearchColumn,
}: {
  env: string;
  uuid: string;
  type: 'status' | 'result';
  onSearchColumn?: (queryName: string, column: string, value: string) => void;
}) {
  const accumulatedRef = useRef<NodeLogEntry[]>([]);
  const sinceRef = useRef<string | undefined>(undefined);

  // Live (already-debounced by SearchInput) free-text search. Empty string =
  // "no filter". When this changes we drop the accumulator and re-fetch from
  // scratch so the page reflects only matching rows.
  const [searchQ, setSearchQ] = useState('');

  // Reset accumulator + search when tab type changes
  useEffect(() => {
    accumulatedRef.current = [];
    sinceRef.current = undefined;
    setSearchQ('');
  }, [type]);

  // Drop the running accumulator + since cursor whenever the (debounced)
  // search term changes, so the next query starts fresh.
  useEffect(() => {
    accumulatedRef.current = [];
    sinceRef.current = undefined;
  }, [searchQ]);

  const { data, isLoading, isError, error, isFetching } = useQuery({
    queryKey: ['node-logs', env, uuid, type, searchQ],
    queryFn: async () => {
      const res = await listNodeLogs(
        env,
        uuid,
        type,
        100,
        sinceRef.current,
        searchQ || undefined,
      );
      if (res.items.length > 0) {
        // API returns newest-first (ORDER BY created_at DESC); items[0] is the most recent.
        const newest = res.items[0];
        const ts =
          (newest['created_at'] as string | undefined) ??
          (newest['calendarTime'] as string | undefined);
        if (ts) sinceRef.current = ts;
        // Prepend new entries (newest-first) ahead of already-accumulated ones
        accumulatedRef.current = [...res.items, ...accumulatedRef.current];
      }
      return { ...res, items: accumulatedRef.current };
    },
    staleTime: 10_000,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });

  const items = data?.items ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Search header — debounced via SearchInput's internal 300ms timer */}
      <div className="px-4 py-2 border-b border-[color:var(--border)]">
        <SearchInput
          id={`node-logs-search-${type}`}
          value={searchQ}
          onChange={setSearchQ}
          placeholder={`Search ${type} logs…`}
        />
      </div>

      {isLoading ? (
        <div className="p-4 space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : isError ? (
        <EmptyState
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4M12 16h.01" />
            </svg>
          }
          title={error instanceof Error ? error.message : 'Failed to load logs'}
        />
      ) : items.length === 0 ? (
        <EmptyState
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M9 12h6M9 16h6M9 8h6M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z" />
            </svg>
          }
          title={searchQ ? `No ${type} logs match “${searchQ}”.` : 'No log entries.'}
        />
      ) : (
        <div className="overflow-auto" data-stale={isFetching ? 'true' : undefined}>
          {items.map((entry, i) => (
            <LogEntry
              key={(entry['created_at'] as string | undefined) ?? `idx-${i}`}
              entry={entry}
              type={type}
              onSearchColumn={onSearchColumn}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NodeDetailPage
// ---------------------------------------------------------------------------

const TABS = [
  { id: 'details' as Tab, label: 'Details' },
  { id: 'status-logs' as Tab, label: 'Status logs' },
  { id: 'result-logs' as Tab, label: 'Result logs' },
] as const;

export function NodeDetailPage() {
  const { env, uuid } = useParams({ from: '/_app/env/$env/nodes/$uuid' as const });
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [activityInterval, setActivityInterval] = useState<ActivityInterval>('6h');
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  function handleTabKeyDown(e: React.KeyboardEvent) {
    const currentIndex = TABS.findIndex((t) => t.id === activeTab);
    let nextIndex = currentIndex;
    if (e.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + TABS.length) % TABS.length;
    else if (e.key === 'ArrowRight') nextIndex = (currentIndex + 1) % TABS.length;
    else return;
    e.preventDefault();
    const nextTab = TABS[nextIndex];
    setActiveTab(nextTab.id);
    tabRefs.current[nextIndex]?.focus();
  }

  const { data: node, isLoading, isError, error } = useQuery({
    queryKey: ['node', env, uuid],
    queryFn: () => getNode(env, uuid),
    staleTime: 10_000,
  });

  // Decide whether to show destructive actions (Delete). The server
  // requires AdminLevel on the env for DELETE; we mirror that gate
  // in the UI so non-admins don't see a button that would 403.
  // Super-admins bypass; env-scoped admins get it on their env(s).
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
  });
  const { data: envs } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
  });
  const envUuid = envs?.find((e) => e.name === env)?.uuid;
  const canDeleteNode =
    me?.admin === true ||
    (envUuid !== undefined && me?.permissions?.[envUuid]?.admin === true);

  // Archive the current node. The backend's POST /nodes/{env}/delete
  // handler maps to ArchiveDeleteByUUID — it always snapshots into the
  // archive table BEFORE removing the live row, so every removal goes
  // through the archive. We deliberately only expose this single op
  // (no separate hard-delete) so accidental clicks remain forensically
  // recoverable. Until an /archive page lands the recovery is "query
  // archive_osquery_nodes" — but the snapshot exists.
  const qc = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const archiveMut = useMutation({
    mutationFn: () => deleteNode(env, uuid),
    onSuccess: () => {
      setActionError(null);
      // Bust the listing caches so the Nodes table reflects removal
      // before we land back on it.
      void qc.invalidateQueries({ queryKey: ['nodes', env] });
      void qc.invalidateQueries({ queryKey: ['node', env, uuid] });
      void navigate({ to: '/_app/env/$env/nodes', params: { env } });
    },
    onError: (err) =>
      setActionError(err instanceof Error ? err.message : 'Action failed'),
  });

  function handleArchive() {
    if (!confirm(`Archive node ${node?.hostname ?? uuid}?\n\nThe node is snapshotted into the archive table and removed from the active list. A forensic record is retained.`)) {
      return;
    }
    archiveMut.mutate();
  }

  // Node-scoped activity heatmap — now embedded in the default Details view.
  // Keep the polling scoped to the Details tab so switching into raw log views
  // does not leave a background refresh loop running for an off-screen chart.
  // DB-backed per-node activity, requested at HOURLY granularity so it can be
  // merged with the hourly Redis config series below. status/result/query
  // keep their full history from the logging tables; carve is dropped in
  // favor of config (see mergeNodeActivityBuckets).
  // Fixed 24-column grid: the DB bucket size scales with the window so the
  // heatmap always renders 24 squares regardless of the selected interval.
  const activityBucketSeconds =
    (NODE_INTERVAL_HOURS[activityInterval] * 3600) / NODE_ACTIVITY_COLUMNS;
  const { data: activityBuckets = [], isLoading: activityLoading } = useQuery({
    queryKey: ['node-activity', env, uuid, activityInterval],
    queryFn: () => getNodeActivity(env, uuid, activityInterval, activityBucketSeconds),
    staleTime: 30_000,
    refetchInterval: 30_000,
    enabled: activeTab === 'details',
  });

  // Redis-backed per-endpoint series (config + read/write split). Hourly; the
  // window tracks the heatmap interval so config aligns with the DB buckets.
  const daysForInterval = Math.max(
    1,
    Math.ceil(NODE_INTERVAL_HOURS[activityInterval] / 24),
  );
  const { data: activityTiles, isLoading: tilesLoading } = useQuery({
    queryKey: ['node-activity-tiles', env, uuid, activityInterval],
    queryFn: () => getNodeActivityTiles(env, uuid, daysForInterval),
    staleTime: 30_000,
    refetchInterval: 30_000,
    enabled: activeTab === 'details',
  });

  // Fixed 24h readout for the per-endpoint last-seen panel (independent of the
  // heatmap's interval so it always reflects the last day).
  const { data: activityTiles24h, isLoading: tiles24hLoading } = useQuery({
    queryKey: ['node-activity-tiles-24h', env, uuid],
    queryFn: () => getNodeActivityTiles(env, uuid, 1),
    staleTime: 30_000,
    refetchInterval: 30_000,
    enabled: activeTab === 'details',
  });

  // Merge the hourly DB buckets (status/result/query, with history) with the
  // hourly Redis config series (aligned by timestamp) into the grid the
  // heatmap renders. Config hours outside the Redis window read as 0.
  const heatmapBuckets = useMemo(
    () => mergeNodeActivityBuckets(activityBuckets, activityTiles),
    [activityBuckets, activityTiles],
  );

  // IR workflow: clicking the 🔍 button on a result-log row hands an operator
  // a prefilled query-run form. SQL is best-effort from buildSearchSQL; when
  // the table can't be guessed the operator edits the placeholder.
  function onSearchColumn(queryName: string, column: string, value: string) {
    const { sql, label } = buildSearchSQL(queryName, column, value);
    void navigate({
      to: '/_app/env/$env/queries/new',
      params: { env },
      search: { sql, name: label },
    });
  }

  // Redirect to login on 401
  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const isActive = node ? isWithinHours(node.last_seen, 24) : false;

  return (
    <div className="flex flex-col h-full min-h-0 px-6 py-4 max-w-5xl mx-auto w-full">
      {/* ── Back link ── */}
      <div className="mb-4">
        <Link
          to="/_app/env/$env/nodes"
          params={{ env }}
          className={cn(
            'inline-flex items-center gap-1 text-sm text-[color:var(--text-3)]',
            'hover:text-[color:var(--text-1)] transition-colors',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)] rounded',
          )}
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M15 18l-6-6 6-6" />
          </svg>
          Back to nodes
        </Link>
      </div>

      {/* ── Header ── */}
      <div className="mb-6 flex items-start gap-3">
        {isLoading ? (
          <div className="flex-1 space-y-2">
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-48" />
          </div>
        ) : node ? (
          <>
            <StatusPip
              variant={isActive ? 'success' : 'dim'}
              className="mt-1.5"
            />
            <div className="flex-1 min-w-0">
              <h1 className="font-display text-2xl font-bold text-[color:var(--text-1)] leading-tight">
                {node.hostname}
              </h1>
              <p className="font-mono-tabular text-xs text-[color:var(--text-3)] mt-0.5">
                {node.uuid}
              </p>
            </div>
            {/* Single-node action toolbar — Archive + Refresh + Delete.
                Archive routes through the same DELETE endpoint with
                archive=true, which the server gates on env-admin —
                so the button hides for non-admins same as Delete. */}
            <div className="flex items-center gap-2 flex-shrink-0">
              {/* Single archive action — no separate hard-delete button.
                  Archive snapshots the node into archive_osquery_nodes
                  before removing the live row, so every removal is
                  forensically recoverable. The two-button shape that
                  used to live here looked like soft vs hard but mapped
                  to the same backend op, which read as misleading. If
                  a true hard-delete is ever needed it should land as a
                  separate package-level call gated behind a stronger
                  confirmation. */}
              {canDeleteNode && (
                <button
                  type="button"
                  aria-label="Archive this node"
                  onClick={handleArchive}
                  disabled={archiveMut.isPending}
                  className={cn(
                    'px-3 py-1.5 text-xs font-medium rounded',
                    'border border-[color:var(--danger)] text-[color:var(--danger)]',
                    'hover:bg-[color:var(--danger)] hover:text-white',
                    'transition-colors',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                  )}
                >
                  {archiveMut.isPending ? 'Archiving…' : 'Archive'}
                </button>
              )}
            </div>
            {actionError && (
              <div
                role="alert"
                className="mt-2 w-full text-xs text-[color:var(--danger)] font-mono-tabular"
              >
                {actionError}
              </div>
            )}
          </>
        ) : isError ? (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title={error instanceof Error ? error.message : 'Failed to load node'}
          />
        ) : null}
      </div>

      {/* ── Hero strip — load-bearing signals above the tabs ── */}
      {node && !isLoading && <HeroStrip node={node} isActive={isActive} />}
      {isLoading && (
        <div className="mb-5 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 border border-[color:var(--border)] rounded-lg overflow-hidden">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="px-4 py-3 border-r border-[color:var(--border)]">
              <Skeleton className="h-3 w-12 mb-2" />
              <Skeleton className="h-4 w-20" />
            </div>
          ))}
        </div>
      )}

      {/* ── Tabs ── */}
      <div className="border-b border-[color:var(--border)] mb-4">
        <nav
          role="tablist"
          aria-label="Node sections"
          className="flex gap-1 -mb-px"
          onKeyDown={handleTabKeyDown}
        >
          {TABS.map(({ id, label }, idx) => (
            <button
              key={id}
              ref={(el) => { tabRefs.current[idx] = el; }}
              type="button"
              role="tab"
              id={`tab-${id}`}
              aria-selected={activeTab === id}
              aria-controls={`panel-${id}`}
              tabIndex={activeTab === id ? 0 : -1}
              onClick={() => setActiveTab(id)}
              className={cn(
                'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
                'rounded-t',
                activeTab === id
                  ? 'border-[color:var(--signal)] text-[color:var(--text-1)]'
                  : 'border-transparent text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:border-[color:var(--border)]',
              )}
            >
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Tab panels ── */}
      <div
        role="tabpanel"
        id={`panel-${activeTab}`}
        aria-labelledby={`tab-${activeTab}`}
        className="flex-1 overflow-auto min-h-0"
      >
        {activeTab === 'details' && node && (() => {
          // Pull the parsed system_info enrichment that the API now exposes
          // (pkg/types/node_view.go). When the node has no raw_enrollment or
          // the parse failed, every sub-field is undefined and the Hardware
          // section is omitted entirely below.
          const sys = node.system_info?.system;
          const bios = node.system_info?.bios;

          // Memory comes back from the DB as a string of raw bytes — turn
          // it into "30.8 GiB" for the operator. Falls back to the raw
          // string when parsing fails so we never hide bad data silently.
          const memoryDisplay = (() => {
            const n = Number(node.memory);
            if (!n || Number.isNaN(n)) return node.memory || '—';
            const gib = n / 1024 ** 3;
            return `${gib.toFixed(1)} GiB`;
          })();

          const hardwareItems: KvItem[] = [
            { label: 'Vendor', value: sys?.hardware_vendor ?? '—' },
            { label: 'Model', value: sys?.hardware_model ?? '—' },
            { label: 'CPU type', value: sys?.cpu_type ?? '—' },
            {
              label: 'Physical cores',
              value: (
                <span className="font-mono-tabular tnum">
                  {sys?.cpu_physical_cores ?? '—'}
                </span>
              ),
            },
            {
              label: 'Logical cores',
              value: (
                <span className="font-mono-tabular tnum">
                  {sys?.cpu_logical_cores ?? '—'}
                </span>
              ),
            },
            { label: 'BIOS vendor', value: bios?.vendor ?? '—' },
            { label: 'BIOS version', value: bios?.version ?? '—' },
            { label: 'BIOS date', value: bios?.date ?? '—' },
          ].filter((row) => row.value !== '—');

          return (
            <>
              <div className="mb-5">
                <NodeActivityHeatmap
                  interval={activityInterval}
                  buckets={heatmapBuckets}
                  onIntervalChange={setActivityInterval}
                  isLoading={activityLoading || tilesLoading}
                />
              </div>

              <div className="mb-5">
                <NodeEndpointLastSeen
                  series={activityTiles24h}
                  isLoading={tiles24hLoading}
                />
              </div>

              <KvGrid
                title="Identity"
                items={[
                  { label: 'Hostname', value: node.hostname },
                  { label: 'Local name', value: node.localname || '—' },
                  {
                    label: 'IP address',
                    value: <span className="font-mono-tabular text-xs">{node.ip_address}</span>,
                  },
                  { label: 'Username', value: node.username || '—' },
                  { label: 'Environment', value: node.environment },
                  { label: 'osquery user', value: node.osquery_user || '—' },
                  {
                    label: 'UUID',
                    value: (
                      <span className="font-mono-tabular text-[color:var(--signal)] text-xs break-all">
                        {node.uuid}
                      </span>
                    ),
                    wide: true,
                  },
                ]}
              />

              <KvGrid
                title="System"
                items={[
                  { label: 'CPU', value: <span className="text-xs">{node.cpu || '—'}</span> },
                  {
                    label: 'Memory',
                    value: (
                      <span className="font-mono-tabular tnum text-xs">{memoryDisplay}</span>
                    ),
                  },
                  { label: 'Platform', value: node.platform },
                  {
                    label: 'Platform version',
                    value: (
                      <span className="font-mono-tabular text-xs">
                        {node.platform_version || '—'}
                      </span>
                    ),
                  },
                  {
                    label: 'osquery version',
                    value: (
                      <span className="font-mono-tabular text-xs">{node.osquery_version}</span>
                    ),
                  },
                  {
                    label: 'Hardware serial',
                    value: (
                      <span className="font-mono-tabular text-xs text-[color:var(--text-2)]">
                        {node.hardware_serial || '—'}
                      </span>
                    ),
                  },
                  {
                    label: 'Config hash',
                    value: (
                      <span className="font-mono-tabular text-xs text-[color:var(--text-3)] break-all">
                        {node.config_hash || '—'}
                      </span>
                    ),
                    wide: true,
                  },
                  {
                    label: 'Daemon hash',
                    value: (
                      <span className="font-mono-tabular text-xs text-[color:var(--text-3)] break-all">
                        {node.daemon_hash || '—'}
                      </span>
                    ),
                    wide: true,
                  },
                ]}
              />

              {/* Hardware — only rendered when raw_enrollment had a parseable
                  system_info block. Three-column grid since the items are
                  short labels. */}
              {hardwareItems.length > 0 && (
                <KvGrid title="Hardware" items={hardwareItems} cols={3} />
              )}

              <KvGrid
                title="Lifecycle"
                items={[
                  {
                    label: 'First seen',
                    value: (
                      <span className="font-mono-tabular tnum text-xs">
                        {formatAbsolute(node.created_at)}
                      </span>
                    ),
                  },
                  {
                    label: 'Data received',
                    value: (
                      <span className="font-mono-tabular tnum text-xs">
                        {node.bytes_received.toLocaleString()} B
                      </span>
                    ),
                  },
                ]}
              />
            </>
          );
        })()}

        {activeTab === 'details' && isLoading && (
          <div className="space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        )}

        {activeTab === 'status-logs' && (
          <LogsTab env={env} uuid={uuid} type="status" />
        )}

        {activeTab === 'result-logs' && (
          <LogsTab
            env={env}
            uuid={uuid}
            type="result"
            onSearchColumn={onSearchColumn}
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// NodeActivityHeatmap — 4-row strip showing what THIS node has been doing.
//
// Rows: status / result / query / config. Intensity uses per-row quantile
// breaks over the non-zero values so a single outlier bucket can't wash out
// the smaller bumps. Hover surfaces the per-bucket counts via the title attr.
// Same visual contract the env-scoped heatmap used to follow on the Nodes
// table page, but pivoted to per-node categories.
// ---------------------------------------------------------------------------

const NODE_ACTIVITY_CATEGORIES = [
  { key: 'status', label: 'status', cssVar: '--info' },
  { key: 'result', label: 'result', cssVar: '--signal' },
  { key: 'query', label: 'query', cssVar: '--success' },
  { key: 'config', label: 'config', cssVar: '--warning' },
] as const;

type NodeActivityCategoryKey = (typeof NODE_ACTIVITY_CATEGORIES)[number]['key'];

const NODE_INTERVAL_LABEL: Record<ActivityInterval, string> = {
  '3h': 'last 3h',
  '6h': 'last 6h',
  '12h': 'last 12h',
  '1d': 'last 24h',
  '2d': 'last 2d',
  '3d': 'last 3d',
  '7d': 'last 7d',
};

// Window length (in hours) for each interval. The Redis activity rollups are
// hourly with DefaultRetentionDays of history, so the per-node heatmap window
// is expressed in hours and capped by the retention on the backend.
const NODE_INTERVAL_HOURS: Record<ActivityInterval, number> = {
  '3h': 3,
  '6h': 6,
  '12h': 12,
  '1d': 24,
  '2d': 48,
  '3d': 72,
  '7d': 168,
};

// Intervals offered in the node activity picker. The heatmap renders a fixed
// 24-column grid, so every entry must divide evenly into 24 buckets whose size
// is a backend-supported bucket_seconds value (see activityAllowedBucketSeconds).
// 3h is omitted because 3h/24 = 450s is not a supported bucket size.
const NODE_INTERVALS: ActivityInterval[] = ['6h', '12h', '1d', '2d', '3d', '7d'];

// Fixed column count for the node activity heatmap. Every interval renders
// this many cells; the per-cell time window (bucket size) scales with the
// selected interval so the grid always fills the same horizontal space.
const NODE_ACTIVITY_COLUMNS = 48;

function nodeFormatHHMM(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  return `${h}:${m}`;
}

// mergeNodeActivityBuckets aligns the hourly Redis config series onto the
// DB-backed activity grid (status/result/query). The DB grid uses a window-
// scaled bucket so the heatmap always has 24 columns; config (hourly) is
// folded into each cell by summing every Redis hour that overlaps the cell:
//   - sub-hourly cells (6h/12h) → one hour overlaps, so the hour's count is
//     held across the cell (config fetches are continuous, so showing the
//     hour's activity in each of its sub-cells reads as "active this hour");
//   - hourly+ cells (1d and up) → counts are summed, which is honest coarsening.
// Hours outside the Redis window read as 0 — config history only exists going
// forward from when osctrl-tls started emitting activity events.
function mergeNodeActivityBuckets(
  buckets: NodeActivityBucket[],
  tiles?: NodeTileSeries,
): NodeHeatmapBucket[] {
  const startMs = tiles ? Date.parse(tiles.start) : NaN;
  const hourMs = (tiles?.bucket_seconds ?? 3600) * 1000;
  const config = tiles?.config;
  const cellMs =
    buckets.length >= 2
      ? Date.parse(buckets[1].bucket_start) - Date.parse(buckets[0].bucket_start)
      : 3600_000;
  return buckets.map((b) => {
    let configCount = 0;
    if (config && config.length > 0 && !Number.isNaN(startMs)) {
      const cellStart = Date.parse(b.bucket_start);
      const cellEnd = cellStart + cellMs;
      let h = Math.floor((cellStart - startMs) / hourMs);
      while (h < config.length && startMs + h * hourMs < cellEnd) {
        if (h >= 0) configCount += config[h];
        h += 1;
      }
    }
    return {
      bucket_start: b.bucket_start,
      status: b.status,
      result: b.result,
      query: b.query,
      config: configCount,
    };
  });
}

function nodeMakeIntensityScale(
  buckets: NodeHeatmapBucket[],
  key: NodeActivityCategoryKey,
): (count: number) => number {
  const nonZero = buckets.map((b) => b[key]).filter((v) => v > 0).sort((a, b) => a - b);
  if (nonZero.length === 0) return () => 0;
  const q = (p: number) =>
    nonZero[Math.min(nonZero.length - 1, Math.floor(p * (nonZero.length - 1)))];
  const t1 = q(0.25);
  const t2 = q(0.5);
  const t3 = q(0.75);
  return (count: number) => {
    if (count <= 0) return 0;
    if (count <= t1) return 1;
    if (count <= t2) return 2;
    if (count <= t3) return 3;
    return 4;
  };
}

const NODE_STEP_ALPHA = [0, 0.2, 0.4, 0.7, 1] as const;

function nodeCellBackground(cssVar: string, step: number): string {
  if (step === 0) return 'color-mix(in oklab, var(--bg-3) 40%, transparent)';
  const pct = Math.round(NODE_STEP_ALPHA[step] * 100);
  return `color-mix(in oklab, var(${cssVar}) ${pct}%, transparent)`;
}

interface NodeActivityHeatmapProps {
  interval: ActivityInterval;
  buckets: NodeHeatmapBucket[];
  onIntervalChange: (i: ActivityInterval) => void;
  isLoading: boolean;
}

function NodeActivityHeatmap({
  interval,
  buckets,
  onIntervalChange,
  isLoading,
}: NodeActivityHeatmapProps) {
  const n = buckets.length;
  const bucketSeconds =
    n >= 2
      ? Math.round(
          (Date.parse(buckets[1].bucket_start) - Date.parse(buckets[0].bucket_start)) /
            1000,
        )
      : 3600;

  const scales: Record<NodeActivityCategoryKey, (c: number) => number> = {
    status: nodeMakeIntensityScale(buckets, 'status'),
    result: nodeMakeIntensityScale(buckets, 'result'),
    query: nodeMakeIntensityScale(buckets, 'query'),
    config: nodeMakeIntensityScale(buckets, 'config'),
  };

  const totalEvents = buckets.reduce(
    (sum, b) => sum + b.status + b.result + b.query + b.config,
    0,
  );
  const isEmpty = !isLoading && n > 0 && totalEvents === 0;

  // 5 evenly-spaced HH:mm ticks under the grid. Rendered as a flex row that
  // spans the cell area (past the 60px label column) so they stay aligned when
  // the grid fills the container width responsively.
  const tickCount = 5;
  const tickLabels: string[] = [];
  if (n > 0) {
    for (let i = 0; i < tickCount; i++) {
      const idx = Math.round((i * (n - 1)) / (tickCount - 1));
      tickLabels.push(nodeFormatHHMM(buckets[idx].bucket_start));
    }
  }

  // Label column + N cells that stretch to fill the container width. minmax
  // keeps cells from collapsing below 8px (overflow-x-auto handles the rest).
  const gridTemplateColumns = `60px repeat(${Math.max(n, 1)}, minmax(8px, 1fr))`;

  return (
    <section
      aria-label="Node activity heatmap"
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
    >
      {/* Header: title + interval picker */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-[color:var(--border)]">
        <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
          Node activity · {NODE_INTERVAL_LABEL[interval]}
        </h2>
        <div
          role="tablist"
          aria-label="Activity interval"
          className="flex items-center gap-0.5 rounded-md bg-[color:var(--bg-2)] p-0.5 border border-[color:var(--border)]"
        >
          {NODE_INTERVALS.map((iv) => {
            const active = iv === interval;
            return (
              <button
                key={iv}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onIntervalChange(iv)}
                className={cn(
                  'px-2 py-0.5 rounded text-[11px] font-mono-tabular transition-colors',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  active
                    ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]'
                    : 'text-[color:var(--text-3)] hover:text-[color:var(--text-2)]',
                )}
              >
                {iv}
              </button>
            );
          })}
        </div>
      </div>

      {/* Grid body */}
      <div className="px-4 py-3 overflow-x-auto">
        <div
          className="grid gap-y-[2px]"
          style={{ gridTemplateColumns, columnGap: '2px' }}
        >
          {NODE_ACTIVITY_CATEGORIES.map(({ key, label, cssVar }) => (
            <NodeFragmentRow
              key={key}
              label={label}
              cssVar={cssVar}
              buckets={buckets}
              categoryKey={key}
              scale={scales[key]}
              isLoading={isLoading}
              n={n}
              bucketSeconds={bucketSeconds}
            />
          ))}
        </div>

        {/* HH:mm time-axis ticks — flex justify-between spans the cell area */}
        {!isLoading && n > 0 && (
          <div className="mt-2 ml-[60px] flex justify-between" aria-hidden>
            {tickLabels.map((label, i) => (
              <span
                key={i}
                className={cn(
                  'text-[9px] font-mono-tabular text-[color:var(--text-3)]',
                  i === 0 && '-translate-x-1/2',
                  i === tickLabels.length - 1 && 'translate-x-1/2',
                )}
              >
                {label}
              </span>
            ))}
          </div>
        )}

        {isEmpty && (
          <p className="mt-2 text-[11px] text-[color:var(--text-3)]">
            No activity in the {NODE_INTERVAL_LABEL[interval]}.
          </p>
        )}
      </div>

      {/* Legend strip — category dots + intensity ramp */}
      <div className="flex items-center justify-between gap-3 px-4 py-2 border-t border-[color:var(--border)]">
        <div className="flex items-center gap-3">
          {NODE_ACTIVITY_CATEGORIES.map(({ key, label, cssVar }) => (
            <span
              key={key}
              className="inline-flex items-center gap-1.5 text-[10px] font-mono-tabular text-[color:var(--text-3)]"
            >
              <span
                aria-hidden
                className="inline-block w-2 h-2 rounded-full"
                style={{ background: `var(${cssVar})` }}
              />
              {label}
            </span>
          ))}
        </div>
        <div className="flex items-center gap-1.5 text-[10px] font-mono-tabular text-[color:var(--text-3)]">
          <span>less</span>
          {[0, 1, 2, 3, 4].map((step) => (
            <span
              key={step}
              aria-hidden
              className="inline-block w-[10px] h-[10px] rounded-sm border border-[color:var(--border)]"
              style={{
                background:
                  step === 0
                    ? 'color-mix(in oklab, var(--bg-3) 40%, transparent)'
                    : `color-mix(in oklab, var(--text-2) ${Math.round(NODE_STEP_ALPHA[step] * 100)}%, transparent)`,
              }}
            />
          ))}
          <span>more</span>
        </div>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// NodeEndpointLastSeen — Redis-backed per-endpoint activity readout that sits
// under the heatmap. For each osquery endpoint (config / status / result /
// query read / query write) it shows the event total over the last 24h and the
// last hour the node touched that endpoint. This is the data the DB buckets
// collapse: the config fetches and the read/write split are only visible here.
// ---------------------------------------------------------------------------
interface NodeEndpointLastSeenProps {
  series?: NodeTileSeries;
  isLoading: boolean;
}

function NodeEndpointLastSeen({ series, isLoading }: NodeEndpointLastSeenProps) {
  const bucketSeconds = series?.bucket_seconds ?? 3600;
  const items: KvItem[] = TILE_CATEGORIES.map((cat: TileCategory) => {
    const total = series ? tileCategoryTotal(series, cat) : 0;
    const last = series ? tileLastSeen(series, cat) : null;
    return {
      label: TILE_CATEGORY_LABELS[cat],
      value: isLoading ? (
        <Skeleton className="h-4 w-28" />
      ) : (
        <span className="inline-flex items-baseline gap-2">
          <span
            className="text-[color:var(--text-1)]"
            title={last ? `${formatAbsolute(last)} · ${total} events` : 'No activity in the last 24h'}
          >
            {last ? formatBucketAgo(last, bucketSeconds) : 'No activity'}
          </span>
          <span className="text-[color:var(--text-3)]">{total} events in 24h</span>
        </span>
      ),
    };
  });

  return (
    <KvGrid
      title="Endpoint last seen · 24h"
      items={items}
      cols={3}
    />
  );
}

/**
 * One label + N-cells row inside the heatmap grid. Rendered as a sibling
 * fragment so the parent grid lays out label and cells together.
 */
function NodeFragmentRow({
  label,
  cssVar,
  buckets,
  categoryKey,
  scale,
  isLoading,
  n,
  bucketSeconds,
}: {
  label: string;
  cssVar: string;
  buckets: NodeHeatmapBucket[];
  categoryKey: NodeActivityCategoryKey;
  scale: (c: number) => number;
  isLoading: boolean;
  n: number;
  bucketSeconds: number;
}) {
  // Skeleton: render a fixed-width placeholder row so the panel doesn't jump
  // around when the query resolves.
  const skeletonN = isLoading || n === 0 ? NODE_ACTIVITY_COLUMNS : n;
  return (
    <>
      <span className="text-[10px] font-mono-tabular uppercase tracking-[0.1em] text-[color:var(--text-3)] self-center pr-2">
        {label}
      </span>
      {isLoading || n === 0
        ? Array.from({ length: skeletonN }).map((_, i) => (
            <span
              key={i}
              aria-hidden
              className="block w-full aspect-square rounded-[2px] animate-pulse bg-[color:var(--bg-3)]/40"
            />
          ))
        : buckets.map((b, i) => {
            const count = b[categoryKey];
            const step = scale(count);
            const endIso = new Date(
              new Date(b.bucket_start).getTime() + bucketSeconds * 1000,
            ).toISOString();
            const title =
              `${nodeFormatHHMM(b.bucket_start)} – ${nodeFormatHHMM(endIso)}\n` +
              `status ${b.status} · result ${b.result} · query ${b.query} · config ${b.config}`;
            return (
              <span
                key={i}
                title={title}
                aria-label={`${label} ${count} at ${nodeFormatHHMM(b.bucket_start)}`}
                className="block w-full aspect-square rounded-[2px]"
                style={{ background: nodeCellBackground(cssVar, step) }}
              />
            );
          })}
    </>
  );
}

export default NodeDetailPage;
