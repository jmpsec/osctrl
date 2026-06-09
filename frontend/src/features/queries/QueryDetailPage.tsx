import { useParams, useNavigate, useSearch, Link } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getQuery, listQueryResults, getQueryResultsCSVUrl } from '$/api/queries';
import { listNodes } from '$/api/nodes';
import { AuthError } from '$/api/client';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------
function QueryStatusBadge({ q }: { q: { active: boolean; completed: boolean; expired: boolean; deleted: boolean } }) {
  if (q.deleted) return <Badge variant="danger" label="Deleted" />;
  if (q.expired) return <Badge variant="warning" label="Expired" />;
  if (q.completed) return <Badge variant="success" label="Completed" />;
  if (q.active) return <Badge variant="info" label="Active" />;
  return <Badge variant="dim" label="Unknown" />;
}

// osquery distributed result `status` codes:
//   0 → ok        (query ran, returned rows)
//   1 → error     (query failed on the agent — usually SQL syntax / table not present)
//   2 → other     (osquery has used this for transient state in past versions)
// Anything else gets a neutral "code N" rendering so we don't silently hide it.
function StatusBadge({ code }: { code: number }) {
  if (code === 0) return <Badge variant="success" label="ok" />;
  if (code === 1) return <Badge variant="danger" label="error" />;
  if (code === 2) return <Badge variant="warning" label="other" />;
  return <Badge variant="dim" label={`code ${code}`} />;
}

function Badge({
  variant,
  label,
}: {
  variant: 'success' | 'warning' | 'danger' | 'info' | 'dim';
  label: string;
}) {
  const cls = {
    success: 'bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.12)] text-[color:var(--success)]',
    warning: 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]',
    danger:  'bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.12)] text-[color:var(--danger)]',
    info:    'bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.12)] text-[color:var(--info)]',
    dim:     'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
  }[variant];

  return (
    <span className={cn('px-2 py-0.5 rounded-full text-xs font-medium', cls)}>
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// QueryDetailPage
// ---------------------------------------------------------------------------
const DEFAULT_PAGE_SIZE = 50;

export function QueryDetailPage() {
  const { env, name } = useParams({ from: '/_app/env/$env/queries/$name' });
  const navigate = useNavigate({ from: '/_app/env/$env/queries/$name' });
  const search = useSearch({ from: '/_app/env/$env/queries/$name' });

  const page: number = (search.page as number) ?? 1;
  const pageSize: number = (search.page_size as number) ?? DEFAULT_PAGE_SIZE;
  const since: string | undefined = search.since as string | undefined;

  // Query metadata
  const {
    data: query,
    isLoading: metaLoading,
    isError: metaError,
    error: metaErr,
  } = useQuery({
    queryKey: ['query', env, name],
    queryFn: () => getQuery(env, name),
    staleTime: 15_000,
    refetchInterval: 15_000,
  });

  const qc = useQueryClient();

  // Paginated query results
  const {
    data: resultsData,
    isLoading: resultsLoading,
    isError: resultsError,
    error: resultsErr,
  } = useQuery({
    queryKey: ['query-results', env, name, page, pageSize, since],
    queryFn: () => listQueryResults({ env, name, page, pageSize, since }),
    staleTime: 15_000,
    refetchInterval: 15_000,
    enabled: !!query,
  });

  // Nodes lookup map — used to turn the raw uuid on each result row into a
  // human-friendly hostname. Cached for 60s so result-page renders don't
  // hammer the nodes endpoint; staler-than-staleTime gets a quiet refetch
  // on next mount. The nodes query is keyed by env so a small fleet (this
  // is the dev scope, not multi-tenant) pulls the whole list once.
  const { data: nodesData } = useQuery({
    queryKey: ['query-results-nodes-lookup', env],
    queryFn: () => listNodes({ env, pageSize: 500 }),
    staleTime: 60_000,
    enabled: !!query,
  });
  const uuidToHostname = new Map<string, string>();
  for (const n of nodesData?.items ?? []) {
    uuidToHostname.set(n.uuid, n.hostname || n.localname || n.uuid);
  }

  // Redirect to login on 401
  if ((metaError && metaErr instanceof AuthError) || (resultsError && resultsErr instanceof AuthError)) {
    void navigate({ to: '/login' });
    return null;
  }

  // ---------------------------------------------------------------------------
  // Build rows + column union from this page of items
  // ---------------------------------------------------------------------------
  const items = resultsData?.items ?? [];
  const totalItems = resultsData?.total_items ?? 0;
  const totalPages = resultsData?.total_pages ?? 0;

  // Cell values can be nested objects when osquery returns JSON-typed columns
  // (uptime returns `{days,hours,minutes,seconds}`, some apps tables return
  // `{name,version,arch}` per row). Typing as `unknown` keeps us honest; the
  // render path below stringifies anything non-primitive instead of letting
  // React throw error #31 when it sees an object child.
  const rows: Array<{
    id: number;
    uuid: string;
    createdAt: string;
    status: number;
    cols: Record<string, unknown>;
  }> = [];
  const colSet = new Set<string>();

  for (const item of items) {
    let cols: Record<string, unknown> = {};
    try {
      cols = JSON.parse(item.data) as Record<string, unknown>;
    } catch {
      cols = { data: item.data };
    }
    for (const k of Object.keys(cols)) colSet.add(k);
    rows.push({
      id: item.id,
      uuid: item.uuid,
      createdAt: item.created_at,
      status: item.status,
      cols,
    });
  }
  const colHeaders = Array.from(colSet).sort();

  const csvUrl = getQueryResultsCSVUrl(env, name);

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Header ── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)]">
        <div className="flex items-center gap-2 mb-1">
          <Link
            to="/_app/env/$env/queries"
            params={{ env }}
            className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--text-2)] transition-colors"
          >
            ← Queries
          </Link>
        </div>

        {metaLoading ? (
          <div className="h-6 w-64 bg-[color:var(--bg-2)] rounded animate-pulse" />
        ) : query ? (
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] font-mono-tabular">
              {query.name}
            </h1>
            <QueryStatusBadge q={query} />
          </div>
        ) : null}

        {query && (
          <div className="mt-2 flex flex-wrap gap-4 text-xs text-[color:var(--text-2)]">
            <span>Creator: <strong className="text-[color:var(--text-1)]">{query.creator}</strong></span>
            <span>
              Progress:{' '}
              <strong className="font-mono-tabular text-[color:var(--text-1)]">
                {query.executions}/{query.expected}
              </strong>
              {query.errors > 0 && (
                <span className="ml-1 text-[color:var(--danger)]">({query.errors} errors)</span>
              )}
            </span>
            <span>Type: <strong className="text-[color:var(--text-1)]">{query.type}</strong></span>
            <span>Created: <strong className="text-[color:var(--text-1)]" title={query.created_at}>{formatRelative(query.created_at)}</strong></span>
            {query.expiration && !query.expiration.startsWith('0001') && (
              <span>Expires: <strong className="text-[color:var(--text-1)]" title={query.expiration}>{formatRelative(query.expiration)}</strong></span>
            )}
          </div>
        )}

        {query && (
          <div className="mt-3 rounded-md overflow-hidden border border-[color:var(--border)]">
            <pre className="px-4 py-3 text-xs font-mono-tabular text-[color:var(--text-1)] bg-[color:var(--bg-2)] overflow-x-auto whitespace-pre-wrap break-all">
              {query.query}
            </pre>
          </div>
        )}

        {/* Targets — creation-time scope (platform / uuid / hostname /
            tag rows). Matches the legacy admin's Targets table on the
            query detail page so operators can answer "why didn't host
            X run this." Empty list rendered as a quiet hint. */}
        {query && query.targets !== undefined && (
          <div className="mt-3">
            <div className="text-[10px] uppercase tracking-[0.12em] text-[color:var(--text-3)] mb-1">
              Targets
            </div>
            {query.targets.length === 0 ? (
              <div className="text-xs text-[color:var(--text-3)] italic">
                No targets recorded.
              </div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {query.targets.map((t, i) => (
                  <span
                    key={`${t.type}-${t.value}-${i}`}
                    className={cn(
                      'inline-flex items-center gap-1 px-2 py-0.5 rounded-md',
                      'text-[11px] font-mono-tabular',
                      'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
                      'text-[color:var(--text-2)]',
                    )}
                  >
                    <span className="text-[color:var(--text-3)]">{t.type}:</span>
                    <span className="text-[color:var(--text-1)] font-semibold">{t.value}</span>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Results section header ── */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-[color:var(--border)]">
        <h2 className="text-sm font-semibold text-[color:var(--text-1)]">
          Results
          {totalItems > 0 && (
            <span className="ml-2 font-mono-tabular text-xs text-[color:var(--text-3)]">
              ({totalItems} row{totalItems !== 1 ? 's' : ''})
            </span>
          )}
        </h2>
        <div className="ml-auto flex items-center gap-2">
          {/* Refresh button — mirrors the legacy admin's "Refresh table" control.
              The page also polls every 15s via TanStack Query's refetchInterval,
              but an explicit button gives operators the same control they had
              in legacy when watching a long-running distributed query land. */}
          <button
            type="button"
            onClick={() => {
              void qc.invalidateQueries({ queryKey: ['query', env, name] });
              void qc.invalidateQueries({ queryKey: ['query-results', env, name] });
            }}
            className={cn(
              'px-3 py-1 text-xs font-medium rounded-md',
              'border border-[color:var(--border)] text-[color:var(--text-2)]',
              'hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
            aria-label="Refresh query results"
            title="Refresh now"
          >
            Refresh
          </button>
          {totalItems > 0 && (
            <a
              href={csvUrl}
              download
              className={cn(
                'px-3 py-1 text-xs font-medium rounded-md',
                'border border-[color:var(--border)] text-[color:var(--text-2)]',
                'hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors',
                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              )}
              aria-label={`Download CSV of ${name} results`}
            >
              Download CSV
            </a>
          )}
        </div>
      </div>

      {/* ── Results table ── */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          {colHeaders.length > 0 && (
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide whitespace-nowrap"
                >
                  Created
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Node
                </th>
                {colHeaders.map((col) => (
                  <th
                    key={col}
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                  >
                    {col}
                  </th>
                ))}
                <th
                  scope="col"
                  className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Status
                </th>
              </tr>
            </thead>
          )}

          <tbody>
            {/* Loading skeleton */}
            {resultsLoading &&
              Array.from({ length: 5 }).map((_, i) => (
                <SkeletonRow key={i} cells={colHeaders.length + 3 || 4} />
              ))}

            {/* Error state */}
            {resultsError && !resultsLoading && (
              <tr>
                <td colSpan={colHeaders.length + 3 || 4}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={resultsErr instanceof Error ? resultsErr.message : 'Failed to load results'}
                  />
                </td>
              </tr>
            )}

            {/* Empty state (HTTP 200, items: []) */}
            {!resultsLoading && !resultsError && rows.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" />
                      </svg>
                    }
                    title="No results yet."
                  />
                </td>
              </tr>
            )}

            {/* Data rows */}
            {!resultsLoading &&
              !resultsError &&
              rows.map((row) => {
                const hostname = uuidToHostname.get(row.uuid);
                return (
                  <tr
                    key={row.id}
                    className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                  >
                    <td
                      className="px-4 py-2 font-mono-tabular text-xs text-[color:var(--text-2)] whitespace-nowrap"
                      title={row.createdAt}
                    >
                      {formatRelative(row.createdAt)}
                    </td>
                    <td className="px-4 py-2 font-mono-tabular text-xs">
                      <Link
                        to="/_app/env/$env/nodes/$uuid"
                        params={{ env, uuid: row.uuid }}
                        className="text-[color:var(--signal)] hover:underline"
                        title={row.uuid}
                      >
                        {hostname ?? `${row.uuid.slice(0, 8)}…`}
                      </Link>
                    </td>
                    {colHeaders.map((col) => {
                      // osquery cells can be nested objects (e.g. uptime's
                      // `{days, hours, minutes, seconds}`), not just strings —
                      // the typed cast on JSON.parse lies. Coerce non-primitive
                      // values to a compact JSON string so React renders them
                      // safely instead of throwing minified error #31.
                      const raw = row.cols[col];
                      const display =
                        raw == null
                          ? '—'
                          : typeof raw === 'object'
                            ? JSON.stringify(raw)
                            : String(raw);
                      return (
                        <td
                          key={col}
                          className="px-4 py-2 text-xs text-[color:var(--text-1)] max-w-xs truncate"
                          title={display}
                        >
                          {display}
                        </td>
                      );
                    })}
                    <td className="px-4 py-2 whitespace-nowrap">
                      <StatusBadge code={row.status} />
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* ── Pagination footer ── */}
      {!resultsLoading && !resultsError && totalItems > 0 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          totalItems={totalItems}
          pageSize={pageSize}
          onPageChange={(p) =>
            void navigate({
              search: (prev: Record<string, unknown>) => ({ ...prev, page: p }),
              replace: false,
            })
          }
        />
      )}
    </div>
  );
}

export default QueryDetailPage;
