import { useParams, useNavigate, useSearch, Link } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getQuery, listQueryResults, getQueryResultsCSVUrl, actOnQuery } from '$/api/queries';
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
  const completeMutation = useMutation({
    mutationFn: () => actOnQuery(env, name, 'complete'),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['query', env, name] });
      void qc.invalidateQueries({ queryKey: ['query-results', env, name] });
      void qc.invalidateQueries({ queryKey: ['queries', env] });
    },
  });

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
  // Build rows from this page of items.
  //
  // Each item.data is a JSON string of shape
  //   { name, status, message, result: [{...}, {...}, ...] }
  // where `result` is the array of row objects the node returned for this
  // distributed query write. Different nodes (and different runs) may
  // return different shapes, so we keep each item's result set in its own
  // nested data table inside the Data cell — same approach as the legacy
  // admin's queries-logs template. This is much friendlier to the common
  // case (multi-row tables like `processes` or `apps`) than extruding
  // every key onto the outer table.
  // ---------------------------------------------------------------------------
  const items = resultsData?.items ?? [];
  const totalItems = resultsData?.total_items ?? 0;
  const totalPages = resultsData?.total_pages ?? 0;

  const rows: Array<{
    id: number;
    uuid: string;
    createdAt: string;
    status: number;
    results: Array<Record<string, unknown>>;
    parseError: string | null;
  }> = [];

  for (const item of items) {
    let results: Array<Record<string, unknown>> = [];
    let parseError: string | null = null;
    try {
      const parsed = JSON.parse(item.data) as {
        result?: Array<Record<string, unknown>>;
      };
      // osquery distributed writes always wrap rows in `.result`. Tolerate
      // the older legacy double-encoding by re-parsing once if we got a
      // string back instead of an object.
      const inner =
        typeof parsed === 'string'
          ? (JSON.parse(parsed) as { result?: Array<Record<string, unknown>> })
          : parsed;
      results = Array.isArray(inner?.result) ? inner.result : [];
    } catch (e) {
      parseError = e instanceof Error ? e.message : 'parse error';
    }
    rows.push({
      id: item.id,
      uuid: item.uuid,
      createdAt: item.created_at,
      status: item.status,
      results,
      parseError,
    });
  }

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
            <span>
              Expires:{' '}
              <strong
                className="text-[color:var(--text-1)]"
                title={query.expiration && !query.expiration.startsWith('0001') ? query.expiration : 'no expiration'}
              >
                {query.expiration && !query.expiration.startsWith('0001')
                  ? formatRelative(query.expiration)
                  : 'never'}
              </strong>
            </span>
          </div>
        )}

        {query && !query.completed && !query.deleted && (
          <div className="mt-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => completeMutation.mutate()}
              disabled={completeMutation.isPending}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
                'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
              aria-label="Complete query"
            >
              {completeMutation.isPending ? 'Completing…' : 'Complete query'}
            </button>
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
            // Refresh everything: the query, its results, the queries list,
            // and any other live data on the page (stats, activity) — so an
            // operator watching a query land gets a fully fresh view, not just
            // the results table.
            onClick={() => void qc.invalidateQueries()}
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

      {/* ── Results table ──
          Three outer columns: Created · Node · Data. The Data cell holds a
          fully nested table of that result item's rows (one per osquery
          result row) — same shape as the legacy admin renders, so a
          processes-table query with 30 rows from one node renders as 30
          inner rows under one outer row, not 30 outer rows with sparse
          cells. Status is overlaid on the Created cell as a small badge so
          we don't sacrifice horizontal room to a near-always-"ok" column. */}
      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th
                scope="col"
                className="w-[160px] px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide whitespace-nowrap"
              >
                Created
              </th>
              <th
                scope="col"
                className="w-[200px] px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                Node
              </th>
              <th
                scope="col"
                className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
              >
                Data
              </th>
            </tr>
          </thead>

          <tbody>
            {/* Loading skeleton */}
            {resultsLoading &&
              Array.from({ length: 5 }).map((_, i) => (
                <SkeletonRow key={i} cells={3} />
              ))}

            {/* Error state */}
            {resultsError && !resultsLoading && (
              <tr>
                <td colSpan={3}>
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
                <td colSpan={3}>
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
                    className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors align-top"
                  >
                    <td
                      className="px-4 py-2 font-mono-tabular text-xs text-[color:var(--text-2)] whitespace-nowrap"
                      title={row.createdAt}
                    >
                      <div className="flex items-center gap-2">
                        <span>{formatRelative(row.createdAt)}</span>
                        <StatusBadge code={row.status} />
                      </div>
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
                    <td className="px-4 py-2">
                      <ResultPayload results={row.results} parseError={row.parseError} />
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

// ---------------------------------------------------------------------------
// ResultPayload — renders one item's `result` array as a compact nested
// table. Columns are the union of keys across THIS result set so a small
// query (3 process rows) shows 30 columns and a wide query (apps with 10
// fields) shows 10 — same shape the legacy admin uses. Object/array cell
// values get JSON.stringify'd so React doesn't choke on non-primitive
// children.
// ---------------------------------------------------------------------------
function ResultPayload({
  results,
  parseError,
}: {
  results: Array<Record<string, unknown>>;
  parseError: string | null;
}) {
  if (parseError) {
    return (
      <div className="text-xs text-[color:var(--danger)] font-mono-tabular">
        parse error: {parseError}
      </div>
    );
  }
  if (results.length === 0) {
    return (
      <div className="text-xs text-[color:var(--text-3)] italic">No rows.</div>
    );
  }
  // Union of all keys in this result set, preserving first-seen order so
  // the most common column (often `pid` / `name`) shows up on the left
  // without us having to special-case it.
  const seen = new Set<string>();
  const cols: string[] = [];
  for (const r of results) {
    for (const k of Object.keys(r)) {
      if (!seen.has(k)) {
        seen.add(k);
        cols.push(k);
      }
    }
  }
  return (
    <div className="overflow-x-auto rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)]">
      <table className="w-full text-[11px] border-collapse">
        <thead>
          <tr className="bg-[color:var(--bg-1)] border-b border-[color:var(--border)]">
            {cols.map((c) => (
              <th
                key={c}
                scope="col"
                className={cn(
                  'px-2 py-1.5 text-left font-mono-tabular font-medium',
                  'text-[color:var(--text-2)] whitespace-nowrap',
                )}
              >
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {results.map((row, i) => (
            <tr
              key={i}
              className="border-b border-[color:var(--border)] last:border-b-0"
            >
              {cols.map((c) => {
                const raw = row[c];
                const display =
                  raw == null
                    ? ''
                    : typeof raw === 'object'
                      ? JSON.stringify(raw)
                      : String(raw);
                return (
                  <td
                    key={c}
                    className={cn(
                      'px-2 py-1 font-mono-tabular text-[color:var(--text-1)]',
                      'max-w-[280px] truncate',
                    )}
                    title={display}
                  >
                    {display}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
