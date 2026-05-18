import { useState, useEffect, useMemo } from 'react';
import { useSearch, useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import {
  listAuditLogs,
  LOG_TYPE_LABELS,
  type AuditLogsQuery,
} from '$/api/audit';
import { getMe } from '$/api/users';
import { AuthError } from '$/api/client';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { Pagination } from '$/components/data/Pagination';
import { formatRelative } from '$/lib/time';
import type { auditSearchSchema } from '$/routes/_app/audit';
import type { z } from 'zod';

type Search = z.infer<typeof auditSearchSchema>;

// Audit log filter values: empty string = no service filter; the other three
// match the literal strings written to audit_logs.service by each Go service —
// `osctrl-tls`, `osctrl-admin`, `osctrl-api`, `osctrl-cli`. Note the prefixed
// form here is DELIBERATE: it is NOT the same namespace as pkg/settings (which
// uses bare "tls"/"admin"/"api"). The two should not be unified — audit
// readers compare to what was actually written to the column.
const SERVICES = ['', 'osctrl-tls', 'osctrl-admin', 'osctrl-api', 'osctrl-cli'] as const;
const LOG_TYPE_KEYS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10] as const;

export function AuditPage() {
  const search = useSearch({ from: '/_app/audit' });
  const navigate = useNavigate({ from: '/_app/audit' });

  // Resolve the viewer. Super-admins see the full audit trail and
  // the username filter; non-admins see only their own activity
  // (the api force-clamps the username filter server-side) and
  // shouldn't see the username input — typing other usernames
  // would be a no-op and just confuse the operator.
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
  });
  const isSuperAdmin = me?.admin === true;

  const service: string = search.service ?? '';
  const username: string = search.username ?? '';
  const type: number = search.type ?? 0;
  const envUuid: string = search.env_uuid ?? '';
  const since: string = search.since ?? '';
  const until: string = search.until ?? '';
  const page: number = search.page ?? 1;
  const pageSize: number = search.page_size ?? 50;

  // Local input buffers (debounced commit to URL on Apply).
  const [usernameDraft, setUsernameDraft] = useState(username);
  const [envDraft, setEnvDraft] = useState(envUuid);
  const [sinceDraft, setSinceDraft] = useState(since);
  const [untilDraft, setUntilDraft] = useState(until);

  // When URL changes externally (e.g. browser back), re-sync the inputs.
  useEffect(() => {
    setUsernameDraft(username);
    setEnvDraft(envUuid);
    setSinceDraft(since);
    setUntilDraft(until);
  }, [username, envUuid, since, until]);

  function updateSearch(patch: Partial<Search>) {
    void navigate({
      search: (prev: Record<string, unknown>) => {
        const next: Record<string, unknown> = { ...prev, ...patch };
        for (const key of Object.keys(next)) {
          const v = next[key];
          if (v === undefined || v === '' || v === 0) delete next[key];
        }
        return next as typeof prev;
      },
      replace: false,
    });
  }

  // Memoize apiQuery so its identity is stable across renders. TanStack
  // Query 5 hashes queryKey structurally so this should not matter in
  // theory, but in practice a parent re-render that rebuilds this
  // object can interact badly with React StrictMode's double-invoke
  // and trigger refetch storms. Pin the identity to keep the query
  // referentially stable.
  const apiQuery: AuditLogsQuery = useMemo(() => ({
    service: service || undefined,
    username: username || undefined,
    type: type > 0 ? type : undefined,
    env_uuid: envUuid || undefined,
    since: since || undefined,
    until: until || undefined,
    page,
    page_size: pageSize,
  }), [service, username, type, envUuid, since, until, page, pageSize]);

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ['audit-logs', apiQuery],
    queryFn: () => listAuditLogs(apiQuery),
    // 30s staleness window — audit log isn't a real-time feed; the
    // SPA's refetch-on-mount / focus is enough freshness, and a
    // longer window blunts any remaining re-render storm.
    staleTime: 30_000,
    // refetchOnWindowFocus stays on (default true) so reopening the
    // tab after time away gives fresh data, but inside a stable focus
    // session we don't re-query.
    refetchOnWindowFocus: true,
    placeholderData: (prev) => prev,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const items = data?.items ?? [];
  const totalItems = data?.total_items ?? 0;
  const totalPages = data?.total_pages ?? 0;

  function applyFilters() {
    updateSearch({
      username: usernameDraft.trim() || undefined,
      env_uuid: envDraft.trim() || undefined,
      since: sinceDraft.trim() ? toRFC3339(sinceDraft) : undefined,
      until: untilDraft.trim() ? toRFC3339(untilDraft) : undefined,
      page: 1,
    });
  }

  function resetFilters() {
    setUsernameDraft('');
    setEnvDraft('');
    setSinceDraft('');
    setUntilDraft('');
    updateSearch({
      service: undefined,
      username: undefined,
      type: undefined,
      env_uuid: undefined,
      since: undefined,
      until: undefined,
      page: 1,
    });
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
          {isSuperAdmin ? 'Audit Trail' : 'My Activity'}
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          {isSuperAdmin
            ? 'Every state-changing API call writes one row.'
            : 'Your activity history. State-changing API calls you make appear here.'}
        </p>
        {isFetching && !isLoading && (
          <span
            aria-live="polite"
            aria-label="Refreshing data"
            className="ml-auto text-[10px] text-[color:var(--text-3)] font-mono-tabular"
          >
            refreshing…
          </span>
        )}
      </div>

      <div className="px-4 py-3 border-b border-[color:var(--border)] grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3 items-end bg-[color:var(--bg-1)]">
        <FilterField id="f-service" label="Service">
          <select
            id="f-service"
            value={service}
            onChange={(e) => updateSearch({ service: e.target.value || undefined, page: 1 })}
            className={selectClass}
          >
            {SERVICES.map((s) => (
              <option key={s || 'all'} value={s}>
                {s || 'all'}
              </option>
            ))}
          </select>
        </FilterField>

        <FilterField id="f-type" label="Type">
          <select
            id="f-type"
            value={String(type)}
            onChange={(e) => updateSearch({ type: Number(e.target.value) || undefined, page: 1 })}
            className={selectClass}
          >
            {LOG_TYPE_KEYS.map((k) => (
              <option key={k} value={k}>
                {k === 0 ? 'all' : LOG_TYPE_LABELS[k] ?? String(k)}
              </option>
            ))}
          </select>
        </FilterField>

        {/* Username filter is super-admin-only. Non-admins are
            force-clamped to their own activity server-side; showing
            the input would let them type other names that have no
            effect — confusing. */}
        {isSuperAdmin && (
          <FilterField id="f-username" label="Username">
            <input
              id="f-username"
              type="text"
              value={usernameDraft}
              placeholder="partial match"
              onChange={(e) => setUsernameDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') applyFilters();
              }}
              className={inputClass}
            />
          </FilterField>
        )}

        <FilterField id="f-env" label="Env UUID">
          <input
            id="f-env"
            type="text"
            value={envDraft}
            placeholder="00000000-..."
            onChange={(e) => setEnvDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') applyFilters();
            }}
            className={inputClass}
          />
        </FilterField>

        <FilterField id="f-since" label="Since">
          <input
            id="f-since"
            type="datetime-local"
            value={sinceDraft}
            onChange={(e) => setSinceDraft(e.target.value)}
            className={inputClass}
          />
        </FilterField>

        <FilterField id="f-until" label="Until">
          <input
            id="f-until"
            type="datetime-local"
            value={untilDraft}
            onChange={(e) => setUntilDraft(e.target.value)}
            className={inputClass}
          />
        </FilterField>

        <div className="md:col-span-3 lg:col-span-6 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={resetFilters}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Reset
          </button>
          <button
            type="button"
            onClick={applyFilters}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors',
            )}
          >
            Apply filters
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                When
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Service
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Type
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                User
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Source IP
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}

            {isError && !isLoading && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={error instanceof Error ? error.message : 'Failed to load audit log'}
                    action={
                      <button
                        type="button"
                        onClick={() => void refetch()}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Retry
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading && !isError && items.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
                      </svg>
                    }
                    title="No entries match these filters."
                  />
                </td>
              </tr>
            )}

            {!isLoading && !isError &&
              items.map((row) => (
                <tr
                  key={row.id}
                  className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors align-top"
                >
                  <td className="px-4 py-2 tnum text-xs text-[color:var(--text-2)] whitespace-nowrap">
                    <span title={row.created_at}>{formatRelative(row.created_at)}</span>
                  </td>
                  <td className="px-4 py-2 text-xs font-mono-tabular text-[color:var(--text-2)]">
                    {row.service}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono-tabular text-[color:var(--text-3)] bg-[color:var(--bg-2)]">
                      {LOG_TYPE_LABELS[row.log_type] ?? row.log_type}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs font-mono-tabular text-[color:var(--text-1)]">
                    {row.username || <span className="text-[color:var(--text-3)]">—</span>}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono-tabular text-[color:var(--text-3)]">
                    {row.source_ip || '—'}
                  </td>
                  <td className="px-4 py-2 text-xs text-[color:var(--text-1)] break-all">
                    {row.line}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <Pagination
        page={page}
        pageSize={pageSize}
        totalItems={totalItems}
        totalPages={totalPages}
        onPageChange={(p) => updateSearch({ page: p })}
      />
    </div>
  );
}

const inputClass = cn(
  'w-full px-3 py-1.5 text-xs rounded-md border border-[color:var(--border)]',
  'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
  'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
);

const selectClass = inputClass;

function FilterField({
  id,
  label,
  children,
}: {
  id: string;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-[10px] font-semibold text-[color:var(--text-3)] uppercase tracking-wider mb-1">
        {label}
      </label>
      {children}
    </div>
  );
}

// `datetime-local` inputs use "YYYY-MM-DDTHH:mm" (no timezone). Convert to
// RFC3339 by appending the local timezone offset so the server-side parser
// (time.Parse(time.RFC3339, ...)) accepts it.
function toRFC3339(local: string): string {
  if (!local) return '';
  // Construct a Date from the local string and emit ISO with offset.
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) return '';
  // .toISOString() emits UTC ("Z") which is a valid RFC3339 form.
  return d.toISOString();
}

export default AuditPage;
