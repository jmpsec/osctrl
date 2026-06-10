import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { getCarve, getCarveArchiveUrl } from '$/api/carves';
import { listNodes } from '$/api/nodes';
import { AuthError } from '$/api/client';
import type { CarveFile } from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { EmptyState } from '$/components/data/EmptyState';

function StatusBadge({ status }: { status: string }) {
  const normalized = status.toUpperCase();
  const variant =
    normalized === 'COMPLETED'
      ? 'success'
      : normalized === 'IN PROGRESS'
        ? 'info'
        : normalized === 'SCHEDULED' || normalized === 'QUERIED'
          ? 'warning'
          : 'dim';
  const cls = {
    success:
      'bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.12)] text-[color:var(--success)]',
    info:
      'bg-[rgba(var(--info-r),var(--info-g),var(--info-b),0.12)] text-[color:var(--info)]',
    warning:
      'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]',
    dim: 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
  }[variant];
  return (
    <span className={cn('px-2 py-0.5 rounded-full text-xs font-medium', cls)}>
      {status || 'Unknown'}
    </span>
  );
}

function formatBytes(n: number): string {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log10(n) / 3));
  const value = n / Math.pow(1000, i);
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function CarveDetailPage() {
  const { env, name } = useParams({ from: '/_app/env/$env/carves/$name' });
  const navigate = useNavigate({ from: '/_app/env/$env/carves/$name' });

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['carve', env, name],
    queryFn: () => getCarve(env, name),
    staleTime: 15_000,
    refetchInterval: 15_000,
  });

  // Nodes lookup so the carve file rows can render hostname → link to the
  // node detail page, matching the legacy admin's behaviour where the
  // node column was a hyperlink. Same shape as QueryDetailPage uses.
  const { data: nodesData } = useQuery({
    queryKey: ['carve-nodes-lookup', env],
    queryFn: () => listNodes({ env, pageSize: 500 }),
    staleTime: 60_000,
  });
  const uuidToHostname = new Map<string, string>();
  for (const n of nodesData?.items ?? []) {
    uuidToHostname.set(n.uuid, n.hostname || n.localname || n.uuid);
  }

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const query = data?.query;
  const files: CarveFile[] = data?.files ?? [];
  const completedFiles = files.filter((f) => (f.status || '').toUpperCase() === 'COMPLETED');
  const archivableFiles = files.filter(
    (f) => f.archived || (f.status || '').toUpperCase() === 'COMPLETED',
  );

  return (
    <div className="flex flex-col h-full min-h-0 overflow-auto">
      <div className="px-6 py-4 border-b border-[color:var(--border)]">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
              <span className="font-mono-tabular">{name}</span>
            </h1>
            <p className="text-sm text-[color:var(--text-2)] mt-0.5">
              <Link
                to="/_app/env/$env/carves"
                params={{ env }}
                className="text-[color:var(--text-link)] hover:underline"
              >
                ← Back to carves
              </Link>
            </p>
          </div>
          {query && (
            <dl className="flex items-center gap-4 text-xs text-[color:var(--text-2)] tnum">
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-[color:var(--text-3)]">Path</dt>
                <dd className="font-mono-tabular">{query.path || '—'}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-[color:var(--text-3)]">Creator</dt>
                <dd>{query.creator}</dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-[color:var(--text-3)]">Progress</dt>
                <dd>
                  {query.executions + query.errors}/{query.expected || '—'}
                </dd>
              </div>
              <div>
                <dt className="text-[10px] uppercase tracking-wide text-[color:var(--text-3)]">Created</dt>
                <dd title={query.created_at}>{formatRelative(query.created_at)}</dd>
              </div>
            </dl>
          )}
        </div>
      </div>

      <div className="px-6 py-4 flex-1 min-h-0 overflow-auto">
        <h2 className="text-sm font-semibold text-[color:var(--text-1)] mb-3">
          Carved files ({files.length})
          {completedFiles.length > 0 && (
            <span className="ml-2 text-xs text-[color:var(--text-3)] font-normal">
              · {completedFiles.length} completed
            </span>
          )}
        </h2>

        {isLoading && (
          <p className="text-xs text-[color:var(--text-3)]">Loading…</p>
        )}

        {isError && !isLoading && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title={error instanceof Error ? error.message : 'Failed to load carve'}
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
        )}

        {!isLoading && !isError && files.length === 0 && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" />
              </svg>
            }
            title="No carved files yet — waiting for nodes to check in."
          />
        )}

        {!isLoading && !isError && files.length > 0 && (
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)]">
                <th
                  scope="col"
                  className="px-3 py-2 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Node
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Status
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Size
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Blocks
                </th>
                <th
                  scope="col"
                  className="px-3 py-2 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide"
                >
                  Completed
                </th>
                <th scope="col" className="px-3 py-2 w-1" />
              </tr>
            </thead>
            <tbody>
              {files.map((f) => {
                const canDownload = f.archived || (f.status || '').toUpperCase() === 'COMPLETED';
                return (
                  <tr
                    key={f.carve_id || f.session_id}
                    className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                  >
                    <td className="px-3 py-2 font-mono-tabular text-xs">
                      <Link
                        to="/_app/env/$env/nodes/$uuid"
                        params={{ env, uuid: f.uuid }}
                        className="text-[color:var(--signal)] hover:underline"
                        title={f.uuid}
                      >
                        {uuidToHostname.get(f.uuid) ?? `${f.uuid.slice(0, 12)}…`}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="px-3 py-2 text-xs tnum text-[color:var(--text-2)] text-right">
                      {formatBytes(f.carve_size)}
                    </td>
                    <td className="px-3 py-2 text-xs tnum text-[color:var(--text-2)] text-right">
                      {f.completed_blocks}/{f.total_blocks}
                    </td>
                    <td className="px-3 py-2 text-xs tnum text-[color:var(--text-2)] text-right">
                      <span title={f.completed_at}>{formatRelative(f.completed_at)}</span>
                    </td>
                    <td className="px-3 py-2 text-right whitespace-nowrap">
                      {canDownload ? (
                        <a
                          href={getCarveArchiveUrl(env, name, f.session_id)}
                          className={cn(
                            'px-2 py-1 text-xs font-medium rounded',
                            'text-[color:var(--text-link)] hover:underline',
                          )}
                        >
                          Download
                        </a>
                      ) : (
                        <span className="px-2 py-1 text-xs text-[color:var(--text-3)]">
                          —
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {files.length === 1 && archivableFiles.length === 1 && (
          <div className="mt-4">
            {/*
             * Bulk button: only when the carve has exactly one file (total)
             * AND that file is archivable. The session-less archive URL
             * relies on the server seeing exactly one file; when N>1 the
             * server returns 409 and the user must pick a row above.
             */}
            <a
              href={getCarveArchiveUrl(env, name)}
              className={cn(
                'inline-block px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors',
              )}
            >
              Download archive
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

export default CarveDetailPage;
