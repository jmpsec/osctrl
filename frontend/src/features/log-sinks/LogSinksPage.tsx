import { useState, useMemo, useEffect, type ReactNode } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listLogSinks,
  listLogSinkTypes,
  createLogSink,
  updateLogSink,
  deleteLogSink,
  cloneLogSinks,
  applyLogSinks,
  getLogSink,
  type LogSink,
  type LogSinkTypeSpec,
  type LogSinkFieldSpec,
  type LogSinkCreateRequest,
} from '$/api/log-sinks';
import { listEnvironments } from '$/api/environments';
import { getFeatures } from '$/api/features';
import { getServiceCommand, getServiceConfig } from '$/api/service-config';
import { AuthError, ApiError } from '$/api/client';
import { formatRelative } from '$/lib/time';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { cn } from '$/lib/cn';

const GLOBAL_ENV_ID = 0;

// ---------------------------------------------------------------------------
// Per-type icons. All use the same 24×24 / stroke=1.5 convention as the
// side-nav and empty-state icons so they match the visual language. Each
// is a simple pictogram that reads as the sink's purpose at a glance.
// ---------------------------------------------------------------------------
const SINK_TYPE_ICONS: Record<string, ReactNode> = {
  // Discard — trash can
  none: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2M6 7l1 13a2 2 0 002 2h6a2 2 0 002-2l1-13M10 11v6M14 11v6" />
    </svg>
  ),
  // stdout — terminal/console
  stdout: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </svg>
  ),
  // file — document
  file: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z" />
      <path d="M14 3v6h6" />
    </svg>
  ),
  // db — cylinder
  db: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5" />
      <path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3" />
    </svg>
  ),
  // splunk — search/lens
  splunk: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="11" cy="11" r="7" />
      <path d="M16 16l4 4M11 8v6M8 11h6" />
    </svg>
  ),
  // graylog — layers/stash
  graylog: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M12 3l9 5-9 5-9-5 9-5z" />
      <path d="M3 13l9 5 9-5M3 17l9 5 9-5" />
    </svg>
  ),
  // logstash — pipeline/pipe
  logstash: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M4 5h6v6H4zM14 5h6v6h-6zM4 17h6v-4H4zM14 17h6v-4h-6z" />
    </svg>
  ),
  // kinesis — stream/waves
  kinesis: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M3 8c2 0 2-3 4-3s2 3 4 3 2-3 4-3 2 3 4 3" />
      <path d="M3 14c2 0 2-3 4-3s2 3 4 3 2-3 4-3 2 3 4 3" />
      <path d="M3 20c2 0 2-3 4-3s2 3 4 3 2-3 4-3 2 3 4 3" />
    </svg>
  ),
  // s3 — bucket
  s3: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M5 8l2 12a2 2 0 002 2h6a2 2 0 002-2l2-12" />
      <path d="M3 8h18M12 8c0-3-2-5-5-5s-5 2-5 5M12 8c0-3 2-5 5-5s5 2 5 5" />
    </svg>
  ),
  // kafka — message broker / arrows
  kafka: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="6" cy="12" r="2" />
      <path d="M8 12h4M12 8l4-2M12 16l4 2M16 6l2-1v14l-2-1M16 18l-4-2" />
    </svg>
  ),
  // elastic — magnifying chart
  elastic: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M3 12h4l2-5 3 10 2-5h7" />
    </svg>
  ),
};

/** Returns the icon for a sink type, or a default document icon. */
function sinkTypeIcon(type: string): ReactNode {
  return SINK_TYPE_ICONS[type] ?? SINK_TYPE_ICONS.file;
}

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'create' } // step 1: type picker
  | { kind: 'createType'; sinkType: string } // step 2: config form for chosen type
  | { kind: 'edit'; sink: LogSink }
  | { kind: 'clone' }
  | { kind: 'apply' };

/**
 * Log Sinks admin page.
 *
 * Lists log_sinks rows for the selected environment (Global by default),
 * with add/edit/delete, clone-from-another-env, and an Apply button that
 * queues a hot-reload of osctrl-tls. The Apply modal warns that in-flight
 * logs to the old sinks may be dropped during the swap.
 *
 * Visual/structural conventions mirror EnvironmentsPage / ServiceConfigPage:
 * sticky header bar, full-width table with SkeletonRow loading, EmptyState
 * for empty/error, ModalShell dialogs, CSS-var tokens only.
 */
export function LogSinksPage() {
  usePageTitle('Log Sinks');
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [selectedEnv, setSelectedEnv] = useState<number>(GLOBAL_ENV_ID);
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });
  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [reloading, setReloading] = useState(false);

  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  const configDisabled = features?.log_sinks === false;

  const { data: envs } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
  });

  const {
    data: sinks,
    isLoading,
    isFetching,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['log-sinks', selectedEnv],
    queryFn: () => listLogSinks({ env: selectedEnv }),
    enabled: !!features?.log_sinks,
    staleTime: 30_000,
  });

  const { data: types } = useQuery({
    queryKey: ['log-sinks-types'],
    queryFn: () => listLogSinkTypes(),
    staleTime: 60_000,
    enabled: !!features?.log_sinks,
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['log-sinks'] });
    void refetch();
  };

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteLogSink(id),
    onSuccess: () => invalidate(),
    onError: (e) => {
      if (e instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  const cloneMutation = useMutation({
    mutationFn: cloneLogSinks,
    onSuccess: () => {
      setModal({ kind: 'closed' });
      invalidate();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Clone failed');
    },
  });

  const applyMutation = useMutation({
    mutationFn: () => applyLogSinks(),
    onSuccess: (resp) => {
      setApplyErr(null);
      // osctrl-tls consumes the reload command asynchronously; poll the
      // command until it is consumed (status !== pending). Same pattern
      // as the service-config apply path.
      if (!resp.command) {
        setReloading(false);
        setApplyFlash(true);
        setTimeout(() => setApplyFlash(false), 3000);
        return;
      }
      setReloading(true);
      const poll = setInterval(() => {
        getServiceCommand(resp.command!.command_id)
          .then((cmd) => {
            if (cmd.status !== 'pending') {
              clearInterval(poll);
              setReloading(false);
              setApplyFlash(true);
              setTimeout(() => setApplyFlash(false), 3000);
            }
          })
          .catch(() => {
            clearInterval(poll);
            setReloading(false);
          });
      }, 1500);
    },
    onError: (e: unknown) => {
      setApplyErr(e instanceof Error ? e.message : String(e));
    },
  });

  // Early returns must come AFTER all hook calls so hook order stays
  // stable across renders (React rules of hooks).
  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  if (configDisabled) {
    return (
      <div className="flex flex-col h-full min-h-0">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
          <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
            Log Sinks
          </h1>
          <p className="text-xs text-[color:var(--text-3)]">
            Super-admin view. Manage osquery log destinations per environment.
          </p>
        </div>
        <div className="flex-1 overflow-auto min-h-0">
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title="Log Sinks API is disabled"
            description={
              'osctrl-api runs with service.serviceConfigEnabled = false, so the /api/v1/log-sinks endpoints are not registered. osctrl-tls still seeds its YAML logger section into the log_sinks table at startup, so sinks can be changed directly in the database and are picked up on the next restart. Set serviceConfigEnabled: true and restart osctrl-api to manage them here.'
            }
          />
        </div>
      </div>
    );
  }

  const rows = sinks ?? [];
  const sorted = [...rows].sort((a, b) => a.order - b.order || a.id - b.id);
  const hasPending = rows.some((r) => r.source === 'db');

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Sticky header — same shell as EnvironmentsPage / ServiceConfigPage. */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Log Sinks
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Per-environment osquery log destinations. Global sinks are the
          fallback for any environment without its own.
        </p>

        <div className="ml-auto flex items-center gap-2">
          {isFetching && !isLoading && (
            <span
              aria-live="polite"
              aria-label="Refreshing data"
              className="text-[10px] text-[color:var(--text-3)] font-mono-tabular"
            >
              refreshing…
            </span>
          )}
          <button
            type="button"
            onClick={() => setModal({ kind: 'clone' })}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
              'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            )}
          >
            Clone from…
          </button>
          <button
            type="button"
            onClick={() => setModal({ kind: 'create' })}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            New sink
          </button>
          <button
            type="button"
            disabled={reloading || !hasPending}
            title={
              !hasPending
                ? 'No unsaved changes — nothing to apply'
                : 'Hot-reload osctrl-tls with the current sink rows'
            }
            onClick={() => {
              setApplyErr(null);
              setModal({ kind: 'apply' });
            }}
            className={cn(
              'px-3 py-1 text-xs font-medium rounded transition-colors',
              reloading
                ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)]'
                : 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)] hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.2)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {reloading
              ? 'Reloading…'
              : applyFlash
                ? 'Reload triggered ✓'
                : 'Apply changes'}
          </button>
        </div>
      </div>

      {/* Environment selector — matches the inline control style in EnvConfigPage. */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-[color:var(--border)] text-xs">
        <label
          htmlFor="log-sinks-env"
          className="text-[color:var(--text-2)] font-semibold"
        >
          Environment
        </label>
        <select
          id="log-sinks-env"
          value={selectedEnv}
          onChange={(e) => setSelectedEnv(Number(e.target.value))}
          aria-label="Select environment whose sinks to show"
          className={cn(
            'px-2 py-1 rounded font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        >
          <option value={GLOBAL_ENV_ID}>Global (fallback for all)</option>
          {envs?.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
        <span className="text-[color:var(--text-3)]">
          {selectedEnv === GLOBAL_ENV_ID
            ? 'Used by every environment that has no sinks of its own.'
            : 'Overrides the global set for this environment.'}
        </span>
      </div>

      {/* Apply-error toast — mirrors the bulk-error toast in EnvironmentsPage. */}
      {applyErr && (
        <div
          role="alert"
          className={cn(
            'flex items-center gap-3 px-4 py-2.5 border-b',
            'border-[color:var(--danger)]/40 bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)]',
            'text-xs text-[color:var(--danger)]',
          )}
        >
          <span>{applyErr}</span>
          <button
            type="button"
            onClick={() => setApplyErr(null)}
            className="ml-auto text-[color:var(--text-3)] hover:text-[color:var(--text-1)]"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide w-16">
                Order
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Name
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Type
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide w-24">
                Enabled
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide w-24">
                Source
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Updated
              </th>
              <th scope="col" className="px-2 py-3 w-1" />
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={7} />)}

            {isError && !isLoading && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 8v4M12 16h.01" />
                      </svg>
                    }
                    title={error instanceof Error ? error.message : 'Failed to load log sinks'}
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

            {!isLoading && !isError && sorted.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <rect x="3" y="3" width="18" height="18" rx="2" />
                        <path d="M3 9h18M9 21V9" />
                      </svg>
                    }
                    title={
                      selectedEnv === GLOBAL_ENV_ID
                        ? 'No global log sinks.'
                        : `No sinks for ${envNameFor(envs ?? [], selectedEnv)}.`
                    }
                    description={
                      selectedEnv === GLOBAL_ENV_ID
                        ? 'Add one to start forwarding osquery status, result, and query logs to a destination.'
                        : 'This environment inherits the global sinks. Add one here to override.'
                    }
                    action={
                      <button
                        type="button"
                        onClick={() => setModal({ kind: 'create' })}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Add a sink
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              sorted.map((s) => (
                <tr
                  key={s.id}
                  className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors"
                >
                  <td className="px-4 py-3 text-xs font-mono-tabular text-[color:var(--text-3)]">
                    {s.order}
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular">
                        {s.name}
                      </span>
                      {s.info && (
                        <span className="text-[10px] text-[color:var(--text-3)] truncate max-w-[240px]" title={s.info}>
                          — {s.info}
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    <span className="flex items-center gap-1.5">
                      <span className="w-4 h-4 flex-shrink-0 text-[color:var(--text-3)]">
                        {sinkTypeIcon(s.type)}
                      </span>
                      <span className="font-mono-tabular">{s.type}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {s.enabled ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.12)] text-[color:var(--success)]">
                        on
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[color:var(--bg-2)] text-[color:var(--text-3)]">
                        off
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {s.source === 'db' ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]">
                        edited
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[color:var(--bg-2)] text-[color:var(--text-3)]" title={`Seeded from service configuration (source: ${s.source})`}>
                        seed
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-[color:var(--text-2)] text-right font-mono-tabular">
                    <span title={s.updated_at}>{formatRelative(s.updated_at)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'edit', sink: s })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      disabled={deleteMutation.isPending}
                      onClick={() => {
                        if (confirm(`Delete sink "${s.name}"? It will be removed on the next Apply.`)) {
                          deleteMutation.mutate(s.id);
                        }
                      }}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* Modals — same ModalShell + form conventions as EnvironmentsPage. */}
      {modal.kind === 'create' && (
        <SinkTypePicker
          types={types ?? []}
          onPick={(t) => setModal({ kind: 'createType', sinkType: t })}
          onClose={() => setModal({ kind: 'closed' })}
        />
      )}
      {modal.kind === 'createType' && (
        <SinkEditor
          mode="create"
          types={types ?? []}
          sinkType={modal.sinkType}
          envID={selectedEnv}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'edit' && (
        <SinkEditor
          mode="edit"
          types={types ?? []}
          sinkType={modal.sink.type}
          envID={selectedEnv}
          existing={modal.sink}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'clone' && (
        <CloneModal
          envs={envs ?? []}
          targetEnv={selectedEnv}
          pending={cloneMutation.isPending}
          error={
            cloneMutation.error instanceof ApiError
              ? cloneMutation.error.message
              : cloneMutation.error instanceof Error
                ? cloneMutation.error.message
                : null
          }
          onClone={(req) => cloneMutation.mutate(req)}
          onClose={() => setModal({ kind: 'closed' })}
        />
      )}
      {modal.kind === 'apply' && (
        <ApplyConfirmDialog
          pendingSinks={sorted.filter((s) => s.source === 'db')}
          isPending={reloading}
          onConfirm={() => {
            setModal({ kind: 'closed' });
            applyMutation.mutate();
          }}
          onCancel={() => setModal({ kind: 'closed' })}
        />
      )}
    </div>
  );
}

function envNameFor(envs: { id: number; name: string }[], envID: number): string {
  if (envID === GLOBAL_ENV_ID) return 'Global';
  return envs.find((e) => e.id === envID)?.name ?? `Env ${envID}`;
}

// ---------------------------------------------------------------------------
// Step 1: type picker modal — a compact grid of sink types. Selecting
// one advances to the config form (SinkEditor) for that type only, so
// the form stays short and never overflows the viewport.
// ---------------------------------------------------------------------------
function SinkTypePicker({
  types,
  onPick,
  onClose,
}: {
  types: LogSinkTypeSpec[];
  onPick: (sinkType: string) => void;
  onClose: () => void;
}) {
  return (
    <ModalShell
      title="New log sink"
      titleId="log-sink-type-picker-title"
      onClose={onClose}
      panelClassName="max-w-lg"
    >
      <div className="space-y-3">
        <p className="text-xs text-[color:var(--text-3)]">
          Choose a destination type. The next step configures its fields.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {types.map((t) => (
            <button
              key={t.type}
              type="button"
              onClick={() => onPick(t.type)}
              className={cn(
                'flex items-start gap-3 px-3 py-2.5 rounded-md text-left',
                'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
                'hover:border-[color:var(--signal)] hover:bg-[color:var(--bg-1)]',
                'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              )}
            >
              <span className="flex-shrink-0 w-5 h-5 text-[color:var(--text-3)] mt-0.5">
                {sinkTypeIcon(t.type)}
              </span>
              <span className="flex flex-col gap-0.5 min-w-0">
                <span className="text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular">
                  {t.type}
                </span>
                <span className="text-[10px] text-[color:var(--text-3)]">
                  {t.description}
                </span>
              </span>
            </button>
          ))}
        </div>
        <div className="flex justify-end pt-1">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Step 2: create / edit modal for one sink type. The type is fixed
// (chosen in step 1 for create, inherited from the existing row for edit)
// so the form only shows the config fields for that type — no long
// all-types dropdown, no overflow.
// ---------------------------------------------------------------------------
function SinkEditor({
  mode,
  types,
  sinkType,
  envID,
  existing,
  onClose,
  onSaved,
}: {
  mode: 'create' | 'edit';
  types: LogSinkTypeSpec[];
  sinkType: string;
  envID: number;
  existing?: LogSink;
  onClose: () => void;
  onSaved: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [order, setOrder] = useState(existing?.order ?? 0);
  const [info, setInfo] = useState(existing?.info ?? '');
  const [err, setErr] = useState<string | null>(null);

  const spec = useMemo(
    () => types.find((t) => t.type === sinkType),
    [types, sinkType],
  );

  // Field values are a flat map keyed by the field's dotted Name. The
  // buildConfig() helper expands dotted keys into nested objects before
  // sending to the API. Initial values come from the existing config
  // (decoded into a flat map) or from the spec defaults on create.
  const [fieldValues, setFieldValues] = useState<Record<string, unknown>>(() =>
    existing ? flattenConfig(existing.config) : defaultsForSpec(spec),
  );

  // When editing a secret-bearing sink, fetch the revealed config so the
  // operator can see the current secret value before deciding to change
  // it. Merge the revealed secret fields into the existing field values
  // rather than replacing the whole form — the operator may have already
  // edited non-secret fields.
  const revealSecret = useQuery({
    queryKey: ['log-sink-reveal', existing?.id],
    queryFn: () => getLogSink(existing!.id, true),
    enabled: mode === 'edit' && !!existing && !!spec?.has_secret,
    staleTime: 0,
  });
  useEffect(() => {
    if (!revealSecret.data || !existing || revealSecret.data.id !== existing.id) return;
    const revealedFlat = flattenConfig(revealSecret.data.config);
    setFieldValues((prev) => {
      const next = { ...prev };
      for (const f of spec?.fields ?? []) {
        if (f.secret && revealedFlat[f.name] !== undefined) {
          next[f.name] = revealedFlat[f.name];
        }
      }
      return next;
    });
  }, [revealSecret.data, existing, spec]);

  const mutation = useMutation({
    mutationFn: async () => {
      const trimmedName = name.trim();
      if (!trimmedName) throw new Error('Name is required.');
      const config = buildConfig(spec, fieldValues);
      if (mode === 'create') {
        const body: LogSinkCreateRequest = {
          name: trimmedName,
          type: sinkType,
          enabled,
          order,
          config,
          environment_id: envID,
          info: info.trim() || undefined,
        };
        return createLogSink(body);
      }
      return updateLogSink(existing!.id, {
        name: trimmedName,
        type: sinkType,
        enabled,
        order,
        config,
        info: info.trim() || undefined,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['log-sinks'] });
      onSaved();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const inputClass = cn(
    'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
  );

  return (
    <ModalShell
      title={mode === 'create' ? `Add ${sinkType} sink` : `Edit ${existing?.name}`}
      titleId="log-sink-editor-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label
            htmlFor="sink-name"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            Name
          </label>
          <input
            id="sink-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. prod-splunk"
            className={inputClass}
          />
          <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
            Unique label for this sink within its environment.
          </p>
        </div>

        {/* Type is fixed (chosen in step 1 for create, inherited for
            edit). Show it as a read-only badge so the operator always
            knows which sink type they are configuring. */}
        <div>
          <span className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Type
          </span>
          <span className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[color:var(--bg-2)] border border-[color:var(--border)] text-sm font-mono-tabular text-[color:var(--text-1)]">
            <span className="w-4 h-4 flex-shrink-0 text-[color:var(--text-3)]">
              {sinkTypeIcon(sinkType)}
            </span>
            {sinkType}
          </span>
          {spec?.has_secret && (
            <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
              This sink type stores credentials ({spec.secret_fields?.join(', ')}).
              {mode === 'edit' && ' Secret fields are revealed below for editing.'}
            </p>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label
              htmlFor="sink-order"
              className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
            >
              Order
            </label>
            <input
              id="sink-order"
              type="number"
              value={order}
              onChange={(e) => setOrder(Number(e.target.value))}
              className={inputClass}
            />
          </div>
          <fieldset className="flex items-end gap-2 pb-2">
            <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
              />
              <span className="font-mono-tabular">enabled</span>
            </label>
          </fieldset>
        </div>

        {/* Dynamic typed config fields. Rendered from the schema so the
            operator gets the right input per field instead of a raw JSON
            blob. Secret fields use a password input and are pre-filled
            from the reveal query when editing. */}
        <SinkConfigFields
          key={sinkType}
          spec={spec}
          values={fieldValues}
          onChange={setFieldValues}
          inputClass={inputClass}
        />

        <div>
          <label
            htmlFor="sink-info"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            Info (optional)
          </label>
          <input
            id="sink-info"
            type="text"
            value={info}
            onChange={(e) => setInfo(e.target.value)}
            className={inputClass}
          />
        </div>

        {err && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {err}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending || !name.trim()}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : mode === 'create' ? 'Add sink' : 'Save changes'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

/**
 * SinkConfigFields renders the dynamic typed form for one sink type's
 * config. Each field in spec.fields becomes the appropriate input
 * (text, number, checkbox, select, password) using the shared inputClass
 * so the styling matches every other form in the app.
 */
function SinkConfigFields({
  spec,
  values,
  onChange,
  inputClass,
}: {
  spec?: LogSinkTypeSpec;
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  inputClass: string;
}) {
  const [copyErr, setCopyErr] = useState<string | null>(null);
  const [copying, setCopying] = useState(false);

  if (!spec || !spec.fields || spec.fields.length === 0) {
    return (
      <p className="text-[10px] text-[color:var(--text-3)] italic">
        This sink type has no configurable fields.
      </p>
    );
  }

  function setField(name: string, v: unknown) {
    onChange({ ...values, [name]: v });
  }

  // "Copy from existing DB" — fetches the osctrl-tls db section from
  // the service-config API and populates the form fields. Only shown
  // for the db sink type, since that's the one where re-typing the
  // primary DB connection is tedious and error-prone.
  async function copyFromExistingDB() {
    setCopyErr(null);
    setCopying(true);
    try {
      const sc = await getServiceConfig('tls', 'db');
      // The service-config API serializes the db section with
      // json.Marshal, which produces Go struct field names (Type, Host,
      // Port, ...) rather than the lowercase yaml/json tags the sink
      // field schema uses (type, host, port, ...). Build a lowercased
      // lookup map so every field matches regardless of case.
      const raw = JSON.parse(sc.Value) as Record<string, unknown>;
      const dbCfg: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(raw)) {
        dbCfg[k.toLowerCase()] = v;
      }
      const next: Record<string, unknown> = { ...values };
      for (const f of spec?.fields ?? []) {
        const flatName = f.name.replace(/^.*\./, '');
        if (flatName in dbCfg) {
          next[f.name] = dbCfg[flatName];
        }
      }
      onChange(next);
    } catch (e) {
      setCopyErr(e instanceof Error ? e.message : 'Failed to copy DB config');
    } finally {
      setCopying(false);
    }
  }

  return (
    <fieldset className="space-y-3 border border-[color:var(--border)] rounded-md p-3">
      <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">
        Configuration
      </legend>
      {spec.type === 'db' && (
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={copyFromExistingDB}
            disabled={copying}
            className={cn(
              'px-2.5 py-1 text-[11px] font-medium rounded',
              'border border-[color:var(--border)] text-[color:var(--text-2)]',
              'hover:bg-[color:var(--bg-2)] transition-colors',
              'disabled:opacity-50',
            )}
          >
            {copying ? 'Copying…' : 'Copy from existing DB'}
          </button>
          <span className="text-[10px] text-[color:var(--text-3)]">
            Pre-fills from the osctrl-tls db section.
          </span>
          {copyErr && (
            <span className="text-[10px] text-[color:var(--danger)]">{copyErr}</span>
          )}
        </div>
      )}
      {spec.fields.map((f) => (
        <ConfigField
          key={f.name}
          field={f}
          value={values[f.name]}
          onChange={(v) => setField(f.name, v)}
          inputClass={inputClass}
        />
      ))}
    </fieldset>
  );
}

function ConfigField({
  field,
  value,
  onChange,
  inputClass,
}: {
  field: LogSinkFieldSpec;
  value: unknown;
  onChange: (v: unknown) => void;
  inputClass: string;
}) {
  const id = `sink-cfg-${field.name.replace(/\./g, '-')}`;
  const labelEl = (
    <label
      htmlFor={id}
      className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
    >
      {field.label}
      {field.required && <span className="text-[color:var(--danger)]" aria-hidden="true"> *</span>}
    </label>
  );
  const helpEl = field.help && (
    <p className="mt-1 text-[10px] text-[color:var(--text-3)]">{field.help}</p>
  );

  // Group secret fields under a label that makes the reveal-on-edit
  // behavior obvious.
  const secretHint = field.secret && (
    <span className="ml-2 text-[10px] text-[color:var(--text-3)]">(secret)</span>
  );

  switch (field.type) {
    case 'boolean':
      return (
        <div>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              id={id}
              type="checkbox"
              aria-label={field.label}
              checked={Boolean(value)}
              onChange={(e) => onChange(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="font-mono-tabular">{field.label}</span>
            {secretHint}
          </label>
          {helpEl}
        </div>
      );
    case 'integer':
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="number"
            aria-label={field.label}
            value={value === undefined || value === null ? '' : String(value)}
            onChange={(e) => {
              const raw = e.target.value;
              onChange(raw === '' ? undefined : Number(raw));
            }}
            placeholder={field.placeholder}
            className={inputClass}
          />
          {helpEl}
        </div>
      );
    case 'select':
      return (
        <div>
          {labelEl}
          <select
            id={id}
            aria-label={field.label}
            value={String(value ?? '')}
            onChange={(e) => onChange(e.target.value)}
            className={inputClass}
          >
            {field.options?.map((opt) => (
              <option key={opt} value={opt}>
                {opt === '' ? '— none —' : opt}
              </option>
            ))}
          </select>
          {helpEl}
        </div>
      );
    case 'password':
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="password"
            aria-label={field.label}
            value={String(value ?? '')}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            autoComplete="off"
            className={cn(inputClass, 'text-[color:var(--text-2)]')}
          />
          {helpEl}
        </div>
      );
    case 'string':
    default:
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="text"
            aria-label={field.label}
            value={String(value ?? '')}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            className={inputClass}
          />
          {helpEl}
        </div>
      );
  }
}

// --- config (de)serialization helpers -------------------------------------

/**
 * defaultsForSpec returns a flat field-value map seeded from the spec's
 * field defaults. Used as the initial form state on create.
 */
function defaultsForSpec(spec?: LogSinkTypeSpec): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of spec?.fields ?? []) {
    if (f.default !== undefined && f.default !== null && f.default !== '') {
      out[f.name] = f.default;
    }
  }
  return out;
}

/**
 * flattenConfig reads a nested config object (the decoded JSON from the
 * API) and returns a flat map keyed by dotted field names, e.g.
 * { "sasl": { "mechanism": "x" } } -> { "sasl.mechanism": "x" }.
 * Only one level of nesting is supported — that matches every sink
 * config schema currently in the registry (Kafka SASL is the only
 * nested one).
 */
function flattenConfig(config: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (typeof config !== 'object' || config === null || Array.isArray(config)) return out;
  const obj = config as Record<string, unknown>;
  for (const [k, v] of Object.entries(obj)) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      for (const [k2, v2] of Object.entries(v as Record<string, unknown>)) {
        out[`${k}.${k2}`] = v2;
      }
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * buildConfig expands the flat field-value map back into the nested
 * shape the API expects. Dotted keys (e.g. "sasl.mechanism") become
 * nested objects. Empty/undefined values are omitted so the config JSON
 * only carries fields the operator actually set.
 */
function buildConfig(
  spec: LogSinkTypeSpec | undefined,
  values: Record<string, unknown>,
): unknown {
  const out: Record<string, unknown> = {};
  for (const f of spec?.fields ?? []) {
    const v = values[f.name];
    if (v === undefined || v === null || v === '') continue;
    setDotted(out, f.name, v);
  }
  return out;
}

function setDotted(obj: Record<string, unknown>, key: string, value: unknown) {
  const parts = key.split('.');
  if (parts.length === 1) {
    obj[parts[0]] = value;
    return;
  }
  const [head, ...rest] = parts;
  if (typeof obj[head] !== 'object' || obj[head] === null) {
    obj[head] = {};
  }
  setDotted(obj[head] as Record<string, unknown>, rest.join('.'), value);
}

// ---------------------------------------------------------------------------
// Clone modal — mirrors the form layout of CreateEnvModal
// ---------------------------------------------------------------------------
function CloneModal({
  envs,
  targetEnv,
  pending,
  error,
  onClone,
  onClose,
}: {
  envs: { id: number; name: string }[];
  targetEnv: number;
  pending: boolean;
  error: string | null;
  onClone: (req: {
    source_environment_id: number;
    target_environment_id: number;
    overwrite: boolean;
  }) => void;
  onClose: () => void;
}) {
  const [source, setSource] = useState<number>(GLOBAL_ENV_ID);
  const [target, setTarget] = useState<number>(targetEnv);
  const [overwrite, setOverwrite] = useState(false);

  const selectClass = cn(
    'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
  );

  return (
    <ModalShell
      title="Clone log sinks"
      titleId="log-sinks-clone-title"
      onClose={onClose}
      panelClassName="max-w-md"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onClone({ source_environment_id: source, target_environment_id: target, overwrite });
        }}
        className="space-y-4"
      >
        <p className="text-xs text-[color:var(--text-3)]">
          Copy all sinks from one environment to another. The target gets new
          rows with names suffixed “(clone of …)” so they stay unique.
        </p>

        <div>
          <label
            htmlFor="clone-source"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            Source
          </label>
          <select
            id="clone-source"
            value={source}
            onChange={(e) => setSource(Number(e.target.value))}
            className={selectClass}
          >
            <option value={GLOBAL_ENV_ID}>Global</option>
            {envs.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor="clone-target"
            className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
          >
            Target
          </label>
          <select
            id="clone-target"
            value={target}
            onChange={(e) => setTarget(Number(e.target.value))}
            className={selectClass}
          >
            <option value={GLOBAL_ENV_ID}>Global</option>
            {envs.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
        </div>

        <fieldset className="space-y-2 border border-[color:var(--border)] rounded-md p-3">
          <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">
            Options
          </legend>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              type="checkbox"
              checked={overwrite}
              onChange={(e) => setOverwrite(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="font-mono-tabular">overwrite</span>
            <span className="text-[color:var(--text-3)]">
              — delete the target’s existing sinks first
            </span>
          </label>
        </fieldset>

        {error && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {error}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={pending || source === target}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {pending ? 'Cloning…' : 'Clone'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Apply confirmation — mirrors ServiceConfigPage's ApplyConfirmDialog
// ---------------------------------------------------------------------------
function ApplyConfirmDialog({
  pendingSinks,
  isPending,
  onConfirm,
  onCancel,
}: {
  pendingSinks: LogSink[];
  isPending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <ModalShell
      title="Apply sink changes"
      titleId="log-sinks-apply-title"
      onClose={onCancel}
      panelClassName="max-w-md"
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This will hot-reload osctrl-tls with the current sink rows. The
          service is not restarted, but{' '}
          <strong className="text-[color:var(--warning)]">
            logs in-flight to the old sinks may be dropped
          </strong>{' '}
          during the swap — the old sinks are closed the moment the new set
          is live.
        </p>

        <div className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)] p-3">
          <p className="text-[10px] uppercase tracking-[0.08em] text-[color:var(--text-3)] mb-2">
            Pending changes ({pendingSinks.length})
          </p>
          {pendingSinks.length === 0 ? (
            <p className="text-xs text-[color:var(--text-3)]">
              No DB-edited sinks — reloading will just re-read the current
              rows.
            </p>
          ) : (
            <ul className="space-y-1">
              {pendingSinks.map((s) => (
                <li
                  key={s.id}
                  className="flex items-center gap-2 text-xs text-[color:var(--text-2)]"
                >
                  <span className="w-4 h-4 flex-shrink-0 text-[color:var(--text-3)]">
                    {sinkTypeIcon(s.type)}
                  </span>
                  <span className="font-mono-tabular text-[color:var(--text-1)]">
                    {s.name}
                  </span>
                  <span className="text-[color:var(--text-3)]">— {s.type}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={isPending}
            className="px-3 py-1.5 text-xs font-medium rounded border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded transition-colors',
              'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]',
              'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]',
              'disabled:opacity-40 disabled:cursor-not-allowed',
            )}
          >
            {isPending ? 'Reloading…' : 'Reload now'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// Kept for parity with other feature modules that export a default.
export default LogSinksPage;
