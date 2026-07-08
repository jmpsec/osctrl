import { useState } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listEnvironments,
  createEnvironment,
  updateEnvironment,
  deleteEnvironment,
  type TLSEnvironment,
} from '$/api/environments';
import { AuthError, ApiError } from '$/api/client';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; env: TLSEnvironment }
  | { kind: 'delete'; env: TLSEnvironment };

export function EnvironmentsPage() {
  usePageTitle('Environments');
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  // Multi-select state — matches the dock pattern used on Tags / Carves
  // / Nodes / Users. Keyed by env name since DELETE /environments/{env}
  // accepts the name as the path param.
  const [selectedNames, setSelectedNames] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const envs = data ?? [];

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['environments'] });
    void refetch();
  }

  // Header checkbox state — same shape as TagsPage's toggleAll.
  const allVisibleNames = envs.map((e) => e.name);
  const allChecked =
    allVisibleNames.length > 0 &&
    allVisibleNames.every((n) => selectedNames.has(n));
  const someChecked = allVisibleNames.some((n) => selectedNames.has(n));

  function toggleAll() {
    if (allChecked) {
      setSelectedNames(new Set());
    } else {
      setSelectedNames(new Set(allVisibleNames));
    }
  }

  function toggleOne(name: string) {
    setSelectedNames((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  // Bulk delete — the backend's Environments.Delete is a hard
  // (unscoped) DB delete with no cascade check, so we surface the
  // destructive nature in the confirm prompt. Per-name Promise.allSettled
  // so a failing env doesn't block the rest.
  const bulkDeleteMut = useMutation({
    mutationFn: async (names: string[]) => {
      const settled = await Promise.allSettled(
        names.map((name) => deleteEnvironment(name)),
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;
      return { total: names.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      setSelectedNames(new Set());
      if (failed > 0) {
        setBulkError(`Deleted ${total - failed} of ${total} env(s); ${failed} failed.`);
      } else {
        setBulkError(null);
      }
      invalidate();
    },
    onError: (err) => {
      if (err instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setBulkError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'Bulk delete failed',
      );
    },
  });

  function handleBulkDelete() {
    const names = Array.from(selectedNames);
    if (names.length === 0) return;
    if (
      !confirm(
        `Delete ${names.length} environment${names.length === 1 ? '' : 's'}?\n\nNodes, queries, carves, and tags scoped to ${names.length === 1 ? 'this env' : 'these envs'} will be orphaned. This is not recoverable.`,
      )
    ) {
      return;
    }
    setBulkError(null);
    bulkDeleteMut.mutate(names);
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Environments
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Super-admin view. Create and manage osquery environments.
        </p>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => setModal({ kind: 'create' })}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            New environment
          </button>

          {isFetching && !isLoading && (
            <span
              aria-live="polite"
              aria-label="Refreshing data"
              className="text-[10px] text-[color:var(--text-3)] font-mono-tabular"
            >
              refreshing…
            </span>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  aria-label="Select all visible environments"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked && !allChecked;
                  }}
                  onChange={toggleAll}
                  className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                />
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Name
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Hostname
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                UUID
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Enrolls
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Created
              </th>
              <th scope="col" className="px-4 py-3 w-1" />
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
                    title={error instanceof Error ? error.message : 'Failed to load environments'}
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

            {!isLoading && !isError && envs.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <rect x="3" y="3" width="18" height="18" rx="2" />
                        <path d="M3 9h18" />
                      </svg>
                    }
                    title="No environments yet."
                    action={
                      <button
                        type="button"
                        onClick={() => setModal({ kind: 'create' })}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Create your first environment
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              envs.map((env) => {
                const isSelected = selectedNames.has(env.name);
                return (
                <tr
                  key={env.id}
                  className={cn(
                    'border-b border-[color:var(--border)] hover:bg-[color:var(--bg-2)] transition-colors',
                    isSelected && 'bg-[color:var(--signal)]/5',
                  )}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      aria-label={`Select environment ${env.name}`}
                      checked={isSelected}
                      onChange={() => toggleOne(env.name)}
                      className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular">
                      {env.name}
                    </span>
                    {env.type && (
                      <span className="ml-2 text-[10px] text-[color:var(--text-3)] uppercase tracking-wider">
                        {env.type}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs font-mono-tabular">
                    {env.hostname || '—'}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-3)] text-xs font-mono-tabular truncate max-w-[180px]" title={env.uuid}>
                    {env.uuid}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {env.accept_enrolls ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.12)] text-[color:var(--success)]">
                        accepting
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[color:var(--bg-2)] text-[color:var(--text-3)]">
                        paused
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                    <span title={env.created_at}>{formatRelative(env.created_at)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => void navigate({
                        to: '/_app/env/$env/config',
                        params: { env: env.uuid },
                      })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Config…
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'edit', env })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'delete', env })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* Multi-select dock — matches CarvesListPage / TagsPage / UsersPage. */}
      {selectedNames.size > 0 && (
        <div
          role="toolbar"
          aria-label="Bulk actions"
          className={cn(
            'fixed bottom-6 left-1/2 -translate-x-1/2',
            'flex items-center gap-3 px-4 py-2.5 rounded-xl',
            'bg-[color:var(--bg-1)] border border-[color:var(--border-strong)]',
            'shadow-[0_8px_32px_rgba(0,0,0,0.32)]',
            'text-sm font-medium',
            'z-50',
          )}
        >
          <span className="text-[color:var(--text-2)] text-xs font-mono-tabular">
            {selectedNames.size} selected
          </span>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          {bulkError && (
            <span className="text-xs text-[color:var(--danger)]">{bulkError}</span>
          )}
          <button
            type="button"
            disabled={bulkDeleteMut.isPending}
            aria-label="Delete selected environments"
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-50"
            onClick={handleBulkDelete}
          >
            {bulkDeleteMut.isPending ? 'Deleting…' : 'Delete'}
          </button>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          <button
            type="button"
            aria-label="Clear selection"
            onClick={() => setSelectedNames(new Set())}
            className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Clear
          </button>
        </div>
      )}

      {/* Bulk-error toast after selection clears. */}
      {bulkError && selectedNames.size === 0 && (
        <div
          role="alert"
          className={cn(
            'fixed bottom-6 left-1/2 -translate-x-1/2 z-50',
            'flex items-center gap-3 px-4 py-2.5 rounded-xl',
            'bg-[color:var(--bg-1)] border border-[color:var(--danger)]/40',
            'shadow-[0_8px_32px_rgba(0,0,0,0.32)]',
            'text-xs text-[color:var(--danger)]',
          )}
        >
          <span>{bulkError}</span>
          <button
            type="button"
            onClick={() => setBulkError(null)}
            className="text-[color:var(--text-3)] hover:text-[color:var(--text-1)]"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}

      {modal.kind === 'create' && (
        <CreateEnvModal
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'edit' && (
        <EditEnvModal
          env={modal.env}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'delete' && (
        <DeleteEnvModal
          env={modal.env}
          onClose={() => setModal({ kind: 'closed' })}
          onDeleted={invalidate}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create modal
// ---------------------------------------------------------------------------
function CreateEnvModal({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState('');
  const [hostname, setHostname] = useState('');
  const [type, setType] = useState('osquery');
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => {
      const trimmedName = name.trim();
      const trimmedHost = hostname.trim();
      if (!trimmedName) throw new Error('Name is required.');
      if (!trimmedHost) throw new Error('Hostname is required.');
      return createEnvironment({ name: trimmedName, hostname: trimmedHost, type: type.trim() });
    },
    onSuccess: () => {
      onSaved();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 409) {
        setErr('An environment with that name already exists.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Create failed');
    },
  });

  return (
    <ModalShell title="Create environment" titleId="env-create-modal-title" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label htmlFor="env-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Name
          </label>
          <input
            id="env-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. production"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
          <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
            Short identifier used in URLs and CLI commands.
          </p>
        </div>

        <div>
          <label htmlFor="env-host" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Hostname
          </label>
          <input
            id="env-host"
            type="text"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="osctrl.example.com"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
          <p className="mt-1 text-[10px] text-[color:var(--text-3)]">
            Public hostname agents will phone home to (used for enroll links).
          </p>
        </div>

        <div>
          <label htmlFor="env-type" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Type
          </label>
          <input
            id="env-type"
            type="text"
            value={type}
            onChange={(e) => setType(e.target.value)}
            placeholder="osquery"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
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
            disabled={mutation.isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Creating…' : 'Create environment'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Edit modal — name/hostname/type/icon/debug/accept_enrolls
// ---------------------------------------------------------------------------
function EditEnvModal({
  env,
  onClose,
  onSaved,
}: {
  env: TLSEnvironment;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(env.name);
  const [hostname, setHostname] = useState(env.hostname);
  const [type, setType] = useState(env.type);
  const [icon, setIcon] = useState(env.icon);
  const [debugHttp, setDebugHttp] = useState(env.debug_http);
  const [acceptEnrolls, setAcceptEnrolls] = useState(env.accept_enrolls);
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => {
      const body = {
        name: name.trim(),
        hostname: hostname.trim(),
        type: type.trim(),
        icon: icon.trim(),
        debug_http: debugHttp,
        accept_enrolls: acceptEnrolls,
      };
      return updateEnvironment(env.uuid, body);
    },
    onSuccess: () => {
      onSaved();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 404) {
        setErr('Environment not found.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Update failed');
    },
  });

  return (
    <ModalShell title={`Edit ${env.name}`} titleId="env-edit-modal-title" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="edit-env-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Name
            </label>
            <input
              id="edit-env-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            />
          </div>
          <div>
            <label htmlFor="edit-env-type" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Type
            </label>
            <input
              id="edit-env-type"
              type="text"
              value={type}
              onChange={(e) => setType(e.target.value)}
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            />
          </div>
        </div>

        <div>
          <label htmlFor="edit-env-host" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Hostname
          </label>
          <input
            id="edit-env-host"
            type="text"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
        </div>

        <div>
          <label htmlFor="edit-env-icon" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Icon class
          </label>
          <input
            id="edit-env-icon"
            type="text"
            value={icon}
            onChange={(e) => setIcon(e.target.value)}
            placeholder="fas fa-wrench"
            className={cn(
              'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
              'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
        </div>

        <fieldset className="space-y-2 border border-[color:var(--border)] rounded-md p-3">
          <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">Flags</legend>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              type="checkbox"
              checked={acceptEnrolls}
              onChange={(e) => setAcceptEnrolls(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="font-mono-tabular">accept_enrolls</span>
            <span className="text-[color:var(--text-3)]">
              — whether this env accepts new node enrollments
            </span>
          </label>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              type="checkbox"
              checked={debugHttp}
              onChange={(e) => setDebugHttp(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="font-mono-tabular">debug_http</span>
            <span className="text-[color:var(--text-3)]">
              — log full HTTP request/response bodies (noisy)
            </span>
          </label>
        </fieldset>

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
            disabled={mutation.isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Delete confirmation modal — requires typing the env name
// ---------------------------------------------------------------------------
function DeleteEnvModal({
  env,
  onClose,
  onDeleted,
}: {
  env: TLSEnvironment;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () => deleteEnvironment(env.uuid),
    onSuccess: () => {
      onDeleted();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  const matches = confirm.trim() === env.name;

  return (
    <ModalShell title="Delete environment" titleId="env-delete-modal-title" onClose={onClose}>
      <p className="text-sm text-[color:var(--text-1)]">
        Delete <strong className="font-mono-tabular">{env.name}</strong>? Any nodes,
        tags, queries, or carves bound to it remain in the database but become
        inaccessible from the SPA. This cannot be undone.
      </p>

      <div className="mt-4">
        <label
          htmlFor="delete-env-confirm"
          className="block text-xs font-semibold text-[color:var(--text-2)] mb-1"
        >
          Type <code className="font-mono-tabular">{env.name}</code> to confirm
        </label>
        <input
          id="delete-env-confirm"
          type="text"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="off"
          className={cn(
            'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
            'focus:outline focus:outline-2 focus:outline-[color:var(--danger)]',
          )}
        />
      </div>

      {err && (
        <p
          role="alert"
          className="mt-3 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
        >
          {err}
        </p>
      )}

      <div className="flex items-center justify-end gap-2 mt-4">
        <button
          type="button"
          onClick={onClose}
          className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={!matches || mutation.isPending}
          onClick={() => mutation.mutate()}
          className={cn(
            'px-3 py-1.5 text-xs font-medium rounded-md',
            'bg-[color:var(--danger)] text-white hover:opacity-90',
            'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--danger)]',
            'disabled:opacity-50 disabled:cursor-not-allowed',
          )}
        >
          {mutation.isPending ? 'Deleting…' : 'Delete'}
        </button>
      </div>
    </ModalShell>
  );
}

export default EnvironmentsPage;
