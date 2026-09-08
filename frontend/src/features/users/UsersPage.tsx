import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { usePageTitle } from '$/lib/usePageTitle';
import { useLocale } from '$/i18n/useLocale';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listUsers,
  getUserPermissions,
  setUserPermissions,
  setUserPermissionsAllSafe,
  refreshUserToken,
  deleteUserToken,
  createUser,
  deleteUser,
  adminResetUserPassword,
  getMe,
} from '$/api/users';
import type { BulkSetReport } from '$/api/users';
import { listEnvironments } from '$/api/environments';
import { AuthError, ApiError } from '$/api/client';
import type { AdminUser, EnvAccess, TokenResponse } from '$/api/types';
import { formatRelative } from '$/lib/time';
import { cn } from '$/lib/cn';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { MetadataBadge } from '$/components/data/MetadataBadge';
import { Button } from '$/components/atoms/Button';

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'permissions'; user: AdminUser }
  | { kind: 'token'; user: AdminUser }
  | { kind: 'create' }
  | { kind: 'delete'; user: AdminUser }
  | { kind: 'reset-pw'; user: AdminUser };

export function UsersPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.users'));
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  // Multi-select state matches the dock pattern used on Tags / Carves /
  // Nodes — username is the unique key the server uses for /users/{u},
  // so the set is keyed on username (not id).
  const [selectedUsernames, setSelectedUsernames] = useState<Set<string>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: () => listUsers(),
    staleTime: 30_000,
  });

  // Need the current operator's username so the delete button can be
  // suppressed on their own row (server-side guard also rejects
  // self-delete with 400, but hiding the button avoids surprise).
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const users = data ?? [];

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['users'] });
    // Also invalidate the per-user permissions cache so the next
    // open of the Permissions modal sees fresh data instead of
    // whatever was loaded the first time.
    void qc.invalidateQueries({ queryKey: ['user-permissions'] });
    void refetch();
  }

  // Header checkbox state — operates on the deletable subset, since the
  // current operator's own row can't be selected for deletion. If the
  // only visible users are non-deletable (e.g. you're the only super-admin)
  // the header checkbox is disabled rather than misleading.
  const deletableUsernames = users
    .filter((u) => u.username !== me?.username)
    .map((u) => u.username);
  const allChecked =
    deletableUsernames.length > 0 &&
    deletableUsernames.every((n) => selectedUsernames.has(n));
  const someChecked = deletableUsernames.some((n) => selectedUsernames.has(n));

  function toggleAll() {
    if (allChecked) {
      setSelectedUsernames(new Set());
    } else {
      setSelectedUsernames(new Set(deletableUsernames));
    }
  }

  function toggleOne(username: string) {
    setSelectedUsernames((prev) => {
      const next = new Set(prev);
      if (next.has(username)) next.delete(username);
      else next.add(username);
      return next;
    });
  }

  // Bulk delete — Promise.allSettled over the selected usernames so a
  // partial 403/404 reports 'deleted N of M; X failed' instead of
  // hard-failing the whole batch.
  const bulkDeleteMut = useMutation({
    mutationFn: async (usernames: string[]) => {
      const settled = await Promise.allSettled(
        usernames.map((u) => deleteUser(u)),
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;
      return { total: usernames.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      setSelectedUsernames(new Set());
      if (failed > 0) {
        setBulkError(`Deleted ${total - failed} of ${total} user(s); ${failed} failed.`);
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
    const usernames = Array.from(selectedUsernames);
    if (usernames.length === 0) return;
    if (
      !confirm(
        `Delete ${usernames.length} operator${usernames.length === 1 ? '' : 's'}?\n\nThis revokes their access immediately. Any active sessions stop working on next refresh.`,
      )
    ) {
      return;
    }
    setBulkError(null);
    bulkDeleteMut.mutate(usernames);
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          {t('pageTitle.users')}
        </h1>
        <p className="text-xs text-[color:var(--text-3)] flex-1">
          {t('usersPage.superAdminView')}
        </p>
        <Button
          type="button"
          onClick={() => setModal({ kind: 'create' })}
        >
          {t('usersPage.addOperator')}
        </Button>
      </div>

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  aria-label={t('usersPage.selectDeletable')}
                  checked={allChecked}
                  disabled={deletableUsernames.length === 0}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked && !allChecked;
                  }}
                  onChange={toggleAll}
                  className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
                />
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                {t('login.username')}
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                {t('usersPage.email')}
              </th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Role
              </th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">
                Last access
              </th>
              <th scope="col" className="px-4 py-3 w-1" />
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}

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
                    title={error instanceof Error ? error.message : 'Failed to load users'}
                    action={
                      <button
                        type="button"
                        onClick={() => void refetch()}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)] transition-colors"
                      >
                        Retry
                      </button>
                    }
                  />
                </td>
              </tr>
            )}

            {!isLoading && !isError && users.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <circle cx="9" cy="7" r="4" />
                        <path d="M3 21v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
                      </svg>
                    }
                    title={t('usersPage.noUsers')}
                  />
                </td>
              </tr>
            )}

            {!isLoading &&
              !isError &&
              users.map((u) => {
                const isSelf = me?.username === u.username;
                const isSelected = selectedUsernames.has(u.username);
                return (
                <tr
                  key={u.id}
                  className={cn(
                    'border-b border-[color:var(--border)] hover:bg-[color:var(--bg-3)] transition-colors',
                    isSelected && 'bg-[color:var(--signal)]/5',
                  )}
                >
                  <td className="px-4 py-3">
                    {isSelf ? (
                      <span
                        aria-label="You can't select your own account"
                        title="You can't delete your own account."
                        className="inline-block w-4 h-4"
                      />
                    ) : (
                      <input
                        type="checkbox"
                        aria-label={`Select user ${u.username}`}
                        checked={isSelected}
                        onChange={() => toggleOne(u.username)}
                        className="rounded border-[color:var(--border)] accent-[color:var(--signal)] cursor-pointer"
                      />
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium tabular-nums text-[color:var(--text-1)]">
                      {u.username}
                    </span>
                    {u.fullname && (
                      <span className="ml-2 text-xs text-[color:var(--text-3)]">{u.fullname}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[color:var(--text-2)] text-xs">
                    {u.email || '—'}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    <div className="flex flex-wrap items-center gap-1">
                      {u.admin && <MetadataBadge>{t('usersPage.admin')}</MetadataBadge>}
                      {u.service && <MetadataBadge>{t('usersPage.service')}</MetadataBadge>}
                      {!u.admin && !u.service && <MetadataBadge>{t('usersPage.operator')}</MetadataBadge>}
                      {u.auth_source === 'oidc' && (
                        <MetadataBadge className="cursor-help" title={t('usersPage.jitOidc')}>
                          OIDC
                        </MetadataBadge>
                      )}
                      {u.auth_source === 'saml' && (
                        <MetadataBadge className="cursor-help" title={t('usersPage.jitSaml')}>
                          SAML
                        </MetadataBadge>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 tnum text-xs text-[color:var(--text-2)] text-right">
                    <span title={u.last_access}>{formatRelative(u.last_access)}</span>
                  </td>
                  <td className="px-2 py-3 text-right whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'permissions', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
                    >
                      {t('usersPage.permissions')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'token', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
                    >
                      {t('usersPage.token')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setModal({ kind: 'reset-pw', user: u })}
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
                    >
                      {t('usersPage.resetPassword')}
                    </button>
                    {me?.username !== u.username && (
                      <button
                        type="button"
                        onClick={() => setModal({ kind: 'delete', user: u })}
                        className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.10)] transition-colors"
                      >
                        {t('commonExt.delete')}…
                      </button>
                    )}
                  </td>
                </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* Multi-select dock — matches CarvesListPage / TagsPage chrome. */}
      {selectedUsernames.size > 0 && (
        <div
          role="toolbar"
          aria-label={t('commonExt.bulkActions')}
          className={cn(
            'fixed bottom-6 left-1/2 -translate-x-1/2',
            'flex items-center gap-3 px-4 py-2.5 rounded-xl',
            'bg-[color:var(--bg-1)] border border-[color:var(--border-strong)]',
            'shadow-[0_8px_32px_rgba(0,0,0,0.32)]',
            'text-sm font-medium',
            'z-50',
          )}
        >
          <span className="text-[color:var(--text-2)] text-xs tabular-nums">
            {selectedUsernames.size} selected
          </span>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          {bulkError && (
            <span className="text-xs text-[color:var(--danger)]">{bulkError}</span>
          )}
          <button
            type="button"
            disabled={bulkDeleteMut.isPending}
            aria-label={t('usersPage.deleteUsers')}
            className="px-3 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50"
            onClick={handleBulkDelete}
          >
            {bulkDeleteMut.isPending ? 'Deleting…' : 'Delete'}
          </button>
          <div className="w-px h-4 bg-[color:var(--border)]" aria-hidden />
          <button
            type="button"
            aria-label={t('commonExt.clearSelection')}
            onClick={() => setSelectedUsernames(new Set())}
            className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Clear
          </button>
        </div>
      )}

      {/* Bulk-error toast after selection clears. */}
      {bulkError && selectedUsernames.size === 0 && (
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
            aria-label={t('commonExt.dismiss')}
          >
            ×
          </button>
        </div>
      )}

      {modal.kind === 'permissions' && (
        <PermissionsModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={invalidate}
        />
      )}
      {modal.kind === 'token' && (
        <TokenModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
        />
      )}
      {modal.kind === 'create' && (
        <CreateUserModal
          onClose={() => setModal({ kind: 'closed' })}
          onCreated={invalidate}
        />
      )}
      {modal.kind === 'delete' && (
        <DeleteUserModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onDeleted={invalidate}
        />
      )}
      {modal.kind === 'reset-pw' && (
        <ResetPasswordModal
          user={modal.user}
          onClose={() => setModal({ kind: 'closed' })}
          onSaved={() => setModal({ kind: 'closed' })}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Permissions modal
// ---------------------------------------------------------------------------
function PermissionsModal({
  user,
  onClose,
  onSaved,
}: {
  user: AdminUser;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const [envUuid, setEnvUuid] = useState('');
  const [access, setAccess] = useState<EnvAccess>({
    user: true,
    query: false,
    carve: false,
    admin: false,
  });
  const [err, setErr] = useState<string | null>(null);

  // Pull the env list so we can render a dropdown of name → uuid
  // mappings. Falls back to a free-text input on query error so an
  // operator can still type a UUID manually if the env-list endpoint
  // is flaky. The user opening this modal is necessarily a super-
  // admin (UsersPage gates on admin-level), so /api/v1/environments
  // is reachable.
  const { data: envs, isLoading: envsLoading, error: envsError } = useQuery({
    queryKey: ['environments-for-permissions'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
    retry: 1,
  });

  // Pull the target user's CURRENT permission map so the modal can
  // prefill the access checkboxes with what's already in the DB.
  // Without this the modal opened with a fresh {user:true,...}
  // default — re-saving silently overwrote any prior grants the
  // operator might not have remembered to leave alone.
  //
  // Refetch when the modal opens (queryKey includes user.username).
  // staleTime=0 so we always see the latest state when the modal is
  // re-opened after a save.
  const { data: existingPerms } = useQuery({
    queryKey: ['user-permissions', user.username],
    queryFn: () => getUserPermissions(user.username),
    staleTime: 0,
  });

  // When the operator picks an env in the dropdown, sync the
  // checkboxes to the user's existing access for that env. An env
  // with no rows in existingPerms.permissions falls back to a
  // zero-value EnvAccess (everything false) so the modal shows
  // "this user has no access here yet" honestly.
  useEffect(() => {
    if (!envUuid) return;
    const found = existingPerms?.permissions?.[envUuid];
    if (found) {
      setAccess(found);
    } else {
      setAccess({ user: false, query: false, carve: false, admin: false });
    }
  }, [envUuid, existingPerms]);

  const mutation = useMutation({
    mutationFn: () => {
      const trimmed = envUuid.trim();
      if (!trimmed) throw new Error('env_uuid is required');
      return setUserPermissions(user.username, { env_uuid: trimmed, access });
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
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  // Bulk-apply state. Two-step UX: first click reveals a confirmation
  // pane ("This will apply to N environments — continue?"), second
  // click fires setUserPermissionsAllSafe. The confirmation
  // intentionally NOT a window.confirm — the modal is already a
  // dialog, so a native confirm would be a dialog inside a dialog.
  const [bulkConfirm, setBulkConfirm] = useState<boolean>(false);
  const [bulkReport, setBulkReport] = useState<BulkSetReport | null>(null);
  const bulkMutation = useMutation({
    mutationFn: () => {
      const envUuids = (envs ?? []).map((e) => e.uuid);
      return setUserPermissionsAllSafe(user.username, access, envUuids);
    },
    onSuccess: (report) => {
      setBulkReport(report);
      if (report.failed.length === 0) {
        onSaved();
      }
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Bulk apply failed');
    },
  });

  return (
    <ModalShell
      title={`Permissions for ${user.username}`}
      titleId="user-perms-modal-title"
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mutation.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label htmlFor="perm-env-uuid" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Environment
          </label>
          {envsError ? (
            // Fall back to free-text UUID input on env-list error so an
            // operator is never blocked from setting permissions by a
            // flaky /environments endpoint.
            <>
              <input
                id="perm-env-uuid"
                type="text"
                value={envUuid}
                onChange={(e) => setEnvUuid(e.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className={cn(
                  'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                  'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
                  'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                )}
              />
              <p className="mt-1 text-xs text-[color:var(--text-3)]">
                {t('usersPage.pasteUuidHint')}
              </p>
            </>
          ) : (
            <select
              id="perm-env-uuid"
              value={envUuid}
              onChange={(e) => setEnvUuid(e.target.value)}
              disabled={envsLoading}
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                'disabled:opacity-60',
              )}
            >
              <option value="">
                {envsLoading ? 'Loading environments…' : 'Select an environment'}
              </option>
              {envs?.map((e) => (
                // value is the UUID — that's what setUserPermissions
                // expects on the wire and what the backend's
                // /users/{u}/permissions handler matches against.
                // The visible label is the human name so operators
                // pick by what they know.
                <option key={e.uuid} value={e.uuid}>
                  {e.name}
                </option>
              ))}
            </select>
          )}
          <p className="mt-1 text-xs text-[color:var(--text-3)]">
            Permissions are env-scoped — repeat this form to grant access in
            multiple environments.
          </p>
        </div>

        <fieldset className="space-y-2 border border-[color:var(--border)] rounded-md p-3">
          <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">
            Access
          </legend>
          {(['user', 'query', 'carve', 'admin'] as const).map((k) => (
            <label key={k} className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={access[k]}
                onChange={(e) => setAccess((a) => ({ ...a, [k]: e.target.checked }))}
                className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
              />
              <span className="tabular-nums">{k}</span>
              <span className="text-[color:var(--text-3)]">
                {k === 'user' && '— see this env in the SPA'}
                {k === 'query' && '— run distributed queries'}
                {k === 'carve' && '— initiate file carves'}
                {k === 'admin' && '— manage env settings + tags + users'}
              </span>
            </label>
          ))}
        </fieldset>

        {err && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {err}
          </p>
        )}

        {/* Bulk-apply result panel. Hidden until bulkMutation completes. */}
        {bulkReport && (
          <div
            role="status"
            className={cn(
              'text-xs px-3 py-2 rounded-md',
              bulkReport.failed.length === 0
                ? 'text-[color:var(--success)] bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)]'
                : 'text-[color:var(--warning)] bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.08)]',
            )}
          >
            Applied access to {bulkReport.succeeded} of {bulkReport.total} environments
            {bulkReport.usedBulkEndpoint ? ' (bulk endpoint)' : ' (per-env fallback)'}.
            {bulkReport.failed.length > 0 && (
              <span className="block mt-1">
                {bulkReport.failed.length} failed — re-run to retry or set individually.
              </span>
            )}
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 flex-wrap">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Cancel
          </button>
          {/* "Apply to all environments" button. Two-step:
              first click → confirmation pill; second click → fire.
              Disabled when env-list query is loading or in error
              state (we have no UUIDs to enumerate). */}
          {bulkConfirm ? (
            <button
              type="button"
              disabled={bulkMutation.isPending}
              onClick={() => bulkMutation.mutate()}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--warning)] text-black hover:opacity-90',
                'transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
              title={`Will apply the selected access to all ${envs?.length ?? 0} environments`}
            >
              {bulkMutation.isPending
                ? `Applying to ${envs?.length ?? 0}…`
                : `Confirm: apply to all ${envs?.length ?? 0} envs`}
            </button>
          ) : (
            <button
              type="button"
              disabled={!envs || envs.length === 0 || envsLoading}
              onClick={() => setBulkConfirm(true)}
              className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('usersPage.grantAllEnvs')}
            >
              {t('usersPage.applyToAllEnvs')}
            </button>
          )}
          <button
            type="submit"
            disabled={mutation.isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : 'Save permissions'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Token modal — refresh or delete a user's API token
// ---------------------------------------------------------------------------
function TokenModal({
  user,
  onClose,
}: {
  user: AdminUser;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const [token, setToken] = useState<TokenResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const refreshMutation = useMutation({
    mutationFn: () => refreshUserToken(user.username),
    onSuccess: (data) => {
      setToken(data);
      setErr(null);
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Refresh failed');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteUserToken(user.username),
    onSuccess: () => {
      setToken(null);
      setErr(null);
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

  return (
    <ModalShell
      title={`API token — ${user.username}`}
      titleId="user-token-modal-title"
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          Refresh generates a new JWT and invalidates the previous one. Delete
          clears the token entirely — any clients using the old token will
          immediately stop working.
        </p>

        {token && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-[color:var(--text-2)]">
              New token (shown once — copy it now):
            </p>
            <textarea
              readOnly
              value={token.token}
              className={cn(
                'w-full h-24 px-3 py-2 text-xs rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
              )}
              onFocus={(e) => e.currentTarget.select()}
            />
            <p className="text-xs text-[color:var(--text-3)]">
              {t('users.tokenExpires', { date: formatDateTime(new Date(token.expires)) })}
            </p>
          </div>
        )}

        {err && (
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {err}
          </p>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 flex-wrap">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Close
          </button>
          <button
            type="button"
            disabled={refreshMutation.isPending}
            onClick={() => refreshMutation.mutate()}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {refreshMutation.isPending ? 'Refreshing…' : 'Refresh token'}
          </button>
          {confirmDelete ? (
            <button
              type="button"
              disabled={deleteMutation.isPending}
              onClick={() => deleteMutation.mutate()}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-md',
                'bg-[color:var(--danger)] text-white hover:opacity-90',
                'transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
              )}
            >
              {deleteMutation.isPending ? 'Deleting…' : 'Confirm delete'}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-3)] transition-colors"
            >
              {t('usersPage.deleteToken')}
            </button>
          )}
        </div>
      </div>
    </ModalShell>
  );
}

// ====================================================================
// CreateUserModal — super-admin "Add user" form (username/email/
// fullname/password + admin/service flags). Posts to the legacy
// UserActionHandler add path. Closes + invalidates the user list on
// success.
// ====================================================================
function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [fullname, setFullname] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      // Mirror the shape the backend accepts (pkg/utils.SanitizeUsername):
      // either the plain class or an email address, since IdPs commonly
      // identify users by mailbox. The password-create flow doesn't strictly
      // enforce this server-side at create time, but pre-validating here
      // prevents creating users that can't be addressed via the URL-encoded
      // paths the rest of the API uses.
      let trimmed = username.trim();
      const plainShape = /^[a-zA-Z0-9_-]{1,64}$/;
      const emailShape =
        /^[a-zA-Z0-9_%+-]+(?:\.[a-zA-Z0-9_%+-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      if (trimmed.includes('@')) {
        if (trimmed.length > 254 || !emailShape.test(trimmed)) {
          throw new Error('Enter a valid email address, or a plain username.');
        }
        // Canonicalized the same way the backend does, so a locally created
        // account matches what an IdP would resolve to on login.
        trimmed = trimmed.toLowerCase();
      } else if (!plainShape.test(trimmed)) {
        throw new Error(
          'Username must be 1-64 chars (letters/digits/dash/underscore), or an email address.',
        );
      }
      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters.');
      }
      return createUser({
        username: trimmed,
        password,
        email: email.trim(),
        fullname: fullname.trim(),
        admin: isAdmin,
      });
    },
    onSuccess: () => {
      onCreated();
      onClose();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      // ApiError surfaces the server-side message verbatim
      // ("user X already exists", validation failures, etc.).
      setErr(e instanceof Error ? e.message : 'Create failed');
    },
  });

  return (
    <ModalShell title={t('usersPage.addOperator')} titleId="create-user-modal-title" onClose={onClose}>
      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          setErr(null);
          mutation.mutate();
        }}
        className="space-y-3"
      >
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Username <span className="text-[color:var(--danger)]">*</span>
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            required
            placeholder={t('usersPage.usernamePlaceholder')}
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Password <span className="text-[color:var(--danger)]">*</span>
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            placeholder={t('usersPage.passwordHint')}
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">{t('usersPage.email')}</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('usersPage.optional')}
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            Full name
          </label>
          <input
            type="text"
            value={fullname}
            onChange={(e) => setFullname(e.target.value)}
            placeholder={t('usersPage.optional')}
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)] cursor-pointer">
          <input
            type="checkbox"
            checked={isAdmin}
            onChange={(e) => setIsAdmin(e.target.checked)}
            className="accent-[color:var(--signal)]"
          />
          <span>
            Super-admin{' '}
            <span className="text-[color:var(--text-3)]">
              (full access across all environments)
            </span>
          </span>
        </label>

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
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending || !username || !password}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Creating…' : 'Create operator'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

// ====================================================================
// DeleteUserModal — confirmation step + server call. Server-side
// guard already prevents self-deletion; we additionally hide the
// Delete button on the current operator's row.
// ====================================================================
function DeleteUserModal({
  user,
  onClose,
  onDeleted,
}: {
  user: AdminUser;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const { t } = useTranslation();
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () => deleteUser(user.username),
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

  return (
    <ModalShell
      title={`Delete operator — ${user.username}`}
      titleId="delete-user-modal-title"
      onClose={onClose}
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          {t('usersPage.deleteWarning')} <strong>{user.username}</strong> and all
          their per-environment permissions. The user&apos;s API token (if any)
          will stop working immediately.
        </p>
        <p className="text-xs text-[color:var(--text-3)]">
          Federated identities (OIDC/SAML) will be re-JIT-provisioned with zero
          permissions on next login if you have JIT enabled. To prevent
          re-login, also disable the identity at your IdP.
        </p>

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
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate()}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--danger)] text-white hover:opacity-90',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Deleting…' : `Delete ${user.username}`}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ====================================================================
// ResetPasswordModal — super-admin "set someone else's password"
// flow. Posts to UserActionHandler's edit case which calls
// h.Users.ChangePassword. The user themself can still self-change
// at /_app/profile with their old password; this is the operator-
// recovery path for "alice forgot her password."
// ====================================================================
function ResetPasswordModal({
  user,
  onClose,
  onSaved,
}: {
  user: AdminUser;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: async () => {
      if (password !== confirm) throw new Error('Passwords do not match.');
      if (password.length < 8) throw new Error('Password must be at least 8 characters.');
      return adminResetUserPassword(user.username, password);
    },
    onSuccess: () => {
      onSaved();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Password change failed');
    },
  });

  return (
    <ModalShell
      title={`Reset password — ${user.username}`}
      titleId="reset-pw-modal-title"
      onClose={onClose}
    >
      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          setErr(null);
          mutation.mutate();
        }}
        className="space-y-3"
      >
        <p className="text-xs text-[color:var(--text-3)]">
          Setting a new password for{' '}
          <strong className="text-[color:var(--text-1)]">{user.username}</strong>.
          The user will need to log in with the new password; any existing API
          tokens stay valid until explicitly revoked.
        </p>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            {t('usersPage.newPassword')}
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
            minLength={8}
            placeholder={t('usersPage.passwordHint')}
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
            {t('usersPage.confirmNewPassword')}
          </label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            className="w-full px-3 py-1.5 text-sm rounded border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
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
            className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending || !password || !confirm}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
              'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {mutation.isPending ? 'Saving…' : 'Set password'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

export default UsersPage;
