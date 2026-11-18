import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getScimStatus, getUserGroups, removeScimToken, rotateScimToken, scimStatusKey } from '$/api/scim';
import { useLocale } from '$/i18n/useLocale';
import { appPath } from '$/lib/base-path';
import { cn } from '$/lib/cn';
import { ModalShell } from '$/components/feedback/ModalShell';
import { MetadataBadge } from '$/components/data/MetadataBadge';

const ghost =
  'px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors';
const primary = cn(
  'px-3 py-1.5 text-xs font-medium rounded-md',
  'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
  'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
);

function ErrorLine({ err }: { err: unknown }) {
  if (!err) return null;
  return (
    <p role="alert" className="text-xs text-[color:var(--danger)]">
      {err instanceof Error ? err.message : String(err)}
    </p>
  );
}

/** Superuser view of the SCIM token: status, base URL, create/rotate, remove. */
export function ScimModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const qc = useQueryClient();
  const [token, setToken] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const status = useQuery({ queryKey: scimStatusKey, queryFn: getScimStatus });
  const refresh = () => void qc.invalidateQueries({ queryKey: scimStatusKey });
  const rotate = useMutation({
    mutationFn: rotateScimToken,
    onSuccess: (r) => {
      setToken(r.token);
      refresh();
    },
  });
  const remove = useMutation({
    mutationFn: removeScimToken,
    onSuccess: () => {
      setToken(null);
      setConfirmRemove(false);
      refresh();
    },
  });
  const s = status.data;
  const baseUrl = window.location.origin + appPath('/api/v1/scim/v2');

  return (
    <ModalShell title={t('scim.title')} titleId="scim-modal-title" onClose={onClose}>
      <div className="space-y-4 text-sm text-[color:var(--text-1)]">
        <p>{t('scim.intro')}</p>
        <ErrorLine err={status.error ?? rotate.error ?? remove.error} />
        {s && !s.available && <p className="text-[color:var(--text-2)]">{t('scim.unavailable')}</p>}
        {s?.available && (
          <>
            <p className="text-[color:var(--text-2)]">
              {s.enabled && s.token_created_at
                ? t('scim.on', { date: formatDateTime(new Date(s.token_created_at)) })
                : t('scim.off')}
            </p>
            <div>
              <p className="text-xs font-semibold text-[color:var(--text-2)]">{t('scim.baseUrl')}</p>
              <code className="text-xs break-all">{baseUrl}</code>
            </div>
            {token && (
              <div className="space-y-1">
                <p className="text-xs font-semibold text-[color:var(--text-2)]">{t('scim.newToken')}</p>
                <textarea
                  readOnly
                  aria-label={t('scim.newToken')}
                  value={token}
                  onFocus={(e) => e.currentTarget.select()}
                  className="w-full h-16 px-3 py-2 text-xs rounded-md border border-[color:var(--border)] bg-[color:var(--bg-3)] text-[color:var(--text-1)]"
                />
              </div>
            )}
            {s.enabled && <p className="text-xs text-[color:var(--text-3)]">{t('scim.rotateHint')}</p>}
          </>
        )}
        <div className="flex items-center justify-end gap-2 pt-2 flex-wrap">
          <button type="button" onClick={onClose} className={ghost}>
            {t('common.close')}
          </button>
          {s?.available && (
            <button type="button" className={primary} disabled={rotate.isPending} onClick={() => rotate.mutate()}>
              {s.enabled ? t('scim.rotate') : t('scim.create')}
            </button>
          )}
          {s?.enabled &&
            (confirmRemove ? (
              <button
                type="button"
                disabled={remove.isPending}
                onClick={() => remove.mutate()}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-[color:var(--danger)] text-white hover:opacity-90 disabled:opacity-50"
              >
                {t('scim.confirmRemove')}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmRemove(true)}
                className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-3)] transition-colors"
              >
                {t('scim.remove')}
              </button>
            ))}
        </div>
      </div>
    </ModalShell>
  );
}

/** The IdP groups stored for a user, as Santa group tags see them. */
export function GroupsModal({ username, onClose }: { username: string; onClose: () => void }) {
  const { t } = useTranslation();
  const { formatDateTime } = useLocale();
  const { data, error } = useQuery({ queryKey: ['user-groups', username], queryFn: () => getUserGroups(username) });

  return (
    <ModalShell title={t('scim.groupsTitle', { user: username })} titleId="user-groups-modal-title" onClose={onClose}>
      <div className="space-y-3 text-sm text-[color:var(--text-1)]">
        <ErrorLine err={error} />
        {data && (
          <>
            {data.groups.length === 0 ? (
              <p className="text-[color:var(--text-2)]">{t('scim.groupsNone')}</p>
            ) : (
              <ul className="flex flex-wrap gap-1">
                {data.groups.map((g) => (
                  <li key={g}>
                    <MetadataBadge>{g}</MetadataBadge>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-[color:var(--text-3)]">
              {data.scim ? t('scim.viaScim') : t('scim.viaSso')}
              {data.updated_at && ` · ${t('scim.groupsUpdated', { date: formatDateTime(new Date(data.updated_at)) })}`}
            </p>
          </>
        )}
        <div className="flex justify-end pt-2">
          <button type="button" onClick={onClose} className={ghost}>
            {t('common.close')}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
