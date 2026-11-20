import { useCallback, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  deleteSantaModeOverride,
  extendSantaMonitor,
  getSantaConfig,
  listSantaModeOverrides,
  setSantaModeOverride,
  putSantaConfig,
  rotateSantaToken,
  santaQueryKey,
  SANTA_MEDIA_ACTIONS,
  SANTA_MONITOR_HOURS,
  SANTA_REMOUNT_FLAGS,
  SANTA_TOKEN_HEADER,
  SANTA_FILE_ACCESS_ACTIONS,
  type SantaConfig,
  type SantaFileAccessAction,
  type SantaGroupTag,
  type SantaMediaAction,
  type SantaModeOverrideInput,
} from '$/api/santa';
import { listAlertChannels } from '$/api/alerts';
import { getEnvironment } from '$/api/environments';
import { listEnvTags } from '$/api/tags';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { Skeleton } from '$/components/data/Skeleton';
import { ModalShell } from '$/components/feedback/ModalShell';
import { basePath } from '$/lib/base-path';
import { MONO, ROW, TABLE, TD, TH, errorText } from './table';

const CARD = 'space-y-3 rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4';
const CODE = 'block rounded-md bg-[color:var(--bg-3)] px-2 py-1.5 font-mono text-xs text-[color:var(--text-1)] [overflow-wrap:anywhere]';

export function SettingsTab({ env }: { env: string }) {
  const { t } = useTranslation();
  const config = useQuery({ queryKey: santaQueryKey(env, 'config'), queryFn: () => getSantaConfig(env) });
  const environment = useQuery({ queryKey: ['environment', env], queryFn: () => getEnvironment(env), staleTime: 60_000 });
  const host = environment.data?.hostname || '<tls host>';
  const uuid = environment.data?.uuid || '<env uuid>';

  if (config.isLoading) return <Skeleton className="h-40 w-full" />;
  if (config.isError || !config.data) {
    return <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(config.error) ?? t('santa.loadError')}</p>;
  }
  return (
    <div className="space-y-4">
      <ConfigForm env={env} envId={environment.data?.id} config={config.data} />
      <ModeOverridesCard env={env} />
      <TokenCard env={env} tokenSet={config.data.token_set} />
      <section className={CARD}>
        <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.clientSetup')}</h2>
        <p className="text-xs text-[color:var(--text-3)]">{t('santa.clientSetupHint')}</p>
        <div>
          <div className="mb-1 text-xs text-[color:var(--text-3)]">SyncBaseURL</div>
          <code className={CODE}>{`https://${host}/${uuid}/santa/sync/`}</code>
        </div>
        <div>
          <div className="mb-1 text-xs text-[color:var(--text-3)]">SyncExtraHeaders</div>
          <code className={CODE}>{`${SANTA_TOKEN_HEADER}: <token>`}</code>
        </div>
      </section>
    </div>
  );
}

/**
 * Alert channels told about new approval requests, and the email channel that
 * tells requesters about decisions. The list needs an alerts role, so it is
 * simply absent for users without one (or with alerts off); the saved
 * selection is then sent back unchanged.
 */
function NotifyChannels({ envId, selected, onChange, requester, onRequester }: {
  envId?: number; selected: number[]; onChange: (ids: number[]) => void; requester: number; onRequester: (id: number) => void;
}) {
  const { t } = useTranslation();
  const channels = useQuery({ queryKey: ['alerts', 'channels'], queryFn: () => listAlertChannels(), retry: false, staleTime: 60_000 });
  const usable = (channels.data ?? []).filter((c) => c.environment_id === 0 || c.environment_id === envId);
  if (usable.length === 0) return null;
  return (
    <fieldset>
      <legend className="text-sm font-medium text-[color:var(--text-2)]">{t('santa.notifyChannels')}</legend>
      <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
        {usable.map((c) => (
          <label key={c.id} className="flex items-center gap-1.5 text-sm text-[color:var(--text-2)]">
            <input
              type="checkbox"
              checked={selected.includes(c.id)}
              onChange={(e) => onChange(e.target.checked ? [...selected, c.id] : selected.filter((id) => id !== c.id))}
            />
            {c.name} <span className="text-xs text-[color:var(--text-3)]">({c.type})</span>
          </label>
        ))}
      </div>
      <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.notifyChannelsHint')}</p>
      <Label htmlFor="santa-requester-channel" className="mt-3 block">{t('santa.requesterChannel')}</Label>
      <select
        id="santa-requester-channel"
        value={requester}
        onChange={(e) => onRequester(Number(e.target.value))}
        className="h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
      >
        <option value={0}>{t('santa.requesterChannelOff')}</option>
        {usable.filter((c) => c.type === 'email').map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
      </select>
      <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.requesterChannelHint')}</p>
    </fieldset>
  );
}

function GroupTags({ env, value, onChange, match, onMatch }: {
  env: string; value: SantaGroupTag[]; onChange: (v: SantaGroupTag[]) => void; match: string; onMatch: (m: string) => void;
}) {
  const { t } = useTranslation();
  const envTags = useQuery({ queryKey: ['tags', env], queryFn: () => listEnvTags(env), staleTime: 60_000 });
  const set = (i: number, gt: SantaGroupTag) => onChange(value.map((v, j) => (j === i ? gt : v)));
  const select = 'h-8 rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]';
  return (
    <fieldset>
      <legend className="text-sm font-medium text-[color:var(--text-2)]">{t('santa.groupTags.title')}</legend>
      <div className="mt-1 space-y-2">
        {value.map((gt, i) => (
          <div key={i} className="grid gap-2 sm:grid-cols-[1fr_12rem_auto]">
            <Input
              aria-label={t('santa.groupTags.group')}
              placeholder={t('santa.groupTags.group')}
              maxLength={255}
              value={gt.group}
              onChange={(e) => set(i, { ...gt, group: e.target.value })}
            />
            <select aria-label={t('santa.groupTags.tag')} className={select} value={gt.tag} onChange={(e) => set(i, { ...gt, tag: e.target.value })}>
              <option value="" />
              {(envTags.data ?? []).map((tag) => <option key={tag.name} value={tag.name}>{tag.name}</option>)}
            </select>
            <Button type="button" variant="ghost" onClick={() => onChange(value.filter((_, j) => j !== i))}>{t('commonExt.remove')}</Button>
          </div>
        ))}
        <Button type="button" variant="ghost" onClick={() => onChange([...value, { group: '', tag: '' }])}>{t('santa.groupTags.add')}</Button>
      </div>
      <Label htmlFor="santa-group-match" className="mt-2 block">{t('santa.groupTags.match')}</Label>
      <select id="santa-group-match" className={select} value={match} onChange={(e) => onMatch(e.target.value)}>
        {(['', 'local_part', 'email'] as const).map((m) => <option key={m} value={m}>{t(`santa.groupTags.matches.${m || 'exact'}`)}</option>)}
      </select>
      <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.groupTags.matchHint')}</p>
      <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.groupTags.hint')}</p>
    </fieldset>
  );
}

function ConfigForm({ env, envId, config }: { env: string; envId?: number; config: SantaConfig }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [form, setForm] = useState(config);
  const save = useMutation({
    mutationFn: () =>
      putSantaConfig(env, {
        client_mode: form.client_mode,
        batch_size: form.batch_size,
        full_sync_interval_seconds: form.full_sync_interval_seconds ?? 0,
        enable_transitive_rules: form.enable_transitive_rules,
        removable_media: form.removable_media,
        removable_media_flags: form.removable_media === 'REMOUNT' ? form.removable_media_flags : [],
        encrypted_removable_media: form.encrypted_removable_media,
        encrypted_removable_media_flags: form.encrypted_removable_media === 'REMOUNT' ? form.encrypted_removable_media_flags : [],
        approval_url: form.approval_url,
        notify_channels: form.notify_channels ?? [],
        requester_channel: form.requester_channel ?? 0,
        vote_local_threshold: form.vote_local_threshold ?? 0,
        vote_global_threshold: form.vote_global_threshold ?? 0,
        vote_expiry_days: form.vote_expiry_days ?? 0,
        max_monitor_hours: form.max_monitor_hours ?? 0,
        override_file_access_action: form.override_file_access_action ?? '',
        enable_bundles: !!form.enable_bundles,
        enable_all_event_upload: !!form.enable_all_event_upload,
        disable_unknown_event_upload: !!form.disable_unknown_event_upload,
        allowed_path_regex: form.allowed_path_regex ?? '',
        blocked_path_regex: form.blocked_path_regex ?? '',
        event_detail_url: form.event_detail_url ?? '',
        event_detail_text: form.event_detail_text ?? '',
        group_tags: form.group_tags ?? [],
        group_match: form.group_match ?? '',
        require_second_admin: !!form.require_second_admin,
        approver_users: names(form.approver_users),
        approver_groups: names(form.approver_groups),
      }),
    onSuccess: (saved) => qc.setQueryData(santaQueryKey(env, 'config'), saved),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <form onSubmit={submit} className={CARD}>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <Label htmlFor="santa-mode">{t('santa.mode')}</Label>
          <select
            id="santa-mode"
            value={form.client_mode}
            onChange={(e) => setForm({ ...form, client_mode: e.target.value as SantaConfig['client_mode'] })}
            className="h-8 w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
          >
            <option value="MONITOR">MONITOR</option>
            <option value="LOCKDOWN">LOCKDOWN</option>
          </select>
        </div>
        <div>
          <Label htmlFor="santa-batch">{t('santa.batchSize')}</Label>
          <Input
            id="santa-batch"
            type="number"
            min={0}
            value={form.batch_size}
            onChange={(e) => setForm({ ...form, batch_size: Math.max(0, Number(e.target.value) || 0) })}
          />
          <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.batchSizeHint')}</p>
        </div>
        <div>
          <Label htmlFor="santa-sync-interval">{t('santa.syncInterval')}</Label>
          <Input
            id="santa-sync-interval"
            type="number"
            min={0}
            max={86400}
            value={form.full_sync_interval_seconds ?? 0}
            onChange={(e) => setForm({ ...form, full_sync_interval_seconds: Math.max(0, Number(e.target.value) || 0) })}
          />
          <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.syncIntervalHint')}</p>
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-[color:var(--text-2)]">
        <input
          type="checkbox"
          checked={form.enable_transitive_rules}
          onChange={(e) => setForm({ ...form, enable_transitive_rules: e.target.checked })}
        />
        {t('santa.transitiveRules')}
      </label>
      <div>
        <label className="flex items-center gap-2 text-sm text-[color:var(--text-2)]">
          <input
            type="checkbox"
            checked={!!form.require_second_admin}
            onChange={(e) => setForm({ ...form, require_second_admin: e.target.checked })}
          />
          {t('santa.secondAdmin.label')}
        </label>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.secondAdmin.hint')}</p>
      </div>
      {(['enable_bundles', 'enable_all_event_upload', 'disable_unknown_event_upload'] as const).map((field) => (
        <label key={field} className="flex items-center gap-2 text-sm text-[color:var(--text-2)]">
          <input type="checkbox" checked={!!form[field]} onChange={(e) => setForm({ ...form, [field]: e.target.checked })} />
          {t(`santa.settings.${field}`)}
        </label>
      ))}
      <div>
        <div className="grid gap-3 sm:grid-cols-2">
          {(['allowed_path_regex', 'blocked_path_regex'] as const).map((field) => (
            <div key={field}>
              <Label htmlFor={`santa-${field}`}>{t(`santa.settings.${field}`)}</Label>
              <Input
                id={`santa-${field}`}
                className="font-mono"
                maxLength={1024}
                value={form[field] ?? ''}
                onChange={(e) => setForm({ ...form, [field]: e.target.value })}
              />
            </div>
          ))}
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.settings.pathRegexHint')}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <MediaPolicy
          id="santa-media"
          label={t('santa.removableMedia')}
          action={form.removable_media}
          flags={form.removable_media_flags}
          onChange={(action, flags) => setForm({ ...form, removable_media: action || 'ALLOW', removable_media_flags: flags })}
        />
        <MediaPolicy
          id="santa-media-encrypted"
          label={t('santa.encryptedRemovableMedia')}
          action={form.encrypted_removable_media}
          flags={form.encrypted_removable_media_flags}
          inherit
          onChange={(action, flags) => setForm({ ...form, encrypted_removable_media: action, encrypted_removable_media_flags: flags })}
        />
      </div>
      <div>
        <Label htmlFor="santa-file-access">{t('santa.fileAccess.override')}</Label>
        <select
          id="santa-file-access"
          className={SELECT}
          value={form.override_file_access_action ?? ''}
          onChange={(e) => setForm({ ...form, override_file_access_action: e.target.value as SantaFileAccessAction })}
        >
          {SANTA_FILE_ACCESS_ACTIONS.map((a) => <option key={a} value={a}>{t(`santa.fileAccess.actions.${a || 'unset'}`)}</option>)}
        </select>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.fileAccess.overrideHint')}</p>
      </div>
      <div>
        <Label htmlFor="santa-approval-url">{t('santa.approvalUrl')}</Label>
        <Input
          id="santa-approval-url"
          type="url"
          placeholder={window.location.origin + basePath}
          value={form.approval_url ?? ''}
          onChange={(e) => setForm({ ...form, approval_url: e.target.value.trim() })}
        />
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.approvalUrlHint')}</p>
      </div>
      <div>
        <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
          <div>
            <Label htmlFor="santa-event-detail-url">{t('santa.settings.event_detail_url')}</Label>
            <Input
              id="santa-event-detail-url"
              type="url"
              maxLength={1024}
              placeholder="https://…?sha256=%file_sha%"
              value={form.event_detail_url ?? ''}
              onChange={(e) => setForm({ ...form, event_detail_url: e.target.value.trim() })}
            />
          </div>
          <div>
            <Label htmlFor="santa-event-detail-text">{t('santa.settings.event_detail_text')}</Label>
            <Input
              id="santa-event-detail-text"
              maxLength={32}
              value={form.event_detail_text ?? ''}
              onChange={(e) => setForm({ ...form, event_detail_text: e.target.value })}
            />
          </div>
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.settings.eventDetailHint')}</p>
      </div>
      <GroupTags env={env} value={form.group_tags ?? []} onChange={(gts) => setForm({ ...form, group_tags: gts })}
        match={form.group_match ?? ''} onMatch={(m) => setForm({ ...form, group_match: m })} />
      <div>
        <h3 className="text-sm font-medium text-[color:var(--text-1)]">{t('santa.approvers.title')}</h3>
        <div className="mt-2 grid gap-3 sm:grid-cols-2">
          {(['approver_users', 'approver_groups'] as const).map((field) => (
            <div key={field}>
              <Label htmlFor={`santa-${field}`}>{t(field === 'approver_users' ? 'santa.approvers.users' : 'santa.approvers.groups')}</Label>
              <textarea
                id={`santa-${field}`}
                rows={3}
                value={(form[field] ?? []).join('\n')}
                onChange={(e) => setForm({ ...form, [field]: e.target.value.split('\n') })}
                className="w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 py-1 text-sm text-[color:var(--text-1)]"
              />
            </div>
          ))}
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.approvers.hint')}</p>
      </div>
      <NotifyChannels
        envId={envId}
        selected={form.notify_channels ?? []}
        onChange={(ids) => setForm({ ...form, notify_channels: ids })}
        requester={form.requester_channel ?? 0}
        onRequester={(id) => setForm({ ...form, requester_channel: id })}
      />
      <div>
        <div className="grid gap-3 sm:grid-cols-3">
          {(['vote_local_threshold', 'vote_global_threshold', 'vote_expiry_days'] as const).map((field) => (
            <div key={field}>
              <Label htmlFor={`santa-${field}`}>{t({ vote_local_threshold: 'santa.voteLocal', vote_global_threshold: 'santa.voteGlobal', vote_expiry_days: 'santa.voteExpiry' }[field])}</Label>
              <Input
                id={`santa-${field}`}
                type="number"
                min={0}
                value={form[field] ?? 0}
                onChange={(e) => setForm({ ...form, [field]: Math.max(0, Math.floor(Number(e.target.value)) || 0) })}
              />
            </div>
          ))}
        </div>
        <p className="mt-1 text-xs text-[color:var(--text-3)]">{t('santa.voteHint')}</p>
      </div>
      <div className="sm:w-1/3">
        <Label htmlFor="santa-max-monitor-hours">{t('santa.maxMonitorHours')}</Label>
        <Input
          id="santa-max-monitor-hours"
          type="number"
          min={0}
          max={24}
          value={form.max_monitor_hours ?? 0}
          onChange={(e) => setForm({ ...form, max_monitor_hours: Math.max(0, Math.floor(Number(e.target.value)) || 0) })}
        />
      </div>

      {save.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(save.error)}</p>}
      {save.isSuccess && <p role="status" className="text-sm text-[color:var(--text-3)]">{t('santa.saved')}</p>}
      <div className="flex justify-end">
        <Button type="submit" disabled={save.isPending}>{t('common.save')}</Button>
      </div>
    </form>
  );
}

const SELECT =
  'h-8 w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]';
const EMPTY_OVERRIDE: SantaModeOverrideInput = { scope: 'tag', scope_value: '', client_mode: 'LOCKDOWN', hours: 0 };

function ModeOverridesCard({ env }: { env: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = santaQueryKey(env, 'modes');
  const overrides = useQuery({ queryKey: key, queryFn: () => listSantaModeOverrides(env) });
  const [form, setForm] = useState(EMPTY_OVERRIDE);
  const refresh = () => qc.invalidateQueries({ queryKey: key });
  // Only MONITOR on a node can be temporary.
  const temporary = form.scope === 'node' && form.client_mode === 'MONITOR';
  const save = useMutation({
    mutationFn: () => setSantaModeOverride(env, { ...form, hours: temporary ? form.hours : 0 }),
    onSuccess: () => {
      setForm(EMPTY_OVERRIDE);
      return refresh();
    },
  });
  const remove = useMutation({ mutationFn: (id: number) => deleteSantaModeOverride(env, id), onSuccess: refresh });
  // Hours to add, per override.
  const [extendBy, setExtendBy] = useState<Record<number, number>>({});
  const extend = useMutation({ mutationFn: (id: number) => extendSantaMonitor(env, id, extendBy[id] ?? SANTA_MONITOR_HOURS[0]), onSuccess: refresh });
  const rows = overrides.data ?? [];
  const error = save.error ?? remove.error ?? extend.error ?? overrides.error;

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <section className={CARD}>
      <div>
        <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.modeOverrides')}</h2>
        <p className="text-xs text-[color:var(--text-3)]">{t('santa.modeOverridesHint')}</p>
      </div>
      {rows.length === 0 ? (
        !overrides.isLoading && !overrides.isError && <p className="text-sm text-[color:var(--text-3)]">{t('santa.noOverrides')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className={TABLE}>
            <thead>
              <tr className="border-b border-[color:var(--border)]">
                <th scope="col" className={TH}>{t('santa.scope')}</th>
                <th scope="col" className={TH}>{t('santa.scopeValue')}</th>
                <th scope="col" className={TH}>{t('santa.mode')}</th>
                <th scope="col" className={TH}>{t('santa.createdBy')}</th>
                <th scope="col" className={TH}><span className="sr-only">{t('santa.actions')}</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((o) => (
                <tr key={o.id} className={ROW}>
                  <td className={TD}>{t(`santa.scopes.${o.scope}`)}</td>
                  <td className={`${TD} ${MONO}`}>{o.scope_value}</td>
                  <td className={TD}>
                    {o.client_mode}
                    {o.expires_at && (
                      <div className="text-xs text-[color:var(--text-3)]">{t('santa.monitor.until', { time: new Date(o.expires_at).toLocaleString() })}</div>
                    )}
                  </td>
                  <td className={TD}>{o.created_by}</td>
                  <td className={`${TD} text-end`}>
                    {o.expires_at ? (
                      <div className="flex justify-end gap-2">
                        <select
                          className={`${SELECT} w-auto`}
                          aria-label={`${t('santa.monitor.extendBy')} ${o.scope_value}`}
                          value={extendBy[o.id] ?? SANTA_MONITOR_HOURS[0]}
                          onChange={(e) => setExtendBy({ ...extendBy, [o.id]: Number(e.target.value) })}
                        >
                          {SANTA_MONITOR_HOURS.map((h) => <option key={h} value={h}>{t('santa.monitor.hours', { n: h })}</option>)}
                        </select>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={extend.isPending}
                          aria-label={`${t('santa.monitor.extend')} ${o.scope_value}`}
                          onClick={() => extend.mutate(o.id)}
                        >
                          {t('santa.monitor.extend')}
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={remove.isPending}
                          aria-label={`${t('santa.monitor.end')} ${o.scope_value}`}
                          onClick={() => {
                            if (confirm(t('santa.monitor.confirmEnd', { value: o.scope_value }))) remove.mutate(o.id);
                          }}
                        >
                          {t('santa.monitor.end')}
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={remove.isPending}
                        aria-label={`${t('santa.delete')} ${o.scope_value}`}
                        onClick={() => {
                          if (confirm(t('santa.confirmDeleteOverride', { value: o.scope_value }))) remove.mutate(o.id);
                        }}
                      >
                        {t('santa.delete')}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form onSubmit={submit} className="grid items-end gap-3 sm:grid-cols-[8rem_1fr_9rem_8rem_auto]">
        <div>
          <Label htmlFor="santa-override-scope">{t('santa.scope')}</Label>
          <select
            id="santa-override-scope"
            className={SELECT}
            value={form.scope}
            onChange={(e) => setForm({ ...form, scope: e.target.value as SantaModeOverrideInput['scope'] })}
          >
            <option value="tag">{t('santa.scopes.tag')}</option>
            <option value="node">{t('santa.scopes.node')}</option>
          </select>
        </div>
        <div>
          <Label htmlFor="santa-override-value" required>{t('santa.scopeValue')}</Label>
          <Input
            id="santa-override-value"
            required
            value={form.scope_value}
            placeholder={form.scope === 'node' ? 'UUID' : undefined}
            onChange={(e) => setForm({ ...form, scope_value: e.target.value.trim() })}
          />
        </div>
        <div>
          <Label htmlFor="santa-override-mode">{t('santa.mode')}</Label>
          <select
            id="santa-override-mode"
            className={SELECT}
            value={form.client_mode}
            onChange={(e) => setForm({ ...form, client_mode: e.target.value as SantaModeOverrideInput['client_mode'] })}
          >
            <option value="MONITOR">MONITOR</option>
            <option value="LOCKDOWN">LOCKDOWN</option>
          </select>
        </div>
        <div>
          <Label htmlFor="santa-override-hours">{t('santa.monitor.duration')}</Label>
          <select
            id="santa-override-hours"
            className={SELECT}
            disabled={!temporary}
            value={temporary ? form.hours : 0}
            onChange={(e) => setForm({ ...form, hours: Number(e.target.value) })}
          >
            <option value={0}>{t('santa.monitor.permanent')}</option>
            {SANTA_MONITOR_HOURS.map((h) => <option key={h} value={h}>{t('santa.monitor.hours', { n: h })}</option>)}
          </select>
        </div>
        <Button type="submit" disabled={save.isPending}>{t('santa.addOverride')}</Button>
      </form>
      {error && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(error)}</p>}
    </section>
  );
}

const MEDIA_LABEL = { ALLOW: 'santa.mediaAllow', BLOCK: 'santa.mediaBlock', REMOUNT: 'santa.mediaRemount' } as const;

function MediaPolicy({ id, label, action, flags, inherit, onChange }: {
  id: string;
  label: string;
  action: SantaMediaAction | '';
  flags: string[] | null;
  inherit?: boolean;
  onChange: (action: SantaMediaAction | '', flags: string[]) => void;
}) {
  const { t } = useTranslation();
  const selected = flags ?? [];
  function toggle(flag: string, on: boolean) {
    onChange(action, on ? [...selected, flag] : selected.filter((f) => f !== flag));
  }
  return (
    <div>
      <Label htmlFor={id}>{label}</Label>
      <select
        id={id}
        value={action}
        onChange={(e) => onChange(e.target.value as SantaMediaAction | '', selected)}
        className="h-8 w-full rounded-md border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] px-2 text-sm text-[color:var(--text-1)]"
      >
        {inherit && <option value="">{t('santa.mediaInherit')}</option>}
        {SANTA_MEDIA_ACTIONS.map((a) => <option key={a} value={a}>{t(MEDIA_LABEL[a])}</option>)}
      </select>
      {action === 'REMOUNT' && (
        <fieldset className="mt-2">
          <legend className="mb-1 text-xs text-[color:var(--text-3)]">{t('santa.remountFlags')}</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {SANTA_REMOUNT_FLAGS.map((f) => (
              <label key={f} className="flex items-center gap-1.5 font-mono text-xs text-[color:var(--text-2)]">
                <input type="checkbox" checked={selected.includes(f)} onChange={(e) => toggle(f, e.target.checked)} />
                {f}
              </label>
            ))}
          </div>
        </fieldset>
      )}
    </div>
  );
}

function TokenCard({ env, tokenSet }: { env: string; tokenSet: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  // The plaintext token lives only in this state: not in the query or
  // mutation cache, not in storage. Closing the dialog drops it.
  const [token, setToken] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const close = useCallback(() => setToken(null), []);

  async function rotate() {
    setConfirming(false);
    setPending(true);
    setError(null);
    try {
      const res = await rotateSantaToken(env);
      setToken(res.token);
      void qc.invalidateQueries({ queryKey: santaQueryKey(env, 'config') });
    } catch (err) {
      setError(errorText(err) ?? t('santa.rotateError'));
    } finally {
      setPending(false);
    }
  }

  return (
    <section className={CARD}>
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{t('santa.token')}</h2>
          <p className="text-xs text-[color:var(--text-3)]">{tokenSet ? t('santa.tokenSet') : t('santa.tokenNotSet')}</p>
        </div>
        <Button variant="ghost" disabled={pending} onClick={() => (tokenSet ? setConfirming(true) : void rotate())}>{t('santa.rotateToken')}</Button>
      </div>
      {error && <p role="alert" className="text-sm text-[color:var(--danger)]">{error}</p>}
      {confirming && (
        <ModalShell title={t('santa.rotateConfirmTitle')} titleId="santa-rotate-title" onClose={() => setConfirming(false)} panelClassName="max-w-md">
          <div className="space-y-3">
            <p className="text-sm text-[color:var(--text-2)]">{t('santa.rotateConfirmBody')}</p>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setConfirming(false)}>{t('common.cancel')}</Button>
              <Button type="button" onClick={() => void rotate()}>{t('santa.rotateToken')}</Button>
            </div>
          </div>
        </ModalShell>
      )}
      {token && <TokenDialog token={token} onClose={close} />}
    </section>
  );
}

export function TokenDialog({ token, onClose }: { token: string; onClose: () => void }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <ModalShell title={t('santa.tokenTitle')} titleId="santa-token-title" onClose={onClose} panelClassName="max-w-lg">
      <div className="space-y-3">
        <p className="text-sm text-[color:var(--text-2)]">{t('santa.tokenWarning')}</p>
        <code data-testid="santa-token" className={CODE}>{token}</code>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={() => void copy()}>
            {copied ? t('santa.copied') : t('santa.copy')}
          </Button>
          <Button type="button" onClick={onClose}>{t('common.close')}</Button>
        </div>
      </div>
    </ModalShell>
  );
}

/** One name per line in the form; blank lines are dropped. */
function names(lines?: string[]): string[] {
  return (lines ?? []).map((n) => n.trim()).filter(Boolean);
}
