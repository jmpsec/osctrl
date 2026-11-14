import { useCallback, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  deleteSantaModeOverride,
  getSantaConfig,
  listSantaModeOverrides,
  setSantaModeOverride,
  putSantaConfig,
  rotateSantaToken,
  santaQueryKey,
  SANTA_MEDIA_ACTIONS,
  SANTA_REMOUNT_FLAGS,
  SANTA_TOKEN_HEADER,
  type SantaConfig,
  type SantaMediaAction,
  type SantaModeOverrideInput,
} from '$/api/santa';
import { getEnvironment } from '$/api/environments';
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
      <ConfigForm env={env} config={config.data} />
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

function ConfigForm({ env, config }: { env: string; config: SantaConfig }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [form, setForm] = useState(config);
  const save = useMutation({
    mutationFn: () =>
      putSantaConfig(env, {
        client_mode: form.client_mode,
        batch_size: form.batch_size,
        enable_transitive_rules: form.enable_transitive_rules,
        removable_media: form.removable_media,
        removable_media_flags: form.removable_media === 'REMOUNT' ? form.removable_media_flags : [],
        encrypted_removable_media: form.encrypted_removable_media,
        encrypted_removable_media_flags: form.encrypted_removable_media === 'REMOUNT' ? form.encrypted_removable_media_flags : [],
        approval_url: form.approval_url,
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
      </div>
      <label className="flex items-center gap-2 text-sm text-[color:var(--text-2)]">
        <input
          type="checkbox"
          checked={form.enable_transitive_rules}
          onChange={(e) => setForm({ ...form, enable_transitive_rules: e.target.checked })}
        />
        {t('santa.transitiveRules')}
      </label>
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
const EMPTY_OVERRIDE: SantaModeOverrideInput = { scope: 'tag', scope_value: '', client_mode: 'LOCKDOWN' };

function ModeOverridesCard({ env }: { env: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = santaQueryKey(env, 'modes');
  const overrides = useQuery({ queryKey: key, queryFn: () => listSantaModeOverrides(env) });
  const [form, setForm] = useState(EMPTY_OVERRIDE);
  const refresh = () => qc.invalidateQueries({ queryKey: key });
  const save = useMutation({
    mutationFn: () => setSantaModeOverride(env, form),
    onSuccess: () => {
      setForm(EMPTY_OVERRIDE);
      return refresh();
    },
  });
  const remove = useMutation({ mutationFn: (id: number) => deleteSantaModeOverride(env, id), onSuccess: refresh });
  const rows = overrides.data ?? [];
  const error = save.error ?? remove.error ?? overrides.error;

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
                  <td className={TD}>{o.client_mode}</td>
                  <td className={TD}>{o.created_by}</td>
                  <td className={`${TD} text-end`}>
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <form onSubmit={submit} className="grid items-end gap-3 sm:grid-cols-[8rem_1fr_9rem_auto]">
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

function TokenDialog({ token, onClose }: { token: string; onClose: () => void }) {
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
