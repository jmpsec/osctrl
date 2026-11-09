import { useCallback, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getSantaConfig,
  putSantaConfig,
  rotateSantaToken,
  santaQueryKey,
  SANTA_TOKEN_HEADER,
  type SantaConfig,
} from '$/api/santa';
import { getEnvironment } from '$/api/environments';
import { Button } from '$/components/atoms/Button';
import { Input } from '$/components/atoms/Input';
import { Label } from '$/components/atoms/Label';
import { Skeleton } from '$/components/data/Skeleton';
import { ModalShell } from '$/components/feedback/ModalShell';
import { errorText } from './table';

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
        block_usb_mount: form.block_usb_mount,
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
      <label className="flex items-center gap-2 text-sm text-[color:var(--text-2)]">
        <input
          type="checkbox"
          checked={form.block_usb_mount}
          onChange={(e) => setForm({ ...form, block_usb_mount: e.target.checked })}
        />
        {t('santa.blockUsb')}
      </label>
      {save.isError && <p role="alert" className="text-sm text-[color:var(--danger)]">{errorText(save.error)}</p>}
      {save.isSuccess && <p role="status" className="text-sm text-[color:var(--text-3)]">{t('santa.saved')}</p>}
      <div className="flex justify-end">
        <Button type="submit" disabled={save.isPending}>{t('common.save')}</Button>
      </div>
    </form>
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
