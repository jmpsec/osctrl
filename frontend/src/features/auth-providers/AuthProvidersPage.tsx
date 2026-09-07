import { useState, useMemo, useEffect, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { usePageTitle } from '$/lib/usePageTitle';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listAuthProviders,
  listAuthProviderTypes,
  createAuthProvider,
  updateAuthProvider,
  deleteAuthProvider,
  revertAuthProvider,
  testAuthProvider,
  fetchIdPMetadata,
  applyAuthProviders,
  getAuthProvider,
  type AuthProvider,
  type AuthProviderTypeSpec,
  type AuthProviderFieldSpec,
  type AuthProviderCreateRequest,
} from '$/api/auth-providers';
import { getFeatures } from '$/api/features';
import { getServiceCommand } from '$/api/service-config';
import { AuthError, ApiError } from '$/api/client';
import { formatRelative } from '$/lib/time';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { cn } from '$/lib/cn';
import { StatusBadge } from '$/components/data/StatusBadge';
import { MetadataBadge } from '$/components/data/MetadataBadge';
import { Button } from '$/components/atoms/Button';

type ModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'createType'; providerType: string }
  | { kind: 'edit'; provider: AuthProvider }
  | { kind: 'apply' };

const PROVIDER_ICONS: Record<string, ReactNode> = {
  oidc: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="8" cy="15" r="4" />
      <path d="M10.85 12.15L19 4M18 5l2 2M15 8l2-2" />
    </svg>
  ),
  saml: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
};

function providerIcon(type: string): ReactNode {
  return PROVIDER_ICONS[type] ?? PROVIDER_ICONS.oidc;
}

export function AuthProvidersPage() {
  const { t } = useTranslation();
  usePageTitle(t('pageTitle.authProviders'));
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });
  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [reloading, setReloading] = useState(false);

  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  const configDisabled = features?.auth_providers === false;

  const { data: providers, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ['auth-providers'],
    queryFn: () => listAuthProviders(),
    enabled: !!features?.auth_providers,
    staleTime: 30_000,
  });

  const { data: types } = useQuery({
    queryKey: ['auth-provider-types'],
    queryFn: () => listAuthProviderTypes(),
    staleTime: 60_000,
    enabled: !!features?.auth_providers,
  });

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ['auth-providers'] });
    void refetch();
  }

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteAuthProvider(id),
    onSuccess: () => invalidate(),
    onError: (e) => {
      if (e instanceof AuthError) { void navigate({ to: '/login' }); return; }
      setApplyErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  const revertMutation = useMutation({
    mutationFn: (id: number) => revertAuthProvider(id),
    onSuccess: () => invalidate(),
    onError: (e) => {
      if (e instanceof AuthError) { void navigate({ to: '/login' }); return; }
      setApplyErr(e instanceof Error ? e.message : 'Revert failed');
    },
  });

  const applyMutation = useMutation({
    mutationFn: () => applyAuthProviders(),
    onSuccess: (resp) => {
      setApplyErr(null);
      if (!resp.command) {
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
          .catch(() => { clearInterval(poll); setReloading(false); });
      }, 1500);
    },
    onError: (e: unknown) => {
      setApplyErr(e instanceof Error ? e.message : String(e));
    },
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  if (configDisabled) {
    return (
      <div className="flex flex-col h-full min-h-0">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
          <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">Auth Providers</h1>
          <p className="text-xs text-[color:var(--text-3)]">Manage OIDC and SAML federated login providers.</p>
        </div>
        <div className="flex-1 overflow-auto min-h-0">
          <EmptyState icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" /></svg>}
            title="Auth Providers API is disabled"
            description="Set serviceConfigEnabled: true and restart osctrl-api to manage providers here." />
        </div>
      </div>
    );
  }

  const rows = providers ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">Auth Providers</h1>
        <p className="text-xs text-[color:var(--text-3)]">OIDC and SAML federated login. One button per enabled provider on the login page.</p>
        <div className="ml-auto flex items-center gap-2">
          {isFetching && !isLoading && (
            <span className="text-xs text-[color:var(--text-3)] tabular-nums">refreshing…</span>
          )}
          <Button type="button" onClick={() => setModal({ kind: 'create' })}>
            New provider
          </Button>
          <button type="button" disabled={reloading}
            onClick={() => { setApplyErr(null); setModal({ kind: 'apply' }); }}
            className={cn('px-3 py-1 text-xs font-medium rounded transition-colors',
              reloading ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)]'
                : 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)] hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.2)]',
              'disabled:opacity-50 disabled:cursor-not-allowed')}>
            {reloading ? 'Reloading…' : applyFlash ? 'Reload triggered ✓' : 'Apply changes'}
          </button>
        </div>
      </div>

      {applyErr && (
        <div role="alert" className={cn('flex items-center gap-3 px-4 py-2.5 border-b', 'border-[color:var(--danger)]/40 bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)]', 'text-xs text-[color:var(--danger)]')}>
          <span>{applyErr}</span>
          <button type="button" onClick={() => setApplyErr(null)} className="ml-auto text-[color:var(--text-3)] hover:text-[color:var(--text-1)]" aria-label="Dismiss">×</button>
        </div>
      )}

      <div className="flex-1 overflow-auto min-h-0">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="border-b border-[color:var(--border)] bg-[color:var(--bg-0)] sticky top-0 z-10">
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">Name</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">Type</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide w-24">Enabled</th>
              <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide w-24">Source</th>
              <th scope="col" className="px-4 py-3 text-right text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide">Updated</th>
              <th scope="col" className="px-2 py-3 w-1" />
            </tr>
          </thead>
          <tbody>
            {isLoading && Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cells={6} />)}
            {isError && !isLoading && (
              <tr><td colSpan={6}>
                <EmptyState icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" /></svg>}
                  title={error instanceof Error ? error.message : 'Failed to load auth providers'}
                  action={<button type="button" onClick={() => void refetch()} className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)] transition-colors">Retry</button>} />
              </td></tr>
            )}
            {!isLoading && !isError && rows.length === 0 && (
              <tr><td colSpan={6}>
                <EmptyState icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6l8-4z" /></svg>}
                  title="No auth providers configured." description="Add an OIDC or SAML provider to enable federated login."
                  action={<button type="button" onClick={() => setModal({ kind: 'create' })} className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)] transition-colors">Add a provider</button>} />
              </td></tr>
            )}
            {!isLoading && !isError && rows.map((p) => (
              <tr key={p.id} className="border-b border-[color:var(--border)] hover:bg-[color:var(--bg-3)] transition-colors">
                <td className="px-4 py-3">
                  <span className="text-sm font-semibold text-[color:var(--text-1)] tabular-nums">{p.name}</span>
                  {p.info && <span className="ml-2 text-xs text-[color:var(--text-3)] truncate max-w-[240px]" title={p.info}>— {p.info}</span>}
                </td>
                <td className="px-4 py-3 text-xs">
                  <span className="flex items-center gap-1.5">
                    <span className="w-4 h-4 flex-shrink-0 text-[color:var(--text-3)]">{providerIcon(p.type)}</span>
                    <span className="tabular-nums">{p.type}</span>
                  </span>
                </td>
                <td className="px-4 py-3 text-xs">
                  {p.enabled ? (
                    <StatusBadge variant="success" label="Enabled" />
                  ) : (
                    <StatusBadge variant="dim" label="Disabled" />
                  )}
                </td>
                <td className="px-4 py-3 text-xs">
                  {p.source === 'db' ? (
                    <MetadataBadge>Edited</MetadataBadge>
                  ) : (
                    <MetadataBadge className="cursor-help" title={`Seeded from service config (source: ${p.source})`}>Seeded</MetadataBadge>
                  )}
                </td>
                <td className="px-4 py-3 text-xs text-[color:var(--text-2)] text-right tabular-nums">
                  <span title={p.updated_at}>{formatRelative(p.updated_at)}</span>
                </td>
                <td className="px-2 py-3 text-right whitespace-nowrap">
                  <button type="button" onClick={() => setModal({ kind: 'edit', provider: p })}
                    className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors">Edit</button>
                  {p.source === 'db' && (
                    <button type="button" disabled={revertMutation.isPending}
                      onClick={() => { if (confirm(`Revert "${p.name}" to service config?`)) revertMutation.mutate(p.id); }}
                      title="Reset back to service configuration values. Takes effect on the next Apply."
                      className="px-2 py-1 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50">Revert</button>
                  )}
                  <button type="button" disabled={deleteMutation.isPending}
                    onClick={() => { if (confirm(`Delete provider "${p.name}"?`)) deleteMutation.mutate(p.id); }}
                    className="px-2 py-1 text-xs font-medium rounded text-[color:var(--danger)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {modal.kind === 'create' && (
        <ProviderTypePicker types={types ?? []} onPick={(t) => setModal({ kind: 'createType', providerType: t })} onClose={() => setModal({ kind: 'closed' })} />
      )}
      {modal.kind === 'createType' && (
        <ProviderEditor mode="create" types={types ?? []} providerType={modal.providerType}
          onClose={() => setModal({ kind: 'closed' })} onSaved={invalidate} />
      )}
      {modal.kind === 'edit' && (
        <ProviderEditor mode="edit" types={types ?? []} providerType={modal.provider.type} existing={modal.provider}
          onClose={() => setModal({ kind: 'closed' })} onSaved={invalidate} />
      )}
      {modal.kind === 'apply' && (
        <ApplyConfirmDialog isPending={reloading}
          onConfirm={() => { setModal({ kind: 'closed' }); applyMutation.mutate(); }}
          onCancel={() => setModal({ kind: 'closed' })} />
      )}
    </div>
  );
}

function ProviderTypePicker({ types, onPick, onClose }: { types: AuthProviderTypeSpec[]; onPick: (t: string) => void; onClose: () => void; }) {
  return (
    <ModalShell title="New auth provider" titleId="auth-provider-type-picker-title" onClose={onClose} panelClassName="max-w-lg">
      <div className="space-y-3">
        <p className="text-xs text-[color:var(--text-3)]">Choose a provider type. The next step configures its fields.</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {types.map((t) => (
            <button key={t.type} type="button" onClick={() => onPick(t.type)}
              className={cn('flex items-start gap-3 px-3 py-2.5 rounded-md text-left', 'border border-[color:var(--border)] bg-[color:var(--bg-3)]', 'hover:border-[color:var(--signal)] hover:bg-[color:var(--bg-1)]', 'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]')}>
              <span className="flex-shrink-0 w-5 h-5 text-[color:var(--text-3)] mt-0.5">{providerIcon(t.type)}</span>
              <span className="flex flex-col gap-0.5 min-w-0">
                <span className="text-sm font-semibold text-[color:var(--text-1)] tabular-nums">{t.type}</span>
                <span className="text-xs text-[color:var(--text-3)]">{t.description}</span>
              </span>
            </button>
          ))}
        </div>
        <div className="flex justify-end pt-1">
          <button type="button" onClick={onClose} className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors">Cancel</button>
        </div>
      </div>
    </ModalShell>
  );
}

function ProviderEditor({ mode, types, providerType, existing, onClose, onSaved }: {
  mode: 'create' | 'edit'; types: AuthProviderTypeSpec[]; providerType: string; existing?: AuthProvider; onClose: () => void; onSaved: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? '');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [info, setInfo] = useState(existing?.info ?? '');
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [testing, setTesting] = useState(false);

  const spec = useMemo(() => types.find((t) => t.type === providerType), [types, providerType]);

  // Field values are a flat map keyed by the field's Name. buildConfig
  // builds the JSON object from them on submit. Initial values come
  // from the existing config (decoded into a flat map) or from the
  // spec defaults on create.
  const [fieldValues, setFieldValues] = useState<Record<string, unknown>>(() =>
    existing ? flattenConfig(existing.config) : defaultsForSpec(spec),
  );

  // When editing a secret-bearing provider, fetch the revealed config
  // so the operator can see the current secret value.
  const revealSecret = useQuery({
    queryKey: ['auth-provider-reveal', existing?.id],
    queryFn: () => getAuthProvider(existing!.id, true),
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
        const body: AuthProviderCreateRequest = { name: trimmedName, type: providerType, enabled, config, info: info.trim() || undefined };
        return createAuthProvider(body);
      }
      return updateAuthProvider(existing!.id, { name: trimmedName, type: providerType, enabled, config, info: info.trim() || undefined });
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['auth-providers'] }); onSaved(); onClose(); },
    onError: (e) => { if (e instanceof AuthError) { window.location.href = '/login'; return; } setErr(e instanceof Error ? e.message : 'Save failed'); },
  });

  async function handleTest() {
    setErr(null);
    setTesting(true);
    setTestResult(null);
    try {
      const config = buildConfig(spec, fieldValues);
      const result = await testAuthProvider(providerType, config);
      setTestResult(result);
    } catch (e) {
      setTestResult({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setTesting(false);
    }
  }

  const inputClass = cn('w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]', 'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums', 'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]');

  return (
    <ModalShell title={mode === 'create' ? `Add ${providerType} provider` : `Edit ${existing?.name}`} titleId="auth-provider-editor-title" onClose={onClose} bodyClassName="max-h-[70vh] overflow-y-auto">
      <form onSubmit={(e) => { e.preventDefault(); mutation.mutate(); }} className="space-y-4">
        <div>
          <label htmlFor="provider-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">Name</label>
          <input id="provider-name" type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. github-oidc" className={inputClass} />
          <p className="mt-1 text-xs text-[color:var(--text-3)]">Unique label shown on the login page button.</p>
        </div>
        <div>
          <span className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">Type</span>
          <span className="inline-flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[color:var(--bg-3)] border border-[color:var(--border)] text-sm tabular-nums text-[color:var(--text-1)]">
            <span className="w-4 h-4 flex-shrink-0 text-[color:var(--text-3)]">{providerIcon(providerType)}</span>
            {providerType}
          </span>
          {spec?.has_secret && <p className="mt-1 text-xs text-[color:var(--text-3)]">This provider stores credentials ({spec.secret_fields?.join(', ')}). Secret fields are revealed for editing.</p>}
        </div>
        <fieldset className="flex items-end gap-2 pb-2">
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="rounded border-[color:var(--border)] accent-[color:var(--signal)]" />
            <span className="tabular-nums">enabled</span>
          </label>
        </fieldset>

        <ProviderConfigFields
          key={providerType}
          spec={spec}
          values={fieldValues}
          onChange={setFieldValues}
          inputClass={inputClass}
        />

        <div className="flex items-center gap-2">
          <button type="button" onClick={handleTest} disabled={testing}
            className={cn('px-2.5 py-1 text-xs font-medium rounded', 'border border-[color:var(--border)] text-[color:var(--text-2)]', 'hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50')}>
            {testing ? 'Testing…' : 'Test connection'}
          </button>
          {testResult && (
            <span className={cn('text-xs', testResult.ok ? 'text-[color:var(--success)]' : 'text-[color:var(--danger)]')}>
              {testResult.ok ? '✓ Connection successful' : `✕ ${testResult.error ?? 'Failed'}`}
            </span>
          )}
        </div>

        <div>
          <label htmlFor="provider-info" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">Info (optional)</label>
          <input id="provider-info" type="text" value={info} onChange={(e) => setInfo(e.target.value)} className={inputClass} />
        </div>
        {err && <p role="alert" className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md">{err}</p>}
        <div className="flex items-center justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-3)] transition-colors">Cancel</button>
          <button type="submit" disabled={mutation.isPending || !name.trim()}
            className={cn('px-3 py-1.5 text-xs font-medium rounded-md', 'bg-[color:var(--signal)] text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]', 'transition-colors disabled:opacity-50 disabled:cursor-not-allowed')}>
            {mutation.isPending ? 'Saving…' : mode === 'create' ? 'Add provider' : 'Save changes'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

function ApplyConfirmDialog({ isPending, onConfirm, onCancel }: { isPending: boolean; onConfirm: () => void; onCancel: () => void; }) {
  return (
    <ModalShell title="Apply auth provider changes" titleId="auth-providers-apply-title" onClose={onCancel} panelClassName="max-w-md">
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This will hot-reload osctrl-api with the current provider rows. The service is not restarted, but{' '}
          <strong className="text-[color:var(--warning)]">users mid-login may see a transient error</strong> and can retry.
        </p>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button type="button" onClick={onCancel} disabled={isPending}
            className="px-3 py-1.5 text-xs font-medium rounded border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">Cancel</button>
          <button type="button" onClick={onConfirm} disabled={isPending}
            className={cn('px-3 py-1.5 text-xs font-medium rounded transition-colors', 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]', 'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]', 'disabled:opacity-40 disabled:cursor-not-allowed')}>
            {isPending ? 'Reloading…' : 'Reload now'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Dynamic typed config form — same pattern as LogSinksPage
// ---------------------------------------------------------------------------

function ProviderConfigFields({ spec, values, onChange, inputClass }: {
  spec?: AuthProviderTypeSpec;
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  inputClass: string;
}) {
  const [fetching, setFetching] = useState(false);
  const [fetchErr, setFetchErr] = useState<string | null>(null);

  if (!spec || !spec.fields || spec.fields.length === 0) {
    return <p className="text-xs text-[color:var(--text-3)] italic">This provider type has no configurable fields.</p>;
  }

  function setField(name: string, v: unknown) { onChange({ ...values, [name]: v }); }

  // Fetch IdP metadata from the URL field and populate the XML field.
  // Only shown for SAML providers that have both IDPMetadataURL and
  // IDPMetadataXML fields.
  const isSAML = spec.type === 'saml';
  const metadataURL = String(values['IDPMetadataURL'] ?? '');

  async function handleFetchMetadata() {
    if (!metadataURL) return;
    setFetchErr(null);
    setFetching(true);
    try {
      const result = await fetchIdPMetadata(metadataURL);
      setField('IDPMetadataXML', result.xml);
    } catch (e) {
      setFetchErr(e instanceof Error ? e.message : 'Failed to fetch metadata');
    } finally {
      setFetching(false);
    }
  }
  return (
    <fieldset className="space-y-3 border border-[color:var(--border)] rounded-md p-3">
      <legend className="px-1 text-xs font-semibold text-[color:var(--text-2)]">Configuration</legend>
      {spec.fields.map((f) => (
        <div key={f.name}>
          <ProviderConfigField field={f} value={values[f.name]} onChange={(v) => setField(f.name, v)} inputClass={inputClass} />
          {isSAML && f.name === 'IDPMetadataURL' && (
            <div className="flex items-center gap-2 -mt-1">
              <button
                type="button"
                onClick={handleFetchMetadata}
                disabled={fetching || !metadataURL}
                className={cn(
                  'px-2.5 py-1 text-xs font-medium rounded',
                  'border border-[color:var(--border)] text-[color:var(--text-2)]',
                  'hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-50',
                )}
              >
                {fetching ? 'Fetching…' : 'Fetch metadata'}
              </button>
              <span className="text-xs text-[color:var(--text-3)]">
                Fetches the XML from the URL above and fills the IdP metadata XML field below.
              </span>
              {fetchErr && (
                <span className="text-xs text-[color:var(--danger)]">{fetchErr}</span>
              )}
            </div>
          )}
        </div>
      ))}
    </fieldset>
  );
}

function ProviderConfigField({ field, value, onChange, inputClass }: {
  field: AuthProviderFieldSpec;
  value: unknown;
  onChange: (v: unknown) => void;
  inputClass: string;
}) {
  const id = `provider-cfg-${field.name}`;
  const labelEl = (
    <label htmlFor={id} className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
      {field.label}
      {field.required && <span className="text-[color:var(--danger)]" aria-hidden="true"> *</span>}
    </label>
  );
  const helpEl = field.help && <p className="mt-1 text-xs text-[color:var(--text-3)]">{field.help}</p>;

  switch (field.type) {
    case 'boolean':
      return (
        <div>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input id={id} type="checkbox" aria-label={field.label} checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} className="rounded border-[color:var(--border)] accent-[color:var(--signal)]" />
            <span className="tabular-nums">{field.label}</span>
          </label>
          {helpEl}
        </div>
      );
    case 'integer':
      return (
        <div>
          {labelEl}
          <input id={id} type="number" aria-label={field.label} value={value === undefined || value === null ? '' : String(value)}
            onChange={(e) => { const raw = e.target.value; onChange(raw === '' ? undefined : Number(raw)); }}
            placeholder={field.placeholder} className={inputClass} />
          {helpEl}
        </div>
      );
    case 'select':
      return (
        <div>
          {labelEl}
          <select id={id} aria-label={field.label} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)} className={inputClass}>
            {field.options?.map((opt) => <option key={opt} value={opt}>{opt === '' ? '— none —' : opt}</option>)}
          </select>
          {helpEl}
        </div>
      );
    case 'password':
      return (
        <div>
          {labelEl}
          <input id={id} type="password" aria-label={field.label} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder} autoComplete="off" className={cn(inputClass, 'text-[color:var(--text-2)]')} />
          {helpEl}
        </div>
      );
    case 'text':
      return (
        <div>
          {labelEl}
          <textarea id={id} aria-label={field.label} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder} spellCheck={false}
            className={cn('w-full px-3 py-2 text-xs rounded-md border border-[color:var(--border)]', 'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums', 'min-h-[80px] focus:outline focus:outline-2 focus:outline-[color:var(--signal)]')} />
          {helpEl}
        </div>
      );
    case 'string':
    default:
      return (
        <div>
          {labelEl}
          <input id={id} type="text" aria-label={field.label} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder} className={inputClass} />
          {helpEl}
        </div>
      );
  }
}

function defaultsForSpec(spec?: AuthProviderTypeSpec): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of spec?.fields ?? []) {
    if (f.default !== undefined && f.default !== null && f.default !== '') {
      out[f.name] = f.default;
    }
  }
  return out;
}

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

function buildConfig(spec: AuthProviderTypeSpec | undefined, values: Record<string, unknown>): unknown {
  const out: Record<string, unknown> = {};
  for (const f of spec?.fields ?? []) {
    const v = values[f.name];
    if (v === undefined || v === null || v === '') continue;
    // Handle comma-separated string fields that should be arrays
    if (f.name === 'Scopes' || f.name === 'RequiredGroups') {
      const parts = String(v).split(',').map((s) => s.trim()).filter((s) => s !== '');
      if (parts.length > 0) {
        out[f.name] = parts;
      }
      continue;
    }
    setDotted(out, f.name, v);
  }
  return out;
}

function setDotted(obj: Record<string, unknown>, key: string, value: unknown) {
  const parts = key.split('.');
  if (parts.length === 1) { obj[parts[0]] = value; return; }
  const [head, ...rest] = parts;
  if (typeof obj[head] !== 'object' || obj[head] === null) { obj[head] = {}; }
  setDotted(obj[head] as Record<string, unknown>, rest.join('.'), value);
}

export default AuthProvidersPage;
