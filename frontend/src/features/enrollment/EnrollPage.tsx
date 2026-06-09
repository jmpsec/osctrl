import { useState } from 'react';
import { useParams, useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import {
  getEnrollData,
  getRemoveData,
  enrollAction,
  removeAction,
  type EnrollAction,
  type RemoveAction,
  type PackageActionBody,
} from '$/api/enrollment';
import { getEnvironment } from '$/api/environments';
import { AuthError, ApiError } from '$/api/client';
import { Button } from '$/components/atoms/Button';
import { Skeleton } from '$/components/data/Skeleton';
import { cn } from '$/lib/cn';
import { formatRelative } from '$/lib/time';
import { CertificateCard } from './CertificateCard';

/**
 * EnrollPage (v2) — env-scoped node enrollment portal.
 *
 * Layout (xl+):
 *   ┌─────────────────────────────────────────────────────────────────┐
 *   │ Header                                                          │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │ NotAcceptingBanner (only when accept_enrolls=false)             │
 *   ├──────────────────────────────────────┬──────────────────────────┤
 *   │ ScriptPanel                          │ LifecycleCard (enroll)   │
 *   │  ScriptViewToggle (Install / Remove) │ LifecycleCard (remove)   │
 *   │  PlatformTabs    (Linux / Windows)   │ PackageUrlCard           │
 *   │  Single <pre>                        │  (sticky on xl)          │
 *   └──────────────────────────────────────┴──────────────────────────┘
 *
 * Data layer lives in $/api/enrollment.
 */

type Direction = 'install' | 'remove';
type Platform = 'sh' | 'ps1';

type DataResult = UseQueryResult<{ data: string }, Error>;

export function EnrollPage() {
  const { env } = useParams({ from: '/_app/env/$env/enroll' });
  const navigate = useNavigate({ from: '/_app/env/$env/enroll' });
  const qc = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Tab state — toggling these only swaps which prefetched query
  // we render inside ScriptPanel's single <pre>.
  const [scriptView, setScriptView] = useState<Direction>('install');
  const [platform, setPlatform] = useState<Platform>('sh');

  const envQuery = useQuery({
    queryKey: ['env', env],
    queryFn: () => getEnvironment(env),
    staleTime: 30_000,
  });

  if (envQuery.isError && envQuery.error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const e = envQuery.data;

  // 4 warm queries — flipping the toggle/tabs swaps the visible one instantly.
  const enrollSh = useQuery({
    queryKey: ['enrollment', env, 'enroll.sh'],
    queryFn: () => getEnrollData(env, 'enroll.sh'),
    staleTime: 30_000,
    enabled: !!e,
  });
  const enrollPs1 = useQuery({
    queryKey: ['enrollment', env, 'enroll.ps1'],
    queryFn: () => getEnrollData(env, 'enroll.ps1'),
    staleTime: 30_000,
    enabled: !!e,
  });
  const removeSh = useQuery({
    queryKey: ['enrollment', env, 'remove.sh'],
    queryFn: () => getRemoveData(env, 'remove.sh'),
    staleTime: 30_000,
    enabled: !!e,
  });
  const removePs1 = useQuery({
    queryKey: ['enrollment', env, 'remove.ps1'],
    queryFn: () => getRemoveData(env, 'remove.ps1'),
    staleTime: 30_000,
    enabled: !!e,
  });

  // Lifecycle mutations
  const enrollMut = useMutation({
    mutationFn: (action: EnrollAction) => enrollAction(env, action),
    onSuccess: () => {
      setServerError(null);
      void qc.invalidateQueries({ queryKey: ['enrollment', env] });
      void qc.invalidateQueries({ queryKey: ['env', env] });
    },
    onError: (err) => setServerError(err instanceof ApiError ? err.message : 'Action failed'),
  });
  const removeMut = useMutation({
    mutationFn: (action: RemoveAction) => removeAction(env, action),
    onSuccess: () => {
      setServerError(null);
      void qc.invalidateQueries({ queryKey: ['enrollment', env] });
      void qc.invalidateQueries({ queryKey: ['env', env] });
    },
    onError: (err) => setServerError(err instanceof ApiError ? err.message : 'Action failed'),
  });

  async function copy(target: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(target);
      setTimeout(() => setCopied((prev) => (prev === target ? null : prev)), 1500);
    } catch {
      setServerError('Copy failed — your browser blocked clipboard access.');
    }
  }

  // Package URL state — seeded once from the env row.
  const [debUrl, setDebUrl] = useState('');
  const [rpmUrl, setRpmUrl] = useState('');
  const [pkgUrl, setPkgUrl] = useState('');
  const [msiUrl, setMsiUrl] = useState('');
  const [seeded, setSeeded] = useState(false);
  if (!seeded && e) {
    setDebUrl(e.deb_package || '');
    setRpmUrl(e.rpm_package || '');
    setPkgUrl(e.pkg_package || '');
    setMsiUrl(e.msi_package || '');
    setSeeded(true);
  }

  const pkgMut = useMutation({
    mutationFn: (args: { action: EnrollAction; body: PackageActionBody }) =>
      enrollAction(env, args.action, args.body),
    onSuccess: () => {
      setServerError(null);
      void qc.invalidateQueries({ queryKey: ['env', env] });
    },
    onError: (err) => setServerError(err instanceof ApiError ? err.message : 'Save failed'),
  });

  const notAccepting = !!e && !e.accept_enrolls;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Page header ───────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)] flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
            enrollment
          </div>
          <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
            Enroll & unenroll
          </h1>
          {e && (
            <p className="text-xs text-[color:var(--text-2)] mt-0.5">
              Environment <span className="font-mono-tabular text-[color:var(--text-1)]">{e.name}</span>
            </p>
          )}
        </div>
        {e && (
          <span
            className={cn(
              'inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[11px] font-medium',
              e.accept_enrolls
                ? 'bg-[color:var(--success)]/10 text-[color:var(--success)] border border-[color:var(--success)]/30'
                : 'bg-[color:var(--danger)]/10 text-[color:var(--danger)] border border-[color:var(--danger)]/30',
            )}
          >
            <span aria-hidden className="w-1.5 h-1.5 rounded-full bg-current" />
            {e.accept_enrolls ? 'accepting enrolls' : 'not accepting enrolls'}
          </span>
        )}
      </div>

      {/* ── Full-bleed NotAcceptingBanner ─────────────────────────────── */}
      <NotAcceptingBanner show={notAccepting} />

      {/* ── Content ───────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="px-6 py-6 max-w-[1400px] mx-auto">
          {serverError && (
            <div className="mb-4 rounded-lg border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 px-3 py-2.5 text-sm text-[color:var(--danger)]">
              {serverError}
            </div>
          )}

          {/* 2-col @ xl: scripts flex + sticky 320px right rail.        *
           *  When enrolls are off, left column is dimmed but right     *
           *  rail stays interactive so operators can rotate to resume. */}
          <div className="flex flex-col xl:flex-row gap-5 items-start">
            <div
              className={cn(
                'flex-1 min-w-0 w-full transition-opacity',
                notAccepting && 'opacity-50 pointer-events-none',
              )}
              aria-hidden={notAccepting || undefined}
            >
              <ScriptPanel
                scriptView={scriptView}
                setScriptView={setScriptView}
                platform={platform}
                setPlatform={setPlatform}
                enrollSh={enrollSh}
                enrollPs1={enrollPs1}
                removeSh={removeSh}
                removePs1={removePs1}
                copied={copied}
                onCopy={copy}
              />
            </div>

            <aside className="w-full xl:w-80 xl:flex-shrink-0 xl:sticky xl:top-6 space-y-4">
              <LifecycleCard
                label="Enroll secret"
                expireValue={e?.enroll_expire}
                onAction={(a) => enrollMut.mutate(a as EnrollAction)}
                isPending={enrollMut.isPending}
              />
              <LifecycleCard
                label="Remove secret"
                expireValue={e?.remove_expire}
                onAction={(a) => removeMut.mutate(a as RemoveAction)}
                isPending={removeMut.isPending}
              />
              <CertificateCard env={env} />
            </aside>
          </div>

          {/* Full-width package URL setters below the 2-col block. The
              four input rows ([label][url input][Save]) are too cramped
              in the 320px right rail, so they get the whole content
              width here. Inherits the same dim-on-not-accepting state
              as the left column above. */}
          <div
            className={cn(
              'mt-5 transition-opacity',
              notAccepting && 'opacity-50 pointer-events-none',
            )}
            aria-hidden={notAccepting || undefined}
          >
            <PackageUrlCard
              debUrl={debUrl}
              setDebUrl={setDebUrl}
              rpmUrl={rpmUrl}
              setRpmUrl={setRpmUrl}
              pkgUrl={pkgUrl}
              setPkgUrl={setPkgUrl}
              msiUrl={msiUrl}
              setMsiUrl={setMsiUrl}
              isPending={pkgMut.isPending}
              onSave={(action, body) => pkgMut.mutate({ action, body })}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

export default EnrollPage;

// ---------------------------------------------------------------------------
// NotAcceptingBanner — full-bleed danger-tinted strip shown only when an env
// is not accepting enrolls. Returns null when `show` is false so the consumer
// can render unconditionally.
// ---------------------------------------------------------------------------
function NotAcceptingBanner({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <div
      role="alert"
      className={cn(
        'px-6 py-3 border-b border-[color:var(--danger)]/30',
        'bg-[color:var(--danger)]/10 text-[color:var(--danger)]',
      )}
    >
      <div className="flex items-start gap-3 max-w-[1400px] mx-auto">
        <svg
          aria-hidden
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          className="w-5 h-5 flex-shrink-0 mt-0.5"
        >
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v4M12 16h.01" />
        </svg>
        <div>
          <p className="text-sm font-semibold">This environment is not accepting enrolls.</p>
          <p className="text-xs mt-0.5 text-[color:var(--danger)]/90">
            Install scripts are hidden until enroll acceptance is re-enabled — use the lifecycle
            controls on the right to rotate or extend the enroll secret and resume.
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScriptViewToggle — full-width segmented control (Install / Remove).
// ---------------------------------------------------------------------------
function ScriptViewToggle({
  value,
  onChange,
}: {
  value: Direction;
  onChange: (v: Direction) => void;
}) {
  const options: { id: Direction; label: string }[] = [
    { id: 'install', label: 'Install' },
    { id: 'remove', label: 'Remove' },
  ];
  return (
    <div
      role="radiogroup"
      aria-label="Script direction"
      className="grid grid-cols-2 gap-0.5 rounded-md bg-[color:var(--bg-2)] border border-[color:var(--border)] p-0.5"
    >
      {options.map((opt) => {
        const active = value === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.id)}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded transition-colors',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              active
                ? 'bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-sm'
                : 'text-[color:var(--text-3)] hover:bg-[color:var(--bg-1)]/50',
            )}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PlatformTabs — small underline tab strip (Linux / Windows).
// ---------------------------------------------------------------------------
function PlatformTabs({
  value,
  onChange,
}: {
  value: Platform;
  onChange: (v: Platform) => void;
}) {
  const tabs: { id: Platform; label: string }[] = [
    { id: 'sh', label: 'Linux / macOS' },
    { id: 'ps1', label: 'Windows' },
  ];
  return (
    <div role="tablist" aria-label="Target platform" className="flex items-center gap-4">
      {tabs.map((t) => {
        const active = value === t.id;
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={cn(
              'pb-1.5 text-xs transition-colors border-b-2',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              active
                ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
                : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
            )}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScriptPanel — outer card. Picks the active query result from
// {enrollSh, enrollPs1, removeSh, removePs1} based on scriptView + platform
// and renders it inside a single <pre> so the toggle just swaps content.
// ---------------------------------------------------------------------------
function ScriptPanel({
  scriptView,
  setScriptView,
  platform,
  setPlatform,
  enrollSh,
  enrollPs1,
  removeSh,
  removePs1,
  copied,
  onCopy,
}: {
  scriptView: Direction;
  setScriptView: (v: Direction) => void;
  platform: Platform;
  setPlatform: (v: Platform) => void;
  enrollSh: DataResult;
  enrollPs1: DataResult;
  removeSh: DataResult;
  removePs1: DataResult;
  copied: string | null;
  onCopy: (target: string, text: string) => void;
}) {
  // Resolve which of the 4 queries to surface.
  const activeQuery: DataResult =
    scriptView === 'install'
      ? platform === 'sh' ? enrollSh : enrollPs1
      : platform === 'sh' ? removeSh : removePs1;

  const targetName =
    scriptView === 'install'
      ? platform === 'sh' ? 'enroll.sh' : 'enroll.ps1'
      : platform === 'sh' ? 'remove.sh' : 'remove.ps1';

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
      aria-label="Install / remove scripts"
    >
      <div className="px-4 pt-4 pb-3 space-y-3 border-b border-[color:var(--border)]">
        <ScriptViewToggle value={scriptView} onChange={setScriptView} />
        <PlatformTabs value={platform} onChange={setPlatform} />
      </div>

      <div className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
            {scriptView === 'install' ? 'one-liner enroll' : 'one-liner remove'}
            {' · '}
            {platform === 'sh' ? 'bash' : 'powershell'}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => activeQuery.data && onCopy(targetName, activeQuery.data.data)}
            disabled={!activeQuery.data}
          >
            {copied === targetName ? 'Copied ✓' : 'Copy'}
          </Button>
        </div>
        <pre
          className={cn(
            'text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] rounded-md',
            'p-3 overflow-x-auto whitespace-pre-wrap break-all',
            'text-[color:var(--text-1)] min-h-[140px]',
          )}
        >
          {activeQuery.isLoading ? (
            <Skeleton className="h-4 w-full" />
          ) : activeQuery.isError ? (
            <span className="text-[color:var(--danger)]">
              {(activeQuery.error as Error | undefined)?.message ?? 'Failed to load'}
            </span>
          ) : (
            activeQuery.data?.data
          )}
        </pre>
        <p className="mt-2 text-[10px] text-[color:var(--text-3)]">
          The script embeds this environment's enroll secret — handle accordingly.
        </p>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// LifecycleCard — heading row (label · expires …) + 4-button action grid.
// ---------------------------------------------------------------------------
type LifecycleActionId = 'extend' | 'rotate' | 'expire' | 'notexpire';

const LIFECYCLE_ACTIONS: { id: LifecycleActionId; label: string; title: string }[] = [
  { id: 'extend',    label: 'Extend',    title: 'Push the secret expiration further into the future.' },
  { id: 'rotate',    label: 'Rotate',    title: 'Generate a brand new secret immediately — invalidates any not-yet-run install script.' },
  { id: 'expire',    label: 'Expire',    title: 'Invalidate the current secret now. Re-rotate to issue a new one.' },
  { id: 'notexpire', label: 'Never',     title: 'Mark the secret as never expiring. Use sparingly.' },
];

function LifecycleCard({
  label,
  expireValue,
  onAction,
  isPending,
}: {
  label: string;
  expireValue?: string;
  onAction: (a: LifecycleActionId) => void;
  isPending: boolean;
}) {
  // Decide what to show next to the label. The Go API returns the string
  // "never" (or no ISO at all) when the secret is set to non-expiring.
  const expiresText = (() => {
    if (!expireValue) return 'never expires';
    if (expireValue.toLowerCase().includes('never')) return 'never expires';
    const d = new Date(expireValue);
    if (isNaN(d.getTime())) return 'never expires';
    // Future date → "expires in <relative>"; past date → "expired <relative> ago".
    return `expires ${formatRelative(expireValue)}`;
  })();

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label={label}
    >
      <div className="mb-3 flex items-center justify-between gap-2 flex-wrap">
        <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          {label}
        </h2>
        <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums">
          · {expiresText}
        </span>
      </div>
      <div className="grid grid-cols-4 gap-1.5">
        {LIFECYCLE_ACTIONS.map((a) => (
          <Button
            key={a.id}
            variant="ghost"
            size="sm"
            title={a.title}
            onClick={() => onAction(a.id)}
            disabled={isPending}
            className="px-1.5"
          >
            {a.label}
          </Button>
        ))}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// PackageUrlCard — heading + 4 compact rows (DEB / RPM / PKG / MSI).
// Each row: [label][url input][Save] on a single line.
// ---------------------------------------------------------------------------
function PackageUrlCard({
  debUrl,
  setDebUrl,
  rpmUrl,
  setRpmUrl,
  pkgUrl,
  setPkgUrl,
  msiUrl,
  setMsiUrl,
  isPending,
  onSave,
}: {
  debUrl: string;
  setDebUrl: (v: string) => void;
  rpmUrl: string;
  setRpmUrl: (v: string) => void;
  pkgUrl: string;
  setPkgUrl: (v: string) => void;
  msiUrl: string;
  setMsiUrl: (v: string) => void;
  isPending: boolean;
  onSave: (action: EnrollAction, body: PackageActionBody) => void;
}) {
  const rows: {
    label: string;
    value: string;
    onChange: (v: string) => void;
    action: EnrollAction;
    body: () => PackageActionBody;
  }[] = [
    { label: 'DEB',        value: debUrl, onChange: setDebUrl, action: 'set_deb', body: () => ({ deb_url: debUrl }) },
    { label: 'RPM',        value: rpmUrl, onChange: setRpmUrl, action: 'set_rpm', body: () => ({ rpm_url: rpmUrl }) },
    { label: 'PKG (macOS)', value: pkgUrl, onChange: setPkgUrl, action: 'set_pkg', body: () => ({ pkg_url: pkgUrl }) },
    { label: 'MSI (Win)',  value: msiUrl, onChange: setMsiUrl, action: 'set_msi', body: () => ({ msi_url: msiUrl }) },
  ];

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label="Pre-built package URLs"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          Package URLs <span className="text-[color:var(--text-3)] font-normal">· optional</span>
        </h2>
        <span
          className="text-[10px] text-[color:var(--text-3)] cursor-help"
          title="If set, install scripts fetch this pre-built package instead of building one on the fly. Useful for air-gapped or signed installs."
        >
          ⓘ
        </span>
      </div>
      <div className="space-y-2">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center gap-2">
            <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)] uppercase tracking-[0.1em] w-[68px] flex-shrink-0">
              {r.label}
            </span>
            <input
              type="url"
              value={r.value}
              onChange={(ev) => r.onChange(ev.target.value)}
              placeholder="https://…"
              className={cn(
                'flex-1 min-w-0 px-2.5 py-1 rounded-md text-[11px] font-mono-tabular',
                'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
                'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
                'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:border-transparent',
              )}
            />
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onSave(r.action, r.body())}
              disabled={isPending}
            >
              Save
            </Button>
          </div>
        ))}
      </div>
    </section>
  );
}
