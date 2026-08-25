import { useState, useEffect } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
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
import {
  getEnvironment,
  listEnvPackages,
  addEnvPackage,
  removeEnvPackage,
  updateEnvPackage,
  type EnvironmentPackage,
} from '$/api/environments';
import { AuthError, ApiError } from '$/api/client';
import { Button } from '$/components/atoms/Button';
import { Skeleton } from '$/components/data/Skeleton';
import { cn } from '$/lib/cn';
import { formatRelative, formatTimeUntil } from '$/lib/time';
import { CertificateCard } from './CertificateCard';
import { FlagsCard } from './FlagsCard';
import { AssembledConfigCard } from './AssembledConfigCard';
import { DocsLink } from '$/components/atoms/DocsLink';
import { StatusBadge } from '$/components/data/StatusBadge';
import { MetadataBadge } from '$/components/data/MetadataBadge';

/**
 * EnrollPage (v3) — tabbed env-scoped enrollment portal.
 *
 *   ┌─────────────────────────────────────────────────────────────────┐
 *   │ Header — env name + accepting-enrolls badge                     │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │ Install  ·  Configuration  ·  Lifecycle                         │
 *   ├─────────────────────────────────────────────────────────────────┤
 *   │ ┌─ Install ────────────────────────────────────────────────────┐│
 *   │ │ ScriptPanel (Install/Remove · Linux/Windows · one-liner)     ││
 *   │ │ Pre-built package URLs (collapsed by default)                ││
 *   │ └──────────────────────────────────────────────────────────────┘│
 *   │ ┌─ Configuration ──────────────────────────────────────────────┐│
 *   │ │ FlagsCard (per-OS, substituted)                              ││
 *   │ │ AssembledConfigCard (Monaco read-only)                       ││
 *   │ └──────────────────────────────────────────────────────────────┘│
 *   │ ┌─ Lifecycle ──────────────────────────────────────────────────┐│
 *   │ │ LifecycleCard (enroll secret) · LifecycleCard (remove secret)││
 *   │ │ CertificateCard (full — view + replace)                      ││
 *   │ └──────────────────────────────────────────────────────────────┘│
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * Tab choice optimises for the modal trip: an operator who comes here
 * to grab a script doesn't see six cards stacked. Lifecycle (destructive
 * + secret-bearing) lives behind its own tab so it's out of the
 * accidental-click path. Configuration is the rare debugging trip.
 *
 * Data layer lives in $/api/enrollment.
 */

type Direction = 'install' | 'remove';
type Platform = 'sh' | 'ps1';
type PageTab = 'install' | 'configuration' | 'lifecycle';

type DataResult = UseQueryResult<{ data: string }, Error>;

export function EnrollPage() {
  usePageTitle('Enroll');
  const { env } = useParams({ from: '/_app/env/$env/enroll' });
  const navigate = useNavigate({ from: '/_app/env/$env/enroll' });
  const qc = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Page-level tab — splits the page into Install (default), Configuration,
  // and Lifecycle so an operator who comes here just to grab a script
  // doesn't have to wade through six cards. Inner ScriptPanel still has
  // its own Install/Remove + platform toggles.
  const [pageTab, setPageTab] = useState<PageTab>('install');

  // State for the inner ScriptPanel — toggling these only swaps which
  // prefetched query is rendered inside its <pre>.
  const [scriptView, setScriptView] = useState<Direction>('install');
  const [platform, setPlatform] = useState<Platform>('sh');

  // Package URLs section is collapsible on the Install tab so the
  // primary affordance (the script) gets prime real estate.
  const [pkgOpen, setPkgOpen] = useState(false);

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

  // Package URL state is managed by the PackageListCard component
  // which uses the multi-architecture EnvironmentPackage API.
  const [seeded] = useState(false);

  const notAccepting = !!e && !e.accept_enrolls;

  // The Install tab needs the not-accepting dim treatment because scripts +
  // package URLs are useless when enrolls are closed. Configuration and
  // Lifecycle tabs stay fully interactive — those are how the operator
  // FIXES the not-accepting state.
  const installDimCls = cn(notAccepting && 'opacity-50 pointer-events-none');
  const installAriaHidden = notAccepting || undefined;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Page header ───────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)] flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="text-xs font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
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
          <StatusBadge
            variant={e.accept_enrolls ? 'success' : 'danger'}
            label={e.accept_enrolls ? 'Accepting enrollments' : 'Enrollments closed'}
            title={
              e.accept_enrolls
                ? 'New nodes can enroll right now.'
                : 'Enrolls are closed. Use Lifecycle → Rotate to reopen.'
            }
          />
        )}
      </div>

      {/* ── Page tab bar ──────────────────────────────────────────────── */}
      <div
        role="tablist"
        aria-label="Enrollment sections"
        className="flex items-center gap-1 px-4 border-b border-[color:var(--border)] overflow-x-auto"
      >
        <PageTabButton
          id="install"
          label="Install"
          active={pageTab === 'install'}
          onClick={() => setPageTab('install')}
        />
        <PageTabButton
          id="configuration"
          label="Configuration"
          active={pageTab === 'configuration'}
          onClick={() => setPageTab('configuration')}
        />
        <PageTabButton
          id="lifecycle"
          label="Lifecycle"
          active={pageTab === 'lifecycle'}
          onClick={() => setPageTab('lifecycle')}
          warn={notAccepting}
        />
      </div>

      {/* ── Content ───────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="px-6 py-6 max-w-[1400px] mx-auto">
          {serverError && (
            <div className="mb-4 rounded-lg border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 px-3 py-2.5 text-sm text-[color:var(--danger)]">
              {serverError}
            </div>
          )}

          {/* ── Install tab ─────────────────────────────────────────── */}
          {pageTab === 'install' && (
            <div role="tabpanel" aria-labelledby="tab-install" className="space-y-5">
              <div className="flex items-center justify-end -mt-2">
                <DocsLink
                  href="https://osquery.readthedocs.io/en/latest/deployment/remote/"
                  label="enrollment docs"
                />
              </div>
              {notAccepting && (
                <NotAcceptingHint
                  onJumpToLifecycle={() => setPageTab('lifecycle')}
                />
              )}
              <div className={installDimCls} aria-hidden={installAriaHidden}>
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

              {/* Collapsible package URLs — secondary affordance, so we
                  give the script all the room first and only expand
                  this row on demand. */}
              <div className={installDimCls} aria-hidden={installAriaHidden}>
                <Collapsible
                  open={pkgOpen}
                  onToggle={() => setPkgOpen((v) => !v)}
                  title="Pre-built package URLs"
                  subtitle="optional · DEB · RPM · PKG · MSI · per-architecture"
                >
                  <PackageListCard envName={env} />
                </Collapsible>
              </div>
            </div>
          )}

          {/* ── Configuration tab ───────────────────────────────────── */}
          {pageTab === 'configuration' && (
            <div role="tabpanel" aria-labelledby="tab-configuration" className="space-y-5">
              <div className="flex items-center justify-end -mt-2 gap-3">
                <DocsLink
                  href="https://osquery.readthedocs.io/en/latest/installation/cli-flags/"
                  label="flags docs"
                />
                <DocsLink
                  href="https://osquery.readthedocs.io/en/latest/deployment/configuration/"
                  label="config docs"
                />
              </div>
              <FlagsCard env={env} />
              <AssembledConfigCard env={env} />
            </div>
          )}

          {/* ── Lifecycle tab ───────────────────────────────────────── */}
          {pageTab === 'lifecycle' && (
            <div role="tabpanel" aria-labelledby="tab-lifecycle" className="space-y-5">
              <div className="flex items-center justify-end -mt-2">
                <DocsLink
                  href="https://osquery.readthedocs.io/en/latest/deployment/remote/#tls-server"
                  label="enroll/cert docs"
                />
              </div>
              {/* 2-col @ lg: secret cards next to each other; certificate
                  full-width below (Replace textarea needs the room). */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
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
              </div>
              <SecretField envName={env} envDisplayName={e?.name ?? env} />
              <CertificateCard env={env} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PageTabButton — underline tab matching the rest of the SPA (same
// styling as the EnvConfigPage TabButton). `warn` paints a small amber
// dot to the right of the label when the corresponding tab needs
// operator attention (e.g. enrolls closed → Lifecycle tab).
// ---------------------------------------------------------------------------
function PageTabButton({
  id,
  label,
  active,
  warn,
  onClick,
}: {
  id: string;
  label: string;
  active: boolean;
  warn?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      id={`tab-${id}`}
      aria-selected={active}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 px-3 pt-2 pb-1.5 text-xs whitespace-nowrap',
        'border-b-2 transition-colors',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        active
          ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
          : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
      )}
    >
      {label}
      {warn && (
        <span
          aria-hidden
          className="w-1.5 h-1.5 rounded-full bg-[color:var(--warning)]"
          title="Needs attention"
        />
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// SecretField — read-only secret display with copy + download buttons.
// ---------------------------------------------------------------------------
function SecretField({
  envName,
  envDisplayName,
}: {
  envName: string;
  envDisplayName: string;
}) {
  const [secret, setSecret] = useState('');
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['enroll-secret', envName],
    queryFn: () => getEnrollData(envName, 'secret'),
    staleTime: 0,
  });

  useEffect(() => {
    if (data?.data) {
      setSecret(data.data);
    }
  }, [data]);

  async function handleCopy() {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setErr('Copy failed — your browser blocked clipboard access.');
    }
  }

  function handleDownload() {
    if (!secret) return;
    const blob = new Blob([secret], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osctrl-${envDisplayName}.secret`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label="Enroll secret"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          Enroll secret
        </h2>
        <span
          className="text-xs text-[color:var(--text-3)] cursor-help"
          title="The enroll secret authenticates osquery agents to osctrl-tls. Keep it secure — anyone with this secret can enroll nodes."
        >
          ⓘ
        </span>
      </div>

      {isLoading && <Skeleton className="h-9 w-full" />}

      {isError && !isLoading && (
        <div className="flex items-center gap-2">
          <p className="text-xs text-[color:var(--danger)] flex-1">
            {error instanceof Error ? error.message : 'Failed to load secret'}
          </p>
          <Button variant="ghost" size="sm" onClick={() => refetch()}>Retry</Button>
        </div>
      )}

      {!isLoading && !isError && (
        <div className="flex items-center gap-2">
          <input
            type={revealed ? 'text' : 'password'}
            value={secret}
            readOnly
            className={cn(
              'flex-1 min-w-0 px-2.5 py-1.5 rounded-md text-xs font-mono-tabular',
              'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
              'text-[color:var(--text-1)]',
              'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:border-transparent',
            )}
          />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setRevealed((v) => !v)}
            title={revealed ? 'Hide secret' : 'Reveal secret'}
          >
            {revealed ? 'Hide' : 'Show'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            disabled={!secret}
          >
            {copied ? 'Copied ✓' : 'Copy'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleDownload}
            disabled={!secret}
            title={`Download as osctrl-${envDisplayName}.secret`}
          >
            Download
          </Button>
        </div>
      )}

      {err && (
        <p className="mt-2 text-xs text-[color:var(--danger)]">{err}</p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// NotAcceptingHint — compact inline alert on the Install tab when enrolls
// are closed, with a one-click jump to the Lifecycle tab where Rotate
// will reopen them. Replaces the old full-bleed NotAcceptingBanner.
// ---------------------------------------------------------------------------
function NotAcceptingHint({ onJumpToLifecycle }: { onJumpToLifecycle: () => void }) {
  return (
    <div
      role="alert"
      className={cn(
        'rounded-lg border border-[color:var(--danger)]/30',
        'bg-[color:var(--danger)]/10 text-[color:var(--danger)]',
        'px-3 py-2.5 flex items-start gap-3',
      )}
    >
      <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-4 h-4 flex-shrink-0 mt-0.5">
        <circle cx="12" cy="12" r="10" />
        <path d="M12 8v4M12 16h.01" />
      </svg>
      <div className="flex-1 text-xs">
        <p className="font-semibold">This environment is not accepting enrolls.</p>
        <p className="text-[color:var(--danger)]/90 mt-0.5">
          Install scripts are disabled until enrollment reopens.
        </p>
      </div>
      <button
        type="button"
        onClick={onJumpToLifecycle}
        className={cn(
          'px-2 py-1 rounded text-xs font-medium',
          'border border-[color:var(--danger)]/40 text-[color:var(--danger)]',
          'hover:bg-[color:var(--danger)] hover:text-white transition-colors',
        )}
      >
        Open Lifecycle →
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collapsible — generic header + chevron toggle wrapping a child. Used by
// the Install tab to keep the Package URLs row tucked away by default;
// header stays visible so the affordance is discoverable.
// ---------------------------------------------------------------------------
function Collapsible({
  open,
  onToggle,
  title,
  subtitle,
  children,
}: {
  open: boolean;
  onToggle: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className={cn(
          'w-full flex items-center gap-2 px-4 py-3 text-left',
          'hover:bg-[color:var(--bg-2)] transition-colors',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        )}
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={cn(
            'w-3.5 h-3.5 flex-shrink-0 text-[color:var(--text-3)] transition-transform',
            open && 'rotate-90',
          )}
          aria-hidden
        >
          <path d="M9 18l6-6-6-6" />
        </svg>
        <span className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          {title}
        </span>
        {subtitle && (
          <span className="text-xs text-[color:var(--text-3)] font-mono-tabular">
            · {subtitle}
          </span>
        )}
      </button>
      {open && (
        <div className="border-t border-[color:var(--border)]">{children}</div>
      )}
    </div>
  );
}

export default EnrollPage;


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
          <span className="text-xs font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
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
        <p className="mt-2 text-xs text-[color:var(--text-3)]">
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
    const diffMs = d.getTime() - Date.now();
    if (diffMs <= 0) return `expired ${formatRelative(expireValue)} ago`;
    return `expires ${formatTimeUntil(expireValue)}`;
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
        <span className="text-xs font-mono-tabular text-[color:var(--text-3)] tabular-nums">
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
// PackageListCard — multi-architecture package management.
// Shows all packages from the EnvironmentPackage table, grouped by type,
// with add/remove capability.
// ---------------------------------------------------------------------------
const PACKAGE_TYPES = [
  { value: 'deb', label: 'DEB (Linux)' },
  { value: 'rpm', label: 'RPM (Linux)' },
  { value: 'pkg', label: 'PKG (macOS)' },
  { value: 'msi', label: 'MSI (Windows)' },
];

const ARCH_OPTIONS = ['amd64', 'arm64', 'x86_64', 'aarch64', 'universal'];

function PackageListCard({ envName }: { envName: string }) {
  const qc = useQueryClient();
  const { data: packages, isLoading } = useQuery({
    queryKey: ['env-packages', envName],
    queryFn: () => listEnvPackages(envName),
    staleTime: 30_000,
  });

  const [newType, setNewType] = useState('deb');
  const [newArch, setNewArch] = useState('amd64');
  const [newUrl, setNewUrl] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const addMut = useMutation({
    mutationFn: () => addEnvPackage(envName, {
      type: newType,
      architecture: newArch,
      url: newUrl,
      is_default: false,
    }),
    onSuccess: () => {
      setErr(null);
      setNewUrl('');
      qc.invalidateQueries({ queryKey: ['env-packages', envName] });
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : 'Failed to add package');
    },
  });

  const byType: Record<string, EnvironmentPackage[]> = {};
  for (const p of packages ?? []) {
    if (!byType[p.type]) byType[p.type] = [];
    byType[p.type].push(p);
  }

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4 mt-3"
      aria-label="Multi-architecture packages"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
          Multi-architecture packages{' '}
          <span className="text-[color:var(--text-3)] font-normal">· per-arch URLs</span>
        </h2>
        <span
          className="text-xs text-[color:var(--text-3)] cursor-help"
          title="Register multiple packages per type, each targeting a different architecture (amd64, arm64, etc.). The TLS service serves the correct package based on the requested architecture."
        >
          ⓘ
        </span>
      </div>

      {isLoading && <Skeleton className="h-16 w-full" />}
      {!isLoading && (packages ?? []).length === 0 && (
        <p className="text-xs text-[color:var(--text-3)] italic mb-3">
          No multi-architecture packages configured.
        </p>
      )}
      {!isLoading && Object.keys(byType).length > 0 && (
        <div className="space-y-3 mb-4">
          {PACKAGE_TYPES.map(({ value, label }) => {
            const items = byType[value];
            if (!items || items.length === 0) return null;
            return (
              <div key={value}>
                <p className="text-xs font-mono-tabular text-[color:var(--text-3)] uppercase tracking-[0.1em] mb-1">
                  {label}
                </p>
                <div className="space-y-1">
                  {items.map((p) => (
                    <PackageRow
                      key={p.id}
                      pkg={p}
                      envName={envName}
                      onRemoved={() => qc.invalidateQueries({ queryKey: ['env-packages', envName] })}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <select
          value={newType}
          onChange={(e) => setNewType(e.target.value)}
          className="text-xs px-2 py-1 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
        >
          {PACKAGE_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.value}</option>
          ))}
        </select>
        <select
          value={newArch}
          onChange={(e) => setNewArch(e.target.value)}
          className="text-xs px-2 py-1 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-1)]"
        >
          {ARCH_OPTIONS.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <input
          type="url"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          placeholder="https://… or local filename"
          className={cn(
            'flex-1 min-w-[200px] px-2.5 py-1 rounded-md text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
            'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
            'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:border-transparent',
          )}
        />
        <Button
          variant="ghost"
          size="sm"
          onClick={() => addMut.mutate()}
          disabled={addMut.isPending || !newUrl}
        >
          Add
        </Button>
      </div>
      {err && (
        <p className="mt-2 text-xs text-[color:var(--danger)]">{err}</p>
      )}
    </section>
  );
}

function PackageRow({
  pkg,
  envName,
  onRemoved,
}: {
  pkg: EnvironmentPackage;
  envName: string;
  onRemoved: () => void;
}) {
  const [editUrl, setEditUrl] = useState(pkg.url);
  const [savedFlash, setSavedFlash] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Sync when server data changes (e.g. after a refetch).
  const [lastId, setLastId] = useState(pkg.id);
  if (pkg.id !== lastId) {
    setLastId(pkg.id);
    setEditUrl(pkg.url);
    setErr(null);
  }

  const dirty = editUrl !== pkg.url;

  const updateMut = useMutation({
    mutationFn: () => updateEnvPackage(envName, pkg.id, editUrl),
    onSuccess: () => {
      setErr(null);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1200);
      onRemoved();
    },
    onError: (e) => {
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const removeMut = useMutation({
    mutationFn: () => removeEnvPackage(envName, pkg.id),
    onSuccess: onRemoved,
  });

  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono-tabular text-[color:var(--text-2)] w-16 flex-shrink-0">
          {pkg.architecture || 'default'}
        </span>
        <input
          type="url"
          value={editUrl}
          onChange={(e) => setEditUrl(e.target.value)}
          className={cn(
            'flex-1 min-w-0 px-2.5 py-1 rounded-md text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
            'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
            'focus:outline-none focus:ring-2 focus:ring-[color:var(--signal)] focus:border-transparent',
          )}
        />
        {pkg.is_default && <MetadataBadge className="shrink-0">Default</MetadataBadge>}
        {dirty && <StatusBadge variant="warning" label="Pending" className="shrink-0" />}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => updateMut.mutate()}
          disabled={!dirty || updateMut.isPending}
        >
          {updateMut.isPending ? 'Saving…' : savedFlash ? 'Saved ✓' : 'Save'}
        </Button>
        <button
          type="button"
          onClick={() => removeMut.mutate()}
          disabled={removeMut.isPending}
          className="text-xs text-[color:var(--danger)] hover:underline disabled:opacity-40 flex-shrink-0"
        >
          remove
        </button>
      </div>
      {err && (
        <p className="mt-1 ml-[72px] text-xs text-[color:var(--danger)]">{err}</p>
      )}
    </div>
  );
}
