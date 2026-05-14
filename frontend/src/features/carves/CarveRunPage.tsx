import { useState, useMemo } from 'react';
import { useParams, useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { runCarve } from '$/api/carves';
import { AuthError } from '$/api/client';
import { listCarveSamples, type CarveSample } from '$/api/samples';
import { TargetSelector } from '$/components/forms/TargetSelector';
import type { TargetSelection } from '$/components/forms/TargetSelector';
import { StickyFooter } from '$/features/queries/components/StickyFooter';
import { cn } from '$/lib/cn';

const PLATFORM_LABELS: Record<CarveSample['platform'], string> = {
  linux: 'Linux',
  darwin: 'macOS',
  windows: 'Windows',
};

const PLATFORM_COLOR: Record<CarveSample['platform'], string> = {
  linux: 'var(--plat-linux, var(--warning))',
  darwin: 'var(--plat-mac, var(--info))',
  windows: 'var(--plat-windows, var(--info))',
};

const EXP_OPTIONS = [
  { label: '1 hour', value: 1 },
  { label: '4 hours', value: 4 },
  { label: '24 hours', value: 24 },
  { label: '7 days', value: 168 },
  { label: 'No expiration', value: 0 },
] as const;

const EMPTY_TARGET: TargetSelection = {
  uuids: [],
  platforms: [],
  tags: [],
  hosts: [],
};

/**
 * Returns a lightweight string-shape validation result for a forensic file
 * path. Carves require absolute paths; we surface obvious mistakes (relative,
 * empty, whitespace-only) before the operator hits "Start carve".
 *
 * macOS & Linux: must start with `/`.
 * Windows:        must start with a drive letter `X:\` OR `\\` (UNC).
 */
type PathValidation = { kind: 'ok' } | { kind: 'warn' | 'err'; msg: string };

function validatePath(p: string): PathValidation {
  const t = p.trim();
  if (!t) return { kind: 'err', msg: 'Path is required.' };
  // Windows
  if (/^[a-zA-Z]:[\\/]/.test(t) || t.startsWith('\\\\')) return { kind: 'ok' };
  // POSIX absolute
  if (t.startsWith('/')) return { kind: 'ok' };
  return {
    kind: 'warn',
    msg: 'Looks like a relative path — osquery needs an absolute path (e.g. /etc/hosts or C:\\Windows\\…).',
  };
}

export function CarveRunPage() {
  const { env } = useParams({ from: '/_app/env/$env/carves/new' });
  const navigate = useNavigate({ from: '/_app/env/$env/carves/new' });

  const [path, setPath] = useState('');
  const [target, setTarget] = useState<TargetSelection>(EMPTY_TARGET);
  const [expHours, setExpHours] = useState<number>(24);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Carve sample paths shipped with the binary. Pre-auth endpoint; if it fails
  // we just hide the sample row — the path input still works manually.
  const { data: samples = [] } = useQuery({
    queryKey: ['carve-samples'],
    queryFn: () => listCarveSamples(),
    staleTime: 60 * 60_000,
    retry: 0,
  });

  const samplesByPlatform = useMemo(
    () =>
      samples.reduce<Record<CarveSample['platform'], CarveSample[]>>(
        (acc, s) => {
          (acc[s.platform] ??= []).push(s);
          return acc;
        },
        { linux: [], darwin: [], windows: [] },
      ),
    [samples],
  );

  const pathValidation = validatePath(path);

  async function handleSubmit() {
    const trimmedPath = path.trim();
    if (!trimmedPath) {
      setSubmitError('File path is required.');
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const result = await runCarve(env, {
        path: trimmedPath,
        uuid_list: target.uuids.length > 0 ? target.uuids : undefined,
        platform_list: target.platforms.length > 0 ? target.platforms : undefined,
        host_list: target.hosts.length > 0 ? target.hosts : undefined,
        tag_list: target.tags.length > 0 ? target.tags : undefined,
        exp_hours: expHours,
      });
      void navigate({
        to: '/_app/env/$env/carves/$name',
        params: { env, name: result.query_name },
      });
    } catch (err) {
      if (err instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setSubmitError(err instanceof Error ? err.message : 'Failed to start carve');
      setIsSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Page header ───────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)]">
        <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
          carves · new
        </div>
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
          Start file carve
        </h1>
        <p className="text-xs text-[color:var(--text-2)] mt-0.5">
          Carves a file from selected nodes; the resulting archive will be downloadable from the
          carve detail page once any node completes.
        </p>
      </div>

      {/* ── Scroll container ──────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div className="px-6 py-6 space-y-5 max-w-3xl mx-auto">

          {/* ── Path Hero Strip ──────────────────────────────────────── */}
          <section
            className={cn(
              'rounded-xl border bg-[color:var(--bg-1)] px-5 py-4',
              pathValidation.kind === 'err' && path
                ? 'border-[color:var(--danger)]/40'
                : pathValidation.kind === 'warn'
                  ? 'border-[color:var(--warning)]/40'
                  : 'border-[color:var(--border)]',
            )}
            aria-label="File path"
          >
            <div className="flex items-center gap-2 mb-2">
              <svg
                aria-hidden
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                className="w-4 h-4 text-[color:var(--signal)]"
              >
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                <path d="M14 2v6h6" />
              </svg>
              <label
                htmlFor="carve-path"
                className="text-[12px] font-medium text-[color:var(--text-1)]"
              >
                File path to carve
              </label>
            </div>

            <input
              id="carve-path"
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/etc/hosts  ·  C:\Windows\System32\config\SAM  ·  ~/Library/Keychains/login.keychain-db"
              className={cn(
                'w-full px-3 py-2.5 text-sm rounded-lg border',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                pathValidation.kind === 'err' && path
                  ? 'border-[color:var(--danger)]/50'
                  : pathValidation.kind === 'warn'
                    ? 'border-[color:var(--warning)]/50'
                    : 'border-[color:var(--border)]',
              )}
            />

            <div className="mt-2 flex items-center justify-between gap-2 text-[10.5px]">
              <span className="text-[color:var(--text-3)]">
                Absolute path on the target host(s). osquery must have read access.
              </span>
              {path && pathValidation.kind !== 'ok' && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
                    pathValidation.kind === 'err'
                      ? 'text-[color:var(--danger)] bg-[color:var(--danger)]/10 border border-[color:var(--danger)]/30'
                      : 'text-[color:var(--warning)] bg-[color:var(--warning)]/10 border border-[color:var(--warning)]/30',
                  )}
                >
                  <span aria-hidden className="w-1.5 h-1.5 rounded-full bg-current" />
                  {pathValidation.msg}
                </span>
              )}
              {path && pathValidation.kind === 'ok' && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
                    'text-[color:var(--success)] bg-[color:var(--success)]/10 border border-[color:var(--success)]/30',
                  )}
                >
                  <span aria-hidden className="w-1.5 h-1.5 rounded-full bg-current" />
                  absolute path
                </span>
              )}
            </div>
          </section>

          {/* ── Sample paths (platform-grouped) ──────────────────────── */}
          {samples.length > 0 && (
            <section
              className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] px-5 py-4"
              aria-label="Sample forensic paths"
            >
              <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-2.5">
                Sample paths
              </div>
              <div className="space-y-2">
                {(['linux', 'darwin', 'windows'] as const).map((plat) => {
                  const rows = samplesByPlatform[plat];
                  if (!rows || rows.length === 0) return null;
                  return (
                    <div key={plat} className="flex items-start gap-2">
                      <span
                        className={cn(
                          'flex-shrink-0 inline-flex items-center gap-1.5',
                          'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular uppercase tracking-[0.1em]',
                          'bg-[color:var(--bg-3)] text-[color:var(--text-2)]',
                          'border border-[color:var(--border)]',
                          'w-[80px] justify-start mt-0.5',
                        )}
                      >
                        <span
                          aria-hidden
                          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                          style={{ background: PLATFORM_COLOR[plat] }}
                        />
                        {PLATFORM_LABELS[plat]}
                      </span>
                      <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
                        {rows.map((s) => {
                          const active = path === s.path;
                          return (
                            <button
                              key={`${s.platform}:${s.path}`}
                              type="button"
                              title={s.notes}
                              onClick={() => setPath(s.path)}
                              aria-pressed={active}
                              className={cn(
                                'px-2 py-0.5 rounded text-[11px] font-mono-tabular',
                                'border transition-colors duration-[120ms]',
                                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                                active
                                  ? 'bg-[color:var(--signal)]/15 text-[color:var(--signal-bright,var(--signal))] border-[color:var(--signal)]/40'
                                  : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)] hover:border-[color:var(--border-strong)]',
                              )}
                            >
                              {s.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* ── Targeting ─────────────────────────────────────────────── */}
          <section
            className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] px-5 py-4"
            aria-label="Target nodes"
          >
            <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)] mb-3">
              Target nodes
            </h2>
            <TargetSelector value={target} onChange={setTarget} env={env} />
          </section>

          {/* ── Expiration ────────────────────────────────────────────── */}
          <section
            className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] px-5 py-4"
            aria-label="Expiration"
          >
            <label
              htmlFor="carve-exp"
              className="block text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-2"
            >
              Expiration
            </label>
            <div className="flex flex-wrap gap-1">
              {EXP_OPTIONS.map((opt) => {
                const active = expHours === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setExpHours(opt.value)}
                    aria-pressed={active}
                    className={cn(
                      'px-2.5 py-1 text-[11px] font-medium rounded-md border transition-colors duration-[120ms]',
                      'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                      active
                        ? 'bg-[color:var(--signal)]/12 text-[color:var(--signal-bright,var(--signal))] border-[color:var(--signal)]/40'
                        : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
                    )}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </section>

        </div>
      </div>

      <StickyFooter
        submitting={isSubmitting}
        disabled={isSubmitting || pathValidation.kind === 'err'}
        message={submitError ? { tone: 'error', text: submitError } : null}
        onSubmit={() => void handleSubmit()}
        onCancel={() => void navigate({ to: '/_app/env/$env/carves', params: { env } })}
        submitLabel="Start carve"
      />
    </div>
  );
}

export default CarveRunPage;
