import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getEnrollData, type EnrollTarget } from '$/api/enrollment';
import { Button } from '$/components/atoms/Button';
import { Skeleton } from '$/components/data/Skeleton';
import { cn } from '$/lib/cn';

/**
 * FlagsCard — view, copy, and per-OS download the osquery flags file.
 *
 * The flag template ships with __SECRET_FILE__ and __CERT_FILE__
 * placeholders. The four per-OS targets ({flagsLinux,flagsMac,
 * flagsWindows,flagsFreeBSD}) ask the API to substitute the canonical
 * install path for that platform — same bytes osquery expects to read
 * from /etc/osquery/osctrl-{env}.flags (or platform equivalent).
 *
 * Layout: full-width card under the 2-col block on EnrollPage, so the
 * preview gets the same horizontal room as PackageUrlCard. Tabs across
 * the top switch which substituted variant is shown + which file the
 * Download button writes.
 */

type OS = 'linux' | 'mac' | 'windows' | 'freebsd';

const TABS: { id: OS; label: string; target: EnrollTarget; filename: string }[] = [
  { id: 'linux',   label: 'Linux',   target: 'flagsLinux',   filename: 'osquery.flags' },
  { id: 'mac',     label: 'macOS',   target: 'flagsMac',     filename: 'osquery.flags' },
  { id: 'windows', label: 'Windows', target: 'flagsWindows', filename: 'osquery.flags' },
  { id: 'freebsd', label: 'FreeBSD', target: 'flagsFreeBSD', filename: 'osquery.flags' },
];

export function FlagsCard({ env }: { env: string }) {
  const qc = useQueryClient();
  const [os, setOs] = useState<OS>('linux');
  const [copied, setCopied] = useState(false);
  const [copyErr, setCopyErr] = useState<string | null>(null);

  // Warm all four queries so tab switching is instant. Each result is the
  // env's flag template with __SECRET_FILE__/__CERT_FILE__ substituted for
  // the platform's canonical install path. (Four explicit hooks rather than
  // .map(useQuery) to satisfy Rules of Hooks.)
  const linux = useQuery({
    queryKey: ['enrollment', env, 'flagsLinux'],
    queryFn: () => getEnrollData(env, 'flagsLinux'),
    staleTime: 60_000,
  });
  const mac = useQuery({
    queryKey: ['enrollment', env, 'flagsMac'],
    queryFn: () => getEnrollData(env, 'flagsMac'),
    staleTime: 60_000,
  });
  const windows = useQuery({
    queryKey: ['enrollment', env, 'flagsWindows'],
    queryFn: () => getEnrollData(env, 'flagsWindows'),
    staleTime: 60_000,
  });
  const freebsd = useQuery({
    queryKey: ['enrollment', env, 'flagsFreeBSD'],
    queryFn: () => getEnrollData(env, 'flagsFreeBSD'),
    staleTime: 60_000,
  });
  const byOs: Record<OS, typeof linux> = {
    linux,
    mac,
    windows,
    freebsd,
  };
  const active = byOs[os];
  const activeTab = TABS.find((t) => t.id === os)!;

  async function handleCopy() {
    if (!active.data?.data) return;
    try {
      await navigator.clipboard.writeText(active.data.data);
      setCopied(true);
      setCopyErr(null);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopyErr('Clipboard blocked by browser');
    }
  }

  function handleDownload() {
    if (!active.data?.data) return;
    const blob = new Blob([active.data.data], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeTab.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleRefresh() {
    // Force re-fetch — useful after the user changed env.Flags via the
    // legacy settings page or via a `flagsXxx` API call from elsewhere.
    void qc.invalidateQueries({ queryKey: ['enrollment', env, activeTab.target] });
  }

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label="osquery flags"
    >
      <div className="mb-3 flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
            osquery flags
          </h2>
          <span
            className="text-[10px] text-[color:var(--text-3)] cursor-help"
            title="The flag template with __SECRET_FILE__ / __CERT_FILE__ substituted for the canonical install path of the selected OS. Drop this at /etc/osquery/osctrl-<env>.flags (or platform equivalent)."
          >
            ⓘ
          </span>
        </div>
        <Button variant="ghost" size="sm" onClick={handleRefresh}>
          Refresh
        </Button>
      </div>

      {/* OS tabs */}
      <div role="tablist" aria-label="Target OS" className="flex items-center gap-4 mb-3">
        {TABS.map((t) => {
          const isActive = t.id === os;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setOs(t.id)}
              className={cn(
                'pb-1.5 text-xs transition-colors border-b-2',
                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                isActive
                  ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
                  : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
          flag file · {activeTab.label.toLowerCase()}
        </span>
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            disabled={!active.data?.data}
          >
            {copied ? 'Copied ✓' : 'Copy'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleDownload}
            disabled={!active.data?.data}
          >
            Download
          </Button>
        </div>
      </div>
      <pre
        className={cn(
          'text-xs font-mono-tabular',
          'bg-[color:var(--bg-2)] border border-[color:var(--border)] rounded-md',
          'p-3 overflow-auto whitespace-pre-wrap break-all',
          'text-[color:var(--text-1)] min-h-[180px] max-h-[420px]',
        )}
      >
        {active.isLoading ? (
          <Skeleton className="h-4 w-full" />
        ) : active.isError ? (
          <span className="text-[color:var(--danger)]">
            {(active.error as Error | undefined)?.message ?? 'Failed to load'}
          </span>
        ) : (
          active.data?.data
        )}
      </pre>
      {copyErr && (
        <p className="mt-1.5 text-[10px] text-[color:var(--danger)]">{copyErr}</p>
      )}
      <p className="mt-2 text-[10px] text-[color:var(--text-3)]">
        Save as <span className="font-mono-tabular text-[color:var(--text-2)]">{activeTab.filename}</span> next to the secret + cert files this environment expects.
      </p>
    </section>
  );
}
