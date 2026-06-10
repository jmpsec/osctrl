import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getEnvironmentAssembledConfig } from '$/api/environments';
import { Button } from '$/components/atoms/Button';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { cn } from '$/lib/cn';

/**
 * AssembledConfigCard — read-only Monaco viewer for the env's assembled
 * osquery configuration JSON.
 *
 * Wraps GET /api/v1/environments/{env}/configuration/assembled, which
 * re-runs RefreshConfiguration server-side before reading. The result is
 * the exact JSON the TLS endpoint serves to agents — so this card is
 * the canonical preview of what each node will actually receive on its
 * next config refresh, including any unsaved edits that have already
 * landed via the parts endpoints.
 *
 * The body is read-only (configuration is composed from parts, not
 * written directly) — Copy / Download are the two affordances.
 */
export function AssembledConfigCard({ env }: { env: string }) {
  const qc = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [copyErr, setCopyErr] = useState<string | null>(null);

  const cfgQuery = useQuery({
    queryKey: ['env', env, 'assembled-config'],
    queryFn: () => getEnvironmentAssembledConfig(env),
    staleTime: 30_000,
  });

  async function handleCopy() {
    if (!cfgQuery.data?.data) return;
    try {
      await navigator.clipboard.writeText(cfgQuery.data.data);
      setCopied(true);
      setCopyErr(null);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopyErr('Clipboard blocked by browser');
    }
  }

  function handleDownload() {
    if (!cfgQuery.data?.data) return;
    const blob = new Blob([cfgQuery.data.data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osctrl-${env}-config.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleRefresh() {
    void qc.invalidateQueries({ queryKey: ['env', env, 'assembled-config'] });
  }

  // Sum the byte length so operators eyeball how heavy the config is
  // before downloading. Useful when a packs section gets out of hand.
  const sizeKb = cfgQuery.data?.data ? (cfgQuery.data.data.length / 1024).toFixed(1) : null;

  return (
    <section
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
      aria-label="Assembled osquery configuration"
    >
      <div className="mb-3 flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)]">
            Assembled configuration
          </h2>
          <span
            className="text-[10px] text-[color:var(--text-3)] cursor-help"
            title="The env's options + schedule + packs + decorators + ATC composed into the canonical osquery configuration JSON. Same bytes the TLS endpoint serves to agents on /config refresh — useful for previewing fleet-wide changes before they propagate."
          >
            ⓘ
          </span>
          {sizeKb && (
            <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)]">
              {sizeKb} KB
            </span>
          )}
        </div>
        <Button variant="ghost" size="sm" onClick={handleRefresh}>
          Refresh
        </Button>
      </div>

      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
          read-only · agents pull this
        </span>
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            disabled={!cfgQuery.data?.data}
          >
            {copied ? 'Copied ✓' : 'Copy'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleDownload}
            disabled={!cfgQuery.data?.data}
          >
            Download
          </Button>
        </div>
      </div>

      {cfgQuery.isError ? (
        <div
          className={cn(
            'rounded-md border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10',
            'px-3 py-2 text-xs text-[color:var(--danger)]',
          )}
        >
          {(cfgQuery.error as Error | undefined)?.message ?? 'Failed to load configuration'}
        </div>
      ) : (
        <CodeEditor
          value={cfgQuery.data?.data ?? ''}
          language="json"
          height="360px"
          readOnly
          aria-label={`Assembled osquery configuration for environment ${env}`}
        />
      )}

      {copyErr && (
        <p className="mt-1.5 text-[10px] text-[color:var(--danger)]">{copyErr}</p>
      )}
    </section>
  );
}
