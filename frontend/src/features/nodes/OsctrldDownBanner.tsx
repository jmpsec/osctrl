import type { NodeFlags } from '$/api/types';

const fmt = (iso: string | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
};

const FLAGS_STAGE: Record<string, string> = {
  environment: "osctrld rolled back to the environment's flags",
  last_known_good: 'osctrld rolled back to the last known good flags',
  exhausted: 'no fallback kept osquery running',
};
const EXTENSIONS_STAGE: Record<string, string> = {
  restored: 'osctrld restored the previous extensions',
  exhausted: 'no fallback kept osquery running',
};

/** Shown on every node tab while osctrld reports osquery down. All reported values are untrusted: plain text only. */
export function OsctrldDownBanner({ osctrld }: { osctrld: NodeFlags['osctrld'] | undefined }) {
  if (osctrld?.osquery_running !== false) return null;
  const text = [
    `osquery is down${osctrld.down_since ? ` since ${fmt(osctrld.down_since)}` : ''} (reported by osctrld ${fmt(osctrld.reported_at)}).`,
    osctrld.flags_stage ? `${FLAGS_STAGE[osctrld.flags_stage] ?? osctrld.flags_stage}.` : '',
    osctrld.extensions_stage ? `${EXTENSIONS_STAGE[osctrld.extensions_stage] ?? osctrld.extensions_stage}.` : '',
    osctrld.apply_error ? `Apply error: ${osctrld.apply_error}` : '',
    osctrld.report_stale ? `Last report ${fmt(osctrld.reported_at)}, it may be stale.` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <div
      role="alert"
      data-testid="osquery-down-banner"
      className="mb-4 rounded-md border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 px-3 py-2 text-sm text-[color:var(--text-1)] break-all"
    >
      {text}
    </div>
  );
}
