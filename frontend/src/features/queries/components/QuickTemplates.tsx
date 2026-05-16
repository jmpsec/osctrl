import { useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listQuerySamples, type QuerySample, type QuerySampleCategory } from '$/api/samples';
import { cn } from '$/lib/cn';

const CATEGORY_LABEL: Record<QuerySampleCategory, string> = {
  recon: 'Recon',
  processes: 'Processes',
  users: 'Users',
  network: 'Network',
  persistence: 'Persistence',
  file_integrity: 'File integrity',
  packages: 'Packages',
};

const CATEGORY_ICON: Record<QuerySampleCategory, ReactNode> = {
  recon: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </svg>
  ),
  processes: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  ),
  users: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="9" cy="7" r="4" />
      <path d="M3 21v-2a4 4 0 014-4h4a4 4 0 014 4v2M17 11a4 4 0 100-8" />
    </svg>
  ),
  network: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" />
    </svg>
  ),
  persistence: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <path d="M12 2l8 4v6c0 5-4 9-8 10-4-1-8-5-8-10V6l8-4z" />
    </svg>
  ),
  file_integrity: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
      <path d="M14 2v6h6" />
    </svg>
  ),
  packages: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <path d="M20 7l-8 4-8-4 8-4 8 4zM4 7v10l8 4M20 7v10l-8 4" />
    </svg>
  ),
};

interface QuickTemplatesProps {
  /** Called with the picked sample's SQL — wire to the editor's setValue. */
  onPick: (sample: QuerySample) => void;
}

/**
 * QuickTemplates — chip rail of starter SQL samples sourced from
 * GET /api/v1/queries/samples (28 samples shipped with the binary, no auth).
 *
 * Default view: the 6 first samples across all categories.
 * "Show all" expands to a per-category grid where each row has the category
 * label + an icon + a wrapping group of chips.
 *
 * The endpoint is pre-auth and ships with the binary so this rail renders
 * fast on first paint; if the fetch fails (offline dev runs, etc.) we hide
 * the whole rail so the operator can still type SQL manually.
 */
export function QuickTemplates({ onPick }: QuickTemplatesProps) {
  const [expanded, setExpanded] = useState(false);

  const { data: samples = [], isLoading, isError } = useQuery({
    queryKey: ['query-samples'],
    queryFn: () => listQuerySamples(),
    staleTime: 60 * 60_000, // baked into the binary
    retry: 0,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
          Quick templates
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-6 w-24 rounded-full bg-[color:var(--bg-3)] animate-pulse"
            />
          ))}
        </div>
      </div>
    );
  }

  if (isError || samples.length === 0) {
    return null;
  }

  // Group by category for the expanded view.
  const byCategory = samples.reduce<Record<string, QuerySample[]>>((acc, s) => {
    (acc[s.category] ??= []).push(s);
    return acc;
  }, {});
  const categories = Object.keys(byCategory) as QuerySampleCategory[];

  // Default "top" view — first 6 samples. Stable order (the server returns
  // them in a sensible default order).
  const top = samples.slice(0, 6);

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between">
        <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
          Quick templates
        </div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-[11px] text-[color:var(--text-link)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)] rounded"
        >
          {expanded ? 'Collapse' : `Show all (${samples.length})`}
        </button>
      </div>

      {!expanded ? (
        <div className="flex flex-wrap gap-1.5">
          {top.map((s) => (
            <TemplateChip key={s.name} sample={s} onPick={onPick} />
          ))}
        </div>
      ) : (
        <div className="space-y-2.5">
          {categories.map((cat) => (
            <div key={cat} className="flex items-start gap-2.5">
              <span
                className={cn(
                  'flex-shrink-0 inline-flex items-center gap-1.5',
                  'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular uppercase tracking-[0.1em]',
                  'bg-[color:var(--bg-3)] text-[color:var(--text-2)] border border-[color:var(--border)]',
                  'w-[110px] justify-start mt-0.5',
                )}
              >
                <span className="w-3 h-3 text-[color:var(--signal)]" aria-hidden>
                  {CATEGORY_ICON[cat]}
                </span>
                {CATEGORY_LABEL[cat]}
              </span>
              <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
                {byCategory[cat].map((s) => (
                  <TemplateChip key={s.name} sample={s} onPick={onPick} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TemplateChip({ sample, onPick }: { sample: QuerySample; onPick: (s: QuerySample) => void }) {
  return (
    <button
      type="button"
      title={`${sample.description}${sample.platforms.length ? `\nPlatforms: ${sample.platforms.join(', ')}` : ''}`}
      onClick={() => onPick(sample)}
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full',
        'text-[11px] font-medium transition-colors duration-[120ms]',
        'border border-[color:var(--border)]',
        'bg-[color:var(--bg-2)] text-[color:var(--text-2)]',
        'hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)] hover:border-[color:var(--border-strong)]',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
      )}
    >
      {sample.name}
    </button>
  );
}
