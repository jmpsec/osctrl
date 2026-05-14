import { cn } from '$/lib/cn';

const EXP_OPTIONS = [
  { label: '1 hour', value: 1 },
  { label: '4 hours', value: 4 },
  { label: '24 hours', value: 24 },
  { label: '7 days', value: 168 },
  { label: 'No expiration', value: 0 },
] as const;

interface OptionsPanelProps {
  expHours: number;
  onExpChange: (v: number) => void;
  hidden: boolean;
  onHiddenChange: (v: boolean) => void;
}

export function OptionsPanel({ expHours, onExpChange, hidden, onHiddenChange }: OptionsPanelProps) {
  return (
    <div className="space-y-3">
      <div>
        <label
          htmlFor="exp-select"
          className="block text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-1.5"
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
                onClick={() => onExpChange(opt.value)}
                aria-pressed={active}
                className={cn(
                  'px-2 py-1 text-[11px] font-medium rounded-md border transition-colors duration-[120ms]',
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
      </div>

      <label className="flex items-start gap-2 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={hidden}
          onChange={(e) => onHiddenChange(e.target.checked)}
          className="rounded border-[color:var(--border)] accent-[color:var(--signal)] mt-0.5"
        />
        <div>
          <span className="text-xs text-[color:var(--text-1)]">Hidden query</span>
          <p className="text-[10px] text-[color:var(--text-3)] leading-snug mt-0.5">
            Visible only in the hidden-active / hidden-completed tabs.
          </p>
        </div>
      </label>
    </div>
  );
}
