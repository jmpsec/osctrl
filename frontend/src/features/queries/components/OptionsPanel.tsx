import { useTranslation } from 'react-i18next';
import { cn } from '$/lib/cn';

import type { TFunction } from 'i18next';

function expOptions(t: TFunction): { label: string; value: number }[] {
  return [
    { label: t('commonExt.hour'), value: 1 },
    { label: t('commonExt.hours4'), value: 4 },
    { label: t('commonExt.hours24'), value: 24 },
    { label: t('commonExt.days7'), value: 168 },
    { label: t('commonExt.noExpiration'), value: 0 },
  ];
}

interface OptionsPanelProps {
  expHours: number;
  onExpChange: (v: number) => void;
  hidden: boolean;
  onHiddenChange: (v: boolean) => void;
}

export function OptionsPanel({ expHours, onExpChange, hidden, onHiddenChange }: OptionsPanelProps) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3">
      <div>
        <label
          htmlFor="exp-select"
          className="block text-xs font-medium uppercase tracking-[0.12em] text-[color:var(--text-3)] mb-1.5"
        >
          {t('commonExt.expiration')}
        </label>
        <div className="flex flex-wrap gap-1">
          {expOptions(t).map((opt) => {
            const active = expHours === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => onExpChange(opt.value)}
                aria-pressed={active}
                className={cn(
                  'px-2 py-1 text-xs font-medium rounded-md border transition-colors duration-[120ms]',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  active
                    ? 'bg-[color:var(--signal)]/12 text-[color:var(--signal-bright,var(--signal))] border-[color:var(--signal)]/40'
                    : 'bg-[color:var(--bg-3)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
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
          <span className="text-xs text-[color:var(--text-1)]">{t('queriesPage.hidden')}</span>
          <p className="text-xs text-[color:var(--text-3)] leading-snug mt-0.5">
            {t('noCode.hiddenHint')}
          </p>
        </div>
      </label>
    </div>
  );
}
