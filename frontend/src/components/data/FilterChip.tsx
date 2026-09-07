import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { useLocale } from '$/i18n/useLocale';
import { cn } from '$/lib/cn';

interface FilterChipProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  label: ReactNode;
  icon?: ReactNode;
  selected?: boolean;
  markerColor?: string;
  count?: number;
}

/** Interactive filter or selection token. Never use for passive state. */
export function FilterChip({
  label,
  icon,
  selected = false,
  markerColor,
  count,
  className,
  'aria-label': ariaLabel,
  ...props
}: FilterChipProps) {
  const { formatNumber } = useLocale();
  const accessibleLabel =
    ariaLabel ?? (typeof label === 'string' ? `${label}${count != null ? ` ${formatNumber(count)}` : ''}` : undefined);

  return (
    <button
      type="button"
      aria-pressed={selected}
      aria-label={accessibleLabel}
      className={cn(
        'inline-flex min-h-7 items-center gap-1.5 rounded border px-2 py-1 text-xs font-medium leading-4',
        'transition-colors duration-[120ms] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        selected
          ? 'border-[color:var(--signal)]/35 bg-[color:var(--accent-soft)] text-[color:var(--text-link)]'
          : 'border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-2)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--text-1)]',
        className,
      )}
      {...props}
    >
      {icon && (
        <span aria-hidden className="inline-flex shrink-0 items-center justify-center">
          {icon}
        </span>
      )}
      {!icon && markerColor && (
        <span aria-hidden className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: markerColor }} />
      )}
      <span>{label}</span>
      {count != null && (
        <span className={cn('tabular-nums', selected ? 'text-[color:var(--text-link)]/75' : 'text-[color:var(--text-3)]')}>
          {formatNumber(count)}
        </span>
      )}
    </button>
  );
}
