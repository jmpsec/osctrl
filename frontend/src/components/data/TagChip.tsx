import { Tag, X, type LucideIcon } from 'lucide-react';
import { cn } from '$/lib/cn';

interface TagChipProps {
  label: string;
  color?: string;
  Icon?: LucideIcon | null;
  title?: string;
  className?: string;
  onRemove?: () => void;
}

/**
 * User-defined metadata. Tag names preserve their authored casing and use a
 * neutral surface; color identifies the tag without making it look like state.
 */
export function TagChip({
  label,
  color = 'var(--text-3)',
  Icon = Tag,
  title,
  className,
  onRemove,
}: TagChipProps) {
  return (
    <span
      title={title ?? label}
      className={cn(
        'inline-flex min-w-0 max-w-[140px] items-center gap-1.5 rounded border border-[color:var(--border)]',
        'bg-[color:var(--bg-2)] px-1.5 py-0.5 text-xs font-medium leading-4 text-[color:var(--text-2)]',
        className,
      )}
    >
      {Icon && <Icon size={12} strokeWidth={1.8} aria-hidden className="shrink-0" style={{ color }} />}
      <span className="truncate">{label}</span>
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          className="-mr-0.5 flex size-4 shrink-0 items-center justify-center rounded-sm text-[color:var(--text-3)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]"
          aria-label={`Remove tag ${label}`}
        >
          <X size={11} strokeWidth={2} aria-hidden />
        </button>
      )}
    </span>
  );
}
