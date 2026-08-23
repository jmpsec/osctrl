import { X } from 'lucide-react';
import { cn } from '$/lib/cn';

interface SelectionChipProps {
  label: string;
  onRemove: () => void;
  title?: string;
  className?: string;
  mono?: boolean;
  removeLabel?: string;
}

/** A committed, removable value such as a selected node or hostname. */
export function SelectionChip({ label, onRemove, title, className, mono = false, removeLabel }: SelectionChipProps) {
  return (
    <span
      title={title ?? label}
      className={cn(
        'inline-flex min-w-0 max-w-[160px] items-center gap-1 rounded border border-[color:var(--signal)]/30',
        'bg-[color:var(--accent-soft)] px-1.5 py-0.5 text-xs font-medium leading-4 text-[color:var(--text-link)]',
        mono && 'font-mono-tabular',
        className,
      )}
    >
      <span className="truncate">{label}</span>
      <button
        type="button"
        onClick={onRemove}
        className="-mr-0.5 flex size-4 shrink-0 items-center justify-center rounded-sm text-[color:var(--text-link)]/70 hover:bg-[color:var(--signal)]/10 hover:text-[color:var(--text-link)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]"
        aria-label={`Remove ${removeLabel ?? label}`}
      >
        <X size={11} strokeWidth={2} aria-hidden />
      </button>
    </span>
  );
}
