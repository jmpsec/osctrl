import { cn } from '$/lib/cn';
import type { SortDir } from '$/api/types';

interface SortableHeaderProps<T extends string> {
  column: T;
  label: string;
  currentSort: T | undefined;
  currentDir: SortDir | undefined;
  defaultDir?: SortDir;
  onSortChange: (column: T, dir: SortDir) => void;
  className?: string;
}

export function SortableHeader<T extends string>({
  column,
  label,
  currentSort,
  currentDir,
  defaultDir,
  onSortChange,
  className,
}: SortableHeaderProps<T>) {
  const isActive = currentSort === column;

  function handleClick() {
    if (isActive) {
      onSortChange(column, currentDir === 'asc' ? 'desc' : 'asc');
    } else {
      onSortChange(column, defaultDir ?? 'asc');
    }
  }

  return (
    <th
      scope="col"
      aria-sort={!isActive ? undefined : currentDir === 'asc' ? 'ascending' : 'descending'}
      className={cn(
        'px-4 py-3 text-left text-xs font-medium text-[color:var(--text-2)] uppercase tracking-wide',
        'whitespace-nowrap',
        className,
      )}
    >
      <button
        type="button"
        onClick={handleClick}
        aria-label={`Sort by ${label}`}
        className={cn(
          'inline-flex items-center gap-1 transition-colors',
          'hover:text-[color:var(--text-1)]',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
          'rounded',
          isActive && 'text-[color:var(--text-1)]',
        )}
      >
        {label}
        <span
          aria-hidden
          className={cn(
            'w-3 h-3 transition-transform',
            !isActive && 'text-[color:var(--text-3)] opacity-0 group-hover:opacity-50',
            isActive && 'text-[color:var(--signal)]',
          )}
        >
          {isActive && currentDir === 'asc' ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 19V5M5 12l7-7 7 7" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 5v14M19 12l-7 7-7-7" />
            </svg>
          )}
        </span>
      </button>
    </th>
  );
}
