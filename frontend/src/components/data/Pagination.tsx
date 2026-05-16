import { cn } from '$/lib/cn';

interface PaginationProps {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  className?: string;
}

export function Pagination({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  className,
}: PaginationProps) {
  const start = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);

  return (
    <div
      className={cn(
        'flex items-center justify-between gap-4 px-4 py-3',
        'border-t border-[color:var(--border)] text-sm',
        className,
      )}
    >
      <span className="text-[color:var(--text-2)] tnum text-xs">
        {totalItems === 0 ? 'No results' : `${start}–${end} of ${totalItems.toLocaleString()}`}
      </span>

      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          aria-label="Previous page"
          className={cn(
            'px-3 py-1.5 rounded text-xs font-medium transition-colors',
            'border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-[color:var(--bg-1)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          Prev
        </button>

        <span className="px-3 py-1.5 text-xs text-[color:var(--text-2)] tnum select-none">
          {page} / {totalPages || 1}
        </span>

        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          aria-label="Next page"
          className={cn(
            'px-3 py-1.5 rounded text-xs font-medium transition-colors',
            'border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-[color:var(--bg-1)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          Next
        </button>
      </div>
    </div>
  );
}
