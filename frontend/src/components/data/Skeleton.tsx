import { cn } from '$/lib/cn';

interface SkeletonProps {
  className?: string;
  'aria-hidden'?: boolean;
}

export function Skeleton({ className, 'aria-hidden': ariaHidden = true }: SkeletonProps) {
  return (
    <div
      aria-hidden={ariaHidden}
      className={cn(
        'animate-pulse rounded bg-[color:var(--bg-3)]',
        className,
      )}
    />
  );
}

/** A full skeleton table row with N cells. */
export function SkeletonRow({ cells = 7 }: { cells?: number }) {
  return (
    <tr aria-hidden>
      {Array.from({ length: cells }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <Skeleton className="h-4 w-full max-w-[120px]" />
        </td>
      ))}
    </tr>
  );
}
