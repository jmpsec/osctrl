import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '$/lib/cn';

interface MetadataBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  children: ReactNode;
}

/** Neutral categorical metadata such as a role, source, or query type. */
export function MetadataBadge({ children, className, ...props }: MetadataBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border border-[color:var(--border)] bg-[color:var(--bg-2)]',
        'px-1.5 py-0.5 text-xs font-medium leading-4 text-[color:var(--text-2)] normal-case tracking-normal',
        className,
      )}
      {...props}
    >
      {children}
    </span>
  );
}
