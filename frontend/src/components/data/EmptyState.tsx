import type { ReactNode } from 'react';
import { cn } from '$/lib/cn';

interface EmptyStateProps {
  /** Icon element to render above the title. */
  icon?: ReactNode;
  title: string;
  description?: string;
  /** Primary action button or link. */
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center py-16 px-6 text-center',
        className,
      )}
    >
      {icon && (
        <div className="mb-4 text-[color:var(--text-3)] w-10 h-10 flex items-center justify-center">
          {icon}
        </div>
      )}
      <p className="text-sm font-medium text-[color:var(--text-1)] mb-1">{title}</p>
      {description && (
        <p className="text-sm text-[color:var(--text-2)] mb-4 max-w-xs">{description}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
