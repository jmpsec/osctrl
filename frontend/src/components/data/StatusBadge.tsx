import type { LucideIcon } from 'lucide-react';
import { cn } from '$/lib/cn';
import { StatusPip, type PipVariant } from './StatusPip';

interface StatusBadgeProps {
  variant: PipVariant;
  label: string;
  Icon?: LucideIcon;
  live?: boolean;
  className?: string;
}

const variantTextClasses: Record<PipVariant, string> = {
  success: 'text-[color:var(--success)]',
  warning: 'text-[color:var(--warning)]',
  danger: 'text-[color:var(--danger)]',
  info: 'text-[color:var(--info)]',
  signal: 'text-[color:var(--signal)]',
  dim: 'text-[color:var(--text-3)]',
};

export function StatusBadge({ variant, label, Icon, live, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-xs font-medium',
        variantTextClasses[variant],
        className,
      )}
    >
      {Icon ? (
        <Icon className="w-3.5 h-3.5 flex-shrink-0" aria-hidden />
      ) : (
        <StatusPip variant={variant} live={live} />
      )}
      <span>{label}</span>
    </span>
  );
}
