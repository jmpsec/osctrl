import type { LucideIcon } from 'lucide-react';
import { cn } from '$/lib/cn';
import { StatusPip, type PipVariant } from './StatusPip';

interface StatusBadgeProps {
  variant: PipVariant;
  label: string;
  Icon?: LucideIcon;
  live?: boolean;
  title?: string;
  ariaLabel?: string;
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

export function StatusBadge({ variant, label, Icon, live, title, ariaLabel, className }: StatusBadgeProps) {
  return (
    <span
      title={title}
      aria-label={ariaLabel}
      className={cn(
        'inline-flex items-center gap-1.5 text-xs font-medium leading-4 normal-case tracking-normal',
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
