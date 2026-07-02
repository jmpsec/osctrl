import { cn } from '$/lib/cn';

export type PipVariant = 'success' | 'warning' | 'danger' | 'info' | 'signal' | 'dim';

interface StatusPipProps {
  variant: PipVariant;
  live?: boolean;
  className?: string;
}

const variantClasses: Record<PipVariant, string> = {
  success: 'bg-[color:var(--success)] dark:shadow-[0_0_8px_rgba(74,222,128,0.5)]',
  warning: 'bg-[color:var(--warning)] dark:shadow-[0_0_8px_rgba(251,191,36,0.5)]',
  danger: 'bg-[color:var(--danger)] dark:shadow-[0_0_8px_rgba(248,113,113,0.5)]',
  info: 'bg-[color:var(--info)] dark:shadow-[0_0_8px_rgba(103,192,255,0.5)]',
  signal: 'bg-[color:var(--signal)] shadow-[0_0_10px_var(--signal-glow)]',
  dim: 'bg-[color:var(--text-3)]',
};

const variantLabels: Record<PipVariant, string> = {
  success: 'active',
  warning: 'degraded',
  danger: 'offline',
  info: 'info',
  signal: 'live',
  dim: 'inactive',
};

export function StatusPip({ variant, live = false, className }: StatusPipProps) {
  return (
    <span
      role="img"
      aria-label={variantLabels[variant]}
      className={cn(
        'inline-block w-[7px] h-[7px] rounded-full relative flex-shrink-0',
        variantClasses[variant],
        live && 'pip-live',
        className,
      )}
    >
      {live && (
        <span aria-hidden className="pip-live-ring" />
      )}
    </span>
  );
}
