import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '$/lib/cn';

export type ButtonVariant = 'primary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary: [
    'bg-gradient-to-b from-[color:var(--signal-bright)] to-[color:var(--signal)]',
    'text-[#051010]',
    'font-semibold',
    'border border-[color:var(--signal)]/60',
    'shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_1px_14px_-2px_var(--signal-glow)]',
    'hover:brightness-110',
    '[data-theme=light]:text-white',
  ].join(' '),
  ghost: [
    'bg-[color:var(--bg-2)]',
    'text-[color:var(--text-1)]',
    'border border-[color:var(--border)]',
    'hover:bg-[color:var(--bg-3)] hover:border-[color:var(--border-strong)]',
  ].join(' '),
  danger: [
    'bg-[color:var(--danger)]/10',
    'text-[color:var(--danger)]',
    'border border-[color:var(--danger)]/30',
    'hover:bg-[color:var(--danger)]/15',
  ].join(' '),
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-2.5 py-1 text-xs rounded-md',
  md: 'px-3.5 py-2 text-sm rounded-lg',
  lg: 'px-5 py-2.5 text-base rounded-lg',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', className, disabled, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-medium',
          'transition-all duration-[120ms] ease-out',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--signal)]',
          'disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none',
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        {...props}
      >
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
