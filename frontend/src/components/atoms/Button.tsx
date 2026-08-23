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
    'bg-[color:var(--accent)] hover:bg-[color:var(--accent-hover)]',
    'text-[color:var(--accent-contrast)]',
    'font-semibold',
    'border border-[color:var(--accent)]',
  ].join(' '),
  ghost: [
    'bg-[color:var(--bg-1)]',
    'text-[color:var(--text-2)]',
    'border border-[color:var(--border)]',
    'hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)] hover:border-[color:var(--border-strong)]',
  ].join(' '),
  danger: [
    'bg-[color:var(--danger)]/10',
    'text-[color:var(--danger)]',
    'border border-[color:var(--danger)]/30',
    'hover:bg-[color:var(--danger)]/15',
  ].join(' '),
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'h-6 px-2 text-xs rounded-md',
  md: 'h-8 px-3 text-sm rounded-md',
  lg: 'h-10 px-4 text-sm rounded-lg',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', className, disabled, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-medium',
          'transition-[background-color,border-color,color] duration-[100ms] ease-out',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--accent-soft)] focus-visible:border-[color:var(--accent)]',
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
