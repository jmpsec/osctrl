import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from '$/lib/cn';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  error?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, error, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn(
          'w-full bg-[color:var(--bg-2)] border rounded-lg',
          'px-3 py-2 text-sm text-[color:var(--text-1)]',
          'placeholder:text-[color:var(--text-3)]',
          'outline-none transition-[border-color,box-shadow] duration-[120ms] ease-out',
          error
            ? 'border-[color:var(--danger)] focus:border-[color:var(--danger)] focus:shadow-[0_0_0_2px_rgba(248,113,113,0.2)]'
            : 'border-[color:var(--border)] focus:border-[color:var(--signal)] focus:shadow-[0_0_0_2px_var(--signal-glow)]',
          'disabled:opacity-40 disabled:cursor-not-allowed',
          className
        )}
        {...props}
      />
    );
  }
);

Input.displayName = 'Input';
