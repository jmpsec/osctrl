import { forwardRef, type LabelHTMLAttributes } from 'react';
import { cn } from '$/lib/cn';

interface LabelProps extends LabelHTMLAttributes<HTMLLabelElement> {
  required?: boolean;
}

export const Label = forwardRef<HTMLLabelElement, LabelProps>(
  ({ className, children, required, ...props }, ref) => {
    return (
      <label
        ref={ref}
        className={cn(
          'block text-xs text-[color:var(--text-2)] mb-1.5 select-none',
          className
        )}
        {...props}
      >
        {children}
        {required && (
          <span className="ml-1 text-[color:var(--text-3)] font-normal">(required)</span>
        )}
      </label>
    );
  }
);

Label.displayName = 'Label';
