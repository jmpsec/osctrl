import { cn } from '$/lib/cn';
import { Button } from '$/components/atoms/Button';

interface StickyFooterProps {
  /** Disable the submit button (submitting in-flight or validation fail). */
  disabled?: boolean;
  /** Show the saving / submitting label. */
  submitting?: boolean;
  /** Optional inline error/status message above the buttons. */
  message?: { tone: 'error' | 'ok'; text: string } | null;
  /** Right-side primary action. */
  onSubmit: () => void;
  /** Left-side ghost action. */
  onCancel: () => void;
  /** Optional middle "Save as" affordance — caller renders the inline form. */
  middle?: React.ReactNode;
  submitLabel?: string;
}

/**
 * StickyFooter — flush to the bottom of the page viewport (or scroll
 * container), backed by a glass / blurred surface so SQL keeps reading
 * uninterrupted as the operator scrolls.
 */
export function StickyFooter({
  disabled,
  submitting,
  message,
  onSubmit,
  onCancel,
  middle,
  submitLabel = 'Run query',
}: StickyFooterProps) {
  return (
    <div
      className={cn(
        'sticky bottom-0 left-0 right-0 z-20',
        'border-t border-[color:var(--border)]',
        'bg-[color:var(--bg-0)]/85 backdrop-blur-[10px]',
        'px-6 py-3',
      )}
    >
      {message && (
        <div
          role={message.tone === 'error' ? 'alert' : 'status'}
          className={cn(
            'mb-2.5 text-xs px-3 py-2 rounded-md inline-block',
            message.tone === 'error'
              ? 'text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)]'
              : 'text-[color:var(--success)] bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)]',
          )}
        >
          {message.text}
        </div>
      )}
      <div className="flex items-center gap-3 flex-wrap">
        {middle && <div className="flex-1 min-w-0">{middle}</div>}
        <div className={cn('flex items-center gap-2', !middle && 'ml-auto')}>
          <Button type="button" variant="ghost" size="md" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="md"
            onClick={onSubmit}
            disabled={disabled}
          >
            {submitting ? 'Submitting…' : submitLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
