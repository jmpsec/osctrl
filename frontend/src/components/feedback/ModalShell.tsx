import { useEffect, useRef } from 'react';
import { cn } from '$/lib/cn';

// ---------------------------------------------------------------------------
// Modal shell — lightweight, accessibility-focused dialog primitive.
//
//   - role="dialog" + aria-modal + aria-labelledby={titleId}
//   - Escape closes; click on the backdrop closes
//   - First form control (input/select/textarea) is focused on open. The
//     header close button is intentionally skipped so users land on the
//     primary interaction; if no form control exists, the close button
//     (first focusable) gets focus instead.
//   - Tab cycles within the dialog (wraps both ways).
//   - When the modal unmounts, focus returns to whatever was active when
//     it opened (focus restoration).
//
// Modals that have multiple dialogs in the same tree must pass distinct
// titleId values; the value becomes the <h2 id> for the title element and
// is referenced by aria-labelledby.
// ---------------------------------------------------------------------------
const FOCUSABLE_SELECTOR =
  'input:not([disabled]):not([type="hidden"]), select:not([disabled]), ' +
  'textarea:not([disabled]), button:not([disabled]), ' +
  'a[href], [tabindex]:not([tabindex="-1"])';

export interface ModalShellProps {
  title: string;
  /** Unique id used as the <h2 id> and the dialog's aria-labelledby target. */
  titleId: string;
  onClose: () => void;
  children: React.ReactNode;
  /** Optional tailwind class for the inner panel — defaults to max-w-2xl. */
  panelClassName?: string;
}

export function ModalShell({
  title,
  titleId,
  onClose,
  children,
  panelClassName,
}: ModalShellProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;

    function focusable(): HTMLElement[] {
      if (!ref.current) return [];
      return Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
    }

    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
        return;
      }
      if (e.key === 'Tab') {
        const all = focusable();
        if (all.length === 0) {
          e.preventDefault();
          return;
        }
        const first = all[0];
        const last = all[all.length - 1];
        const active = document.activeElement as HTMLElement | null;
        if (e.shiftKey) {
          if (active === first || !ref.current?.contains(active)) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (active === last || !ref.current?.contains(active)) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    }

    document.addEventListener('keydown', onKey);

    const all = focusable();
    const firstField = all.find((el) => {
      const tag = el.tagName.toLowerCase();
      return tag === 'input' || tag === 'select' || tag === 'textarea';
    });
    (firstField ?? all[0])?.focus();

    return () => {
      document.removeEventListener('keydown', onKey);
      previouslyFocused?.focus?.();
    };
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
    >
      <div
        aria-hidden
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
      />
      <div
        ref={ref}
        className={cn(
          'relative w-full rounded-xl border border-[color:var(--border-strong)]',
          'bg-[color:var(--bg-1)] shadow-[0_24px_64px_rgba(0,0,0,0.45)]',
          panelClassName ?? 'max-w-2xl',
        )}
      >
        <div className="flex items-center justify-between px-5 py-3 border-b border-[color:var(--border)]">
          <h2
            id={titleId}
            className="font-display text-sm font-semibold text-[color:var(--text-1)]"
          >
            {title}
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="p-1 text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] rounded transition-colors"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export default ModalShell;
