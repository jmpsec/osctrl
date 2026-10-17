import { cn } from '$/lib/cn';

/** Pieces shared by the configuration and flags override views. */
export type View = 'applied' | 'environment' | 'override' | 'diff';

export const VIEWS: { id: View; label: string }[] = [
  { id: 'applied', label: 'Applied' },
  { id: 'environment', label: 'Environment' },
  { id: 'override', label: 'Node override' },
  { id: 'diff', label: 'Diff' },
];

export const warnBtn = cn(
  'px-3 py-1.5 text-xs font-medium rounded transition-colors',
  'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]',
  'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]',
  'disabled:opacity-40 disabled:cursor-not-allowed',
);
export const plainBtn =
  'px-3 py-1.5 text-xs font-medium rounded border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed';

/** ISO timestamp -> value for <input type="datetime-local"> (local time). */
export function toLocalInput(iso: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
