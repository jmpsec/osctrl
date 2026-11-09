export const TH = 'px-3 py-2 text-start text-xs font-medium uppercase tracking-wide text-[color:var(--text-3)]';
export const TD = 'px-3 py-2 align-top text-[color:var(--text-2)]';
export const TABLE = 'w-full border-collapse text-sm';
export const ROW = 'border-b border-[color:var(--border)] last:border-0';
export const MONO = 'font-mono [overflow-wrap:anywhere]';

export function errorText(err: unknown): string | undefined {
  return err instanceof Error ? err.message : undefined;
}
