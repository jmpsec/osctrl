import type { KeyboardEvent } from 'react';
import { cn } from '$/lib/cn';

export interface StatusTab<T extends string> {
  value: T;
  label: string;
}

interface StatusTabsProps<T extends string> {
  tabs: StatusTab<T>[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
}

/**
 * Segmented tab bar for status filtering (All / Active / Completed / etc.).
 * Reusable across Queries, Nodes, Carves, and any tracked-list page.
 */
export function StatusTabs<T extends string>({
  tabs,
  value,
  onChange,
  className,
}: StatusTabsProps<T>) {
  function handleKeyDown(e: KeyboardEvent<HTMLButtonElement>) {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const idx = tabs.findIndex((t) => t.value === value);
    if (idx < 0) return;
    const delta = e.key === 'ArrowRight' ? 1 : -1;
    const nextIdx = (idx + delta + tabs.length) % tabs.length;
    e.preventDefault();
    onChange(tabs[nextIdx].value);
  }

  return (
    <div
      className={cn(
        'flex items-center gap-1 rounded-md bg-[color:var(--bg-2)] p-0.5 border border-[color:var(--border)]',
        className,
      )}
      role="tablist"
      aria-label="Status filter"
    >
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          role="tab"
          aria-selected={value === tab.value}
          tabIndex={value === tab.value ? 0 : -1}
          onClick={() => onChange(tab.value)}
          onKeyDown={handleKeyDown}
          className={cn(
            'px-3 py-1 text-xs font-medium rounded transition-colors',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            value === tab.value
              ? 'bg-[color:var(--bg-1)] text-[color:var(--text-1)] shadow-sm'
              : 'text-[color:var(--text-2)] hover:text-[color:var(--text-1)]',
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
