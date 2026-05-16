import { useState, useEffect } from 'react';
import { cn } from '$/lib/cn';

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  debounceMs?: number;
  className?: string;
  id?: string;
}

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  debounceMs = 300,
  className,
  id = 'node-search',
}: SearchInputProps) {
  const [local, setLocal] = useState(value);

  // Sync external value changes (e.g. URL param reset) — only when the
  // prop value itself changes, not on every parent render.
  useEffect(() => {
    setLocal(value);
  }, [value]);

  // Debounce: fire onChange after debounceMs of inactivity.
  // Skip when local already matches the committed value.
  useEffect(() => {
    if (local === value) return;
    const t = setTimeout(() => onChange(local), debounceMs);
    return () => clearTimeout(t);
  }, [local, value, onChange, debounceMs]);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    setLocal(e.target.value);
  }

  function handleClear() {
    setLocal('');
    onChange('');
  }

  return (
    <div className={cn('relative flex items-center', className)}>
      <label htmlFor={id} className="sr-only">
        Search nodes
      </label>
      {/* Magnifying glass */}
      <span
        aria-hidden
        className="pointer-events-none absolute left-2.5 text-[color:var(--text-3)] w-4 h-4"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <circle cx="11" cy="11" r="8" />
          <path d="M21 21l-4.35-4.35" />
        </svg>
      </span>
      <input
        id={id}
        type="search"
        autoComplete="off"
        value={local}
        onChange={handleChange}
        placeholder={placeholder}
        className={cn(
          'w-full pl-8 pr-8 py-1.5 text-sm rounded-md',
          'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
          'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
          'focus:outline focus:outline-2 focus:outline-offset-0 focus:outline-[color:var(--signal)]',
          'transition-colors',
        )}
      />
      {/* Clear button */}
      {local && (
        <button
          type="button"
          onClick={handleClear}
          aria-label="Clear search"
          className={cn(
            'absolute right-2 text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            'rounded transition-colors',
          )}
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6L6 18M6 6l12 12" />
          </svg>
        </button>
      )}
    </div>
  );
}
