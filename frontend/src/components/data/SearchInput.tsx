import { useState, useEffect } from 'react';
import { Search, X } from 'lucide-react';
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
      <span
        aria-hidden
        className="pointer-events-none absolute left-2.5 text-[color:var(--text-3)] w-4 h-4"
      >
        <Search size={16} strokeWidth={1.8} />
      </span>
      <input
        id={id}
        type="search"
        autoComplete="off"
        value={local}
        onChange={handleChange}
        placeholder={placeholder}
        className={cn(
          'w-full h-8 pl-8 pr-8 text-sm rounded-md',
          'bg-[color:var(--bg-1)] border border-[color:var(--border-strong)]',
          'text-[color:var(--text-1)] placeholder:text-[color:var(--text-3)]',
          'outline-none focus:border-[color:var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)]',
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
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
            'rounded transition-colors',
          )}
        >
          <X size={14} strokeWidth={2} />
        </button>
      )}
    </div>
  );
}
