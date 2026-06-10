import { cn } from '$/lib/cn';
import { ThemeToggle } from './ThemeToggle';
import { UserMenu } from './UserMenu';

interface BreadcrumbSegment {
  label: string;
  href?: string;
}

interface TopBarProps {
  breadcrumbs?: BreadcrumbSegment[];
  username?: string;
  onCommandPalette?: () => void;
  onMenuToggle?: () => void;
}

export function TopBar({
  breadcrumbs = [{ label: 'Command Center' }],
  username,
  onCommandPalette,
  onMenuToggle,
}: TopBarProps) {
  return (
    <header
      className={cn(
        'topbar-glass',
        'h-14 flex items-center gap-3 px-4 md:px-6',
        'border-b border-[color:var(--border)]',
        'sticky top-0 z-30',
      )}
    >
      {/* Hamburger — phones only; the rail is always visible at md+. */}
      {onMenuToggle && (
        <button
          type="button"
          onClick={onMenuToggle}
          aria-label="Open navigation menu"
          className={cn(
            'md:hidden -ml-1 p-1.5 rounded-md',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'transition-colors duration-[120ms]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
            <path d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      )}

      {/* Breadcrumbs */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-[13px] min-w-0">
        {breadcrumbs.map((seg, idx) => {
          const isLast = idx === breadcrumbs.length - 1;
          return (
            <span key={idx} className="flex items-center gap-1.5 min-w-0">
              {idx > 0 && (
                <span className="text-[color:var(--text-3)] select-none" aria-hidden>
                  /
                </span>
              )}
              {isLast ? (
                <span className="font-semibold text-[color:var(--text-1)] truncate">
                  {seg.label}
                </span>
              ) : (
                <a
                  href={seg.href ?? '#'}
                  className="text-[color:var(--text-2)] hover:text-[color:var(--text-1)] truncate transition-colors duration-[120ms]"
                >
                  {seg.label}
                </a>
              )}
            </span>
          );
        })}
      </nav>

      {/* Right controls */}
      <div className="ml-auto flex items-center gap-2.5">
        {onCommandPalette && (
          <button
            type="button"
            onClick={onCommandPalette}
            aria-label="Open command palette"
            className={cn(
              'flex items-center gap-2 px-2.5 py-1 rounded-md text-xs',
              'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
              'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:border-[color:var(--signal)]',
              'transition-colors duration-[120ms]',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            )}
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="M21 21l-4.35-4.35" />
            </svg>
            <span className="hidden md:inline">Search</span>
            <kbd className="hidden md:inline font-mono-tabular text-[10px] text-[color:var(--text-3)]">⌘K</kbd>
          </button>
        )}
        <ThemeToggle />
        <UserMenu username={username} />
      </div>
    </header>
  );
}
