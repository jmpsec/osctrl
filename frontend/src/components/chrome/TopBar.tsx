import { cn } from '$/lib/cn';
import { Menu, PanelLeftClose, PanelLeftOpen, Search } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { ThemeToggle } from './ThemeToggle';
import { LanguageMenu } from './LanguageMenu';
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
  desktopNavCollapsed?: boolean;
  onDesktopNavToggle?: () => void;
}

export function TopBar({
  breadcrumbs = [{ label: 'Command Center' }],
  username,
  onCommandPalette,
  onMenuToggle,
  desktopNavCollapsed,
  onDesktopNavToggle,
}: TopBarProps) {
  const { t } = useTranslation();

  return (
    <header
      className={cn(
        'topbar-glass',
        'h-12 flex items-center gap-3 px-3',
        'border-b border-[color:var(--border)]',
        'sticky top-0 z-30',
      )}
    >
      {/* Hamburger — phones only; the rail is always visible at md+. */}
      {onMenuToggle && (
        <button
          type="button"
          onClick={onMenuToggle}
          aria-label={t('topbar.openNavigation')}
          className={cn(
            'md:hidden -ml-1 flex h-8 w-8 items-center justify-center rounded-md',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'transition-colors duration-[120ms]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
          )}
        >
          <Menu size={18} strokeWidth={1.75} />
        </button>
      )}

      {/* Persistent desktop sidebar control. Keeping this in the toolbar
          means it remains discoverable even when the rail is collapsed. */}
      {onDesktopNavToggle && (
        <button
          type="button"
          onClick={onDesktopNavToggle}
          aria-label={desktopNavCollapsed ? t('topbar.expandNavigation') : t('topbar.collapseNavigation')}
          title={desktopNavCollapsed ? t('topbar.expandNavigation') : t('topbar.collapseNavigation')}
          className={cn(
            'hidden md:flex -ml-1 h-8 w-8 items-center justify-center rounded-md',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'transition-colors duration-[120ms]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
          )}
        >
          {desktopNavCollapsed ? (
            <PanelLeftOpen size={18} strokeWidth={1.75} />
          ) : (
            <PanelLeftClose size={18} strokeWidth={1.75} />
          )}
        </button>
      )}

      {/* Breadcrumbs */}
      <nav aria-label={t('topbar.breadcrumb')} className="flex items-center gap-1.5 text-sm min-w-0">
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
      <div className="ml-auto flex items-center gap-1.5">
        {onCommandPalette && (
          <button
            type="button"
            onClick={onCommandPalette}
            aria-label={t('topbar.openCommandPalette')}
            className={cn(
              'flex h-8 items-center gap-2 rounded-md border border-[color:var(--border)] px-2.5 text-xs',
              'bg-[color:var(--bg-1)] text-[color:var(--text-2)]',
              'hover:border-[color:var(--border-strong)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
              'transition-colors duration-[100ms]',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--accent)]',
            )}
          >
            <Search size={14} strokeWidth={1.8} />
            <span className="hidden md:inline">{t('common.search')}</span>
            <kbd className="hidden md:inline font-mono-tabular text-xs text-[color:var(--text-3)]">⌘K</kbd>
          </button>
        )}
        <ThemeToggle />
        <LanguageMenu />
        <UserMenu username={username} />
      </div>
    </header>
  );
}
