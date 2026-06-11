import { useEffect, useState, type ReactNode } from 'react';
import { useRouterState } from '@tanstack/react-router';
import { cn } from '$/lib/cn';
import { SideNav } from './SideNav';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';

interface AppShellProps {
  children: ReactNode;
  username?: string;
}

const NAV_COLLAPSED_KEY = 'osctrl.sidenav-collapsed';

export function AppShell({ children, username }: AppShellProps) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [navCollapsed, setNavCollapsed] = useState(
    () => localStorage.getItem(NAV_COLLAPSED_KEY) === '1',
  );
  const pathname = useRouterState().location.pathname;

  function toggleNavCollapsed() {
    const next = !navCollapsed;
    setNavCollapsed(next);
    localStorage.setItem(NAV_COLLAPSED_KEY, next ? '1' : '0');
  }

  // Global ⌘K / Ctrl-K toggle. Listener lives at the shell level so any
  // authenticated page can hit it without re-binding. Escape also closes
  // the mobile nav drawer from here for the same reason.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
      if (e.key === 'Escape') {
        setNavOpen(false);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Navigating anywhere dismisses the mobile drawer — covers nav links,
  // the env switcher, and command-palette jumps in one place.
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  return (
    <div className="flex min-h-screen bg-[color:var(--bg-0)]">
      {/* Desktop rail — hidden on phones in favor of the drawer below.
          Collapsible to an icon-only strip; preference persists. */}
      <SideNav
        className="hidden md:flex"
        collapsed={navCollapsed}
        onToggleCollapse={toggleNavCollapsed}
      />

      {/* Mobile off-canvas drawer. Kept mounted so the slide/fade can
          animate both ways; pointer-events gate off interaction while
          closed. The SideNav instance shares React Query caches with the
          desktop one, so the duplicate mount costs no extra requests. */}
      <div
        className={cn('fixed inset-0 z-40 md:hidden', !navOpen && 'pointer-events-none')}
        aria-hidden={!navOpen}
      >
        <div
          className={cn(
            'absolute inset-0 bg-black/50 transition-opacity duration-200',
            navOpen ? 'opacity-100' : 'opacity-0',
          )}
          onClick={() => setNavOpen(false)}
        />
        <div
          className={cn(
            'absolute inset-y-0 left-0 transition-transform duration-200 ease-out',
            navOpen ? 'translate-x-0' : '-translate-x-full',
          )}
        >
          <SideNav className="h-full overflow-y-auto shadow-[4px_0_24px_rgba(0,0,0,0.4)]" />
        </div>
      </div>

      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar
          username={username}
          onCommandPalette={() => setPaletteOpen(true)}
          onMenuToggle={() => setNavOpen((o) => !o)}
        />
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
