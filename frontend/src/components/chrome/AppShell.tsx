import { useEffect, useState, type ReactNode } from 'react';
import { SideNav } from './SideNav';
import { TopBar } from './TopBar';
import { CommandPalette } from './CommandPalette';

interface AppShellProps {
  children: ReactNode;
  username?: string;
}

export function AppShell({ children, username }: AppShellProps) {
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Global ⌘K / Ctrl-K toggle. Listener lives at the shell level so any
  // authenticated page can hit it without re-binding.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="flex min-h-screen bg-[color:var(--bg-0)]">
      <SideNav />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar username={username} onCommandPalette={() => setPaletteOpen(true)} />
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
