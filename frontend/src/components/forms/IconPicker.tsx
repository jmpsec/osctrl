/**
 * IconPicker — icon selector with search and grid.
 *
 * Uses lucide-react icons (bundled, no external CSS needed).
 * Stores the lucide icon name (e.g. "server", "cloud") in the
 * environment's icon field.
 */
import { useState, useMemo, useRef, useEffect } from 'react';
import {
  Server, Cloud, Shield, Lock, Globe, Network, Monitor, Laptop,
  HardDrive, Database, Terminal, Bug, Cog, Wrench, Cpu, Radar,
  Router,  Flame, Bolt, Rocket, Satellite, Building,
  Warehouse, Factory, Store, School, Hospital, Fingerprint,
  Key, Eye, Search, ChartLine, ChartBar, Bell, Flag, Star,
  Heart, Leaf, Anchor, Plane, Drone, type LucideIcon,
} from 'lucide-react';
import { cn } from '$/lib/cn';

const PRESET_ICONS: { name: string; Icon: LucideIcon }[] = [
  { name: 'server', Icon: Server },
  { name: 'cloud', Icon: Cloud },
  { name: 'shield', Icon: Shield },
  { name: 'lock', Icon: Lock },
  { name: 'globe', Icon: Globe },
  { name: 'network', Icon: Network },
  { name: 'monitor', Icon: Monitor },
  { name: 'laptop', Icon: Laptop },
  { name: 'hard-drive', Icon: HardDrive },
  { name: 'database', Icon: Database },
  { name: 'terminal', Icon: Terminal },
  { name: 'bug', Icon: Bug },
  { name: 'cog', Icon: Cog },
  { name: 'wrench', Icon: Wrench },
  { name: 'cpu', Icon: Cpu },
  { name: 'radar', Icon: Radar },
  { name: 'router', Icon: Router },
  { name: 'network', Icon: Network }, // deduped below — remove
  { name: 'flame', Icon: Flame },
  { name: 'bolt', Icon: Bolt },
  { name: 'rocket', Icon: Rocket },
  { name: 'satellite', Icon: Satellite },
  { name: 'building', Icon: Building },
  { name: 'warehouse', Icon: Warehouse },
  { name: 'factory', Icon: Factory },
  { name: 'store', Icon: Store },
  { name: 'school', Icon: School },
  { name: 'hospital', Icon: Hospital },
  { name: 'fingerprint', Icon: Fingerprint },
  { name: 'key', Icon: Key },
  { name: 'eye', Icon: Eye },
  { name: 'search', Icon: Search },
  { name: 'chart-line', Icon: ChartLine },
  { name: 'chart-bar', Icon: ChartBar },
  { name: 'bell', Icon: Bell },
  { name: 'flag', Icon: Flag },
  { name: 'star', Icon: Star },
  { name: 'heart', Icon: Heart },
  { name: 'leaf', Icon: Leaf },
  { name: 'anchor', Icon: Anchor },
  { name: 'plane', Icon: Plane },
  { name: 'drone', Icon: Drone },
];

const ICON_MAP: Record<string, LucideIcon> = Object.fromEntries(
  PRESET_ICONS.map(({ name, Icon }) => [name, Icon]),
);

/** Resolve an icon name string to a lucide component, or null. */
export function resolveEnvIcon(icon: string | undefined | null): LucideIcon | null {
  if (!icon) return null;
  // Support both lucide names ("server") and legacy FA classes ("fas fa-server")
  // by extracting the last segment.
  const name = icon.includes(' ') ? icon.split(' ').pop()! : icon;
  return ICON_MAP[name] ?? null;
}

interface IconPickerProps {
  value: string;
  onChange: (icon: string) => void;
  id?: string;
}

export function IconPicker({ value, onChange, id }: IconPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const currentIcon = resolveEnvIcon(value);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return PRESET_ICONS;
    return PRESET_ICONS.filter((item) => item.name.includes(q));
  }, [search]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        id={id}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'flex items-center gap-2 w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          'hover:border-[color:var(--signal)]/40 transition-colors',
        )}
      >
        {currentIcon ? (
          (() => {
            const Icon = currentIcon;
            return <Icon className="w-4 h-4 flex-shrink-0" />;
          })()
        ) : (
          <span className="text-[color:var(--text-3)] text-xs">No icon</span>
        )}
        <span className="flex-1 text-left truncate text-[color:var(--text-2)] font-mono-tabular">
          {value.trim() || 'Click to pick an icon…'}
        </span>
        <svg className="w-3.5 h-3.5 text-[color:var(--text-3)] flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div
          className={cn(
            'absolute z-50 mt-1 w-full rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-1)] shadow-lg max-h-[280px] flex flex-col',
          )}
        >
          <div className="p-2 border-b border-[color:var(--border)]">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search icons…"
              autoFocus
              className={cn(
                'w-full px-2 py-1 text-xs rounded border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            />
          </div>
          <div className="overflow-auto p-2 grid grid-cols-6 gap-1">
            {filtered.map(({ name, Icon }) => (
              <button
                key={name}
                type="button"
                onClick={() => {
                  onChange(name);
                  setOpen(false);
                  setSearch('');
                }}
                className={cn(
                  'flex items-center justify-center w-9 h-9 rounded transition-colors',
                  'hover:bg-[color:var(--bg-2)]',
                  value.trim() === name || value.trim() === `fas fa-${name}`
                    ? 'bg-[color:var(--signal)]/10 border border-[color:var(--signal)]/30 text-[color:var(--signal)]'
                    : 'text-[color:var(--text-2)] border border-transparent',
                )}
                title={name}
              >
                <Icon className="w-4 h-4" />
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="col-span-6 py-4 text-center text-[10px] text-[color:var(--text-3)]">
                No icons match "{search}".
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
