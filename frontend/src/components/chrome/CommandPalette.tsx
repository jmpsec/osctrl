/**
 * CommandPalette — global ⌘K / Ctrl-K launcher.
 *
 * Indexes static pages + every environment (live, via the same query the
 * EnvSwitcher uses). Filter is a single fuzzy-ish "all words must appear"
 * match against the visible label + the optional aliases. Up/Down navigate,
 * Enter activates, Esc / click-outside / Cmd-K-again all dismiss.
 *
 * Lives in `chrome/` because it's part of the app shell — mounted once at
 * AppShell level and reachable from any authenticated page. Wrapped in
 * ModalShell so the popover gets focus management + a11y for free.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { ModalShell } from '$/components/feedback/ModalShell';
import { listEnvironments, type TLSEnvironment } from '$/api/environments';
import { getMe } from '$/api/users';
import { isAuthenticated } from '$/api/client';

type CommandKind = 'page' | 'env' | 'action';

interface CommandItem {
  id: string;
  kind: CommandKind;
  label: string;
  hint?: string;
  /** Lower-cased haystack used for filtering — label + aliases joined. */
  haystack: string;
  run: () => void;
}

// requires: 'admin' hides the entry from non-super-admin operators.
// Pages without a requires field show to everyone. The SideNav uses the
// same gating logic — keep both in sync when adding new admin-only
// surfaces. The command palette is UI-only defense-in-depth; the
// server-side handler is still the authoritative gate (an operator
// could type the URL manually and would get 403/redirect from the
// data fetch).
const STATIC_PAGES: { label: string; to: string; hint?: string; aliases?: string[]; requires?: 'admin' }[] = [
  { label: 'Dashboard', to: '/_app/', hint: 'Cross-env summary' },
  { label: 'Operators', to: '/_app/users', hint: 'Users + permissions', aliases: ['users', 'permissions'], requires: 'admin' },
  { label: 'Profile', to: '/_app/profile', hint: 'My account' },
  { label: 'Environments', to: '/_app/environments', hint: 'Create / edit envs', requires: 'admin' },
  { label: 'Settings · admin', to: '/_app/settings/admin', aliases: ['settings'], requires: 'admin' },
  { label: 'Settings · tls', to: '/_app/settings/tls', requires: 'admin' },
  { label: 'Settings · osctrl-api', to: '/_app/settings/api', requires: 'admin' },
  // Audit Trail is visible to everyone — non-admins see only their
  // own activity (api force-clamps the username filter server-side).
  { label: 'Audit Trail', to: '/_app/audit', hint: 'Filtered log read' },
];

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const { data: envs = [] } = useQuery({
    queryKey: ['environments-cmdpal'],
    queryFn: () => listEnvironments(),
    enabled: open && isAuthenticated(),
    staleTime: 60_000,
  });

  // Pull the viewer to gate admin-only static pages + env-config
  // entries. Non-admins shouldn't see commands for surfaces they
  // can't actually reach. The "Edit config" env entry also gates on
  // env.admin (env-scoped admin) — same logic the SideNav applies.
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    enabled: open && isAuthenticated(),
    staleTime: 5 * 60_000,
  });
  const isSuperAdmin = me?.admin === true;

  // Reset filter and selection each time we open.
  useEffect(() => {
    if (open) {
      setFilter('');
      setSelected(0);
    }
  }, [open]);

  const items = useMemo<CommandItem[]>(() => {
    const out: CommandItem[] = [];
    for (const p of STATIC_PAGES) {
      if (p.requires === 'admin' && !isSuperAdmin) continue;
      const aliases = [p.label.toLowerCase(), ...(p.aliases ?? [])].join(' ');
      out.push({
        id: `page:${p.to}`,
        kind: 'page',
        label: p.label,
        hint: p.hint,
        haystack: aliases,
        run: () => {
          void navigate({ to: p.to });
          onOpenChange(false);
        },
      });
    }
    for (const e of envs as TLSEnvironment[]) {
      // The /environments list endpoint already filters server-side
      // to envs the user has access to, so every entry here is a
      // legitimate "Go to env" target. No additional gate needed
      // for the goto entry.
      out.push({
        id: `env:${e.uuid}`,
        kind: 'env',
        label: `Go to env · ${e.name}`,
        hint: e.uuid,
        haystack: `${e.name.toLowerCase()} ${e.uuid.toLowerCase()} env`,
        run: () => {
          void navigate({ to: `/_app/env/${e.uuid}/nodes` });
          onOpenChange(false);
        },
      });
      // "Edit config" is admin-tier — gate on super-admin OR
      // env-scoped admin. Without this, a non-admin would see a
      // command that 403s on the config page's data fetch.
      const envAdmin = isSuperAdmin || me?.permissions?.[e.uuid]?.admin === true;
      if (envAdmin) {
        out.push({
          id: `env-config:${e.uuid}`,
          kind: 'action',
          label: `Edit config · ${e.name}`,
          hint: 'osquery config sections',
          haystack: `${e.name.toLowerCase()} config options schedule packs`,
          run: () => {
            void navigate({ to: `/_app/env/${e.uuid}/config` });
            onOpenChange(false);
          },
        });
      }
    }
    return out;
  }, [envs, navigate, onOpenChange, isSuperAdmin, me]);

  const filtered = useMemo(() => {
    const tokens = filter
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    if (tokens.length === 0) return items;
    return items.filter((it) => tokens.every((t) => it.haystack.includes(t)));
  }, [filter, items]);

  // Clamp selection on filter change.
  useEffect(() => {
    setSelected((s) => Math.max(0, Math.min(s, filtered.length - 1)));
  }, [filtered]);

  // Scroll the selected row into view.
  useEffect(() => {
    if (!listRef.current) return;
    const el = listRef.current.querySelector<HTMLLIElement>(
      `li[data-idx="${selected}"]`,
    );
    el?.scrollIntoView({ block: 'nearest' });
  }, [selected]);

  function handleKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelected((s) => Math.min(filtered.length - 1, s + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelected((s) => Math.max(0, s - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const it = filtered[selected];
      if (it) it.run();
    }
  }

  if (!open) return null;

  return (
    <ModalShell
      title="Command palette"
      titleId="command-palette-title"
      onClose={() => onOpenChange(false)}
      panelClassName="max-w-xl"
    >
      <div className="space-y-3">
        <input
          aria-label="Command search"
          autoFocus
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Type to filter… Up/Down + Enter"
          className={cn(
            'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />

        <ul ref={listRef} className="max-h-[320px] overflow-y-auto -mx-1">
          {filtered.length === 0 && (
            <li className="px-3 py-4 text-xs text-[color:var(--text-3)] text-center">
              No matches.
            </li>
          )}
          {filtered.map((it, idx) => (
            <li
              key={it.id}
              data-idx={idx}
              onMouseEnter={() => setSelected(idx)}
            >
              <button
                type="button"
                onClick={it.run}
                className={cn(
                  'w-full text-left flex items-center gap-3 px-3 py-2 rounded-md text-sm',
                  'transition-colors',
                  idx === selected
                    ? 'bg-[color:var(--bg-2)] text-[color:var(--text-1)]'
                    : 'text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)]',
                )}
              >
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{
                    backgroundColor:
                      it.kind === 'env'
                        ? 'var(--success)'
                        : it.kind === 'action'
                          ? 'var(--warning)'
                          : 'var(--signal)',
                  }}
                  aria-hidden
                />
                <span className="flex-1 truncate">{it.label}</span>
                {it.hint && (
                  <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)] truncate max-w-[180px]">
                    {it.hint}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>

        <p className="text-[10px] font-mono-tabular text-[color:var(--text-3)] text-right">
          ⌘K toggle · Esc close · ↑↓ navigate · ↵ activate
        </p>
      </div>
    </ModalShell>
  );
}
