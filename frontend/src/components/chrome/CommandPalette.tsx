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
import { useTranslation } from 'react-i18next';
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

// Static page registry. `tKey` selects the translated label; `hintKey`
// the translated hint. English aliases stay in the haystack so typing
// English still matches regardless of the active language.
const STATIC_PAGES: { tKey: string; hintKey?: string; serviceSuffix?: string; to: string; aliases?: string[]; requires?: 'admin' }[] = [
  { tKey: 'nav.dashboard', hintKey: 'commandPalette.dashboardHint', to: '/_app/' },
  { tKey: 'nav.operators', hintKey: 'commandPalette.operatorsHint', to: '/_app/users', aliases: ['users', 'permissions'], requires: 'admin' },
  { tKey: 'nav.profile', hintKey: 'commandPalette.profileHint', to: '/_app/profile' },
  { tKey: 'nav.environments', hintKey: 'commandPalette.environmentsHint', to: '/_app/environments', requires: 'admin' },
  { tKey: 'nav.settings', hintKey: 'commandPalette.settingsHint', serviceSuffix: 'admin', to: '/_app/settings/admin', aliases: ['settings', 'admin'], requires: 'admin' },
  { tKey: 'nav.settings', hintKey: 'commandPalette.settingsHint', serviceSuffix: 'tls', to: '/_app/settings/tls', aliases: ['settings', 'tls'], requires: 'admin' },
  { tKey: 'nav.settings', hintKey: 'commandPalette.settingsHint', serviceSuffix: 'osctrl-api', to: '/_app/settings/api', aliases: ['settings', 'api'], requires: 'admin' },
  // Audit Trail is visible to everyone — non-admins see only their
  // own activity (api force-clamps the username filter server-side).
  { tKey: 'nav.auditTrail', hintKey: 'commandPalette.auditHint', to: '/_app/audit' },
];

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const navigate = useNavigate();
  const { t } = useTranslation();
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
      const label = p.serviceSuffix
        ? `${t(p.tKey)} · ${p.serviceSuffix}`
        : t(p.tKey);
      const haystack = [label.toLowerCase(), ...(p.aliases ?? [])].join(' ');
      out.push({
        id: `page:${p.to}`,
        kind: 'page',
        label,
        hint: p.hintKey ? t(p.hintKey) : undefined,
        haystack,
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
        label: t('commandPalette.goToEnv', { name: e.name }),
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
          label: t('commandPalette.editConfig', { name: e.name }),
          hint: t('commandPalette.configHint'),
          haystack: `${e.name.toLowerCase()} config options schedule packs`,
          run: () => {
            void navigate({ to: `/_app/env/${e.uuid}/config` });
            onOpenChange(false);
          },
        });
      }
    }
    return out;
  }, [envs, navigate, onOpenChange, isSuperAdmin, me, t]);

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
      title={t('commandPalette.title')}
      titleId="command-palette-title"
      onClose={() => onOpenChange(false)}
      panelClassName="max-w-xl"
    >
      <div className="space-y-3">
        <input
          aria-label={t('commandPalette.searchLabel')}
          autoFocus
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={handleKey}
          placeholder={t('commandPalette.placeholder')}
          className={cn(
            'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />

        <ul ref={listRef} className="max-h-[320px] overflow-y-auto -mx-1">
          {filtered.length === 0 && (
            <li className="px-3 py-4 text-xs text-[color:var(--text-3)] text-center">
              {t('commandPalette.noMatches')}
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
                  <span className="text-xs tabular-nums text-[color:var(--text-3)] truncate max-w-[180px]">
                    {it.hint}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>

        <p className="text-xs tabular-nums text-[color:var(--text-3)] text-right">
          {t('commandPalette.legend')}
        </p>
      </div>
    </ModalShell>
  );
}
