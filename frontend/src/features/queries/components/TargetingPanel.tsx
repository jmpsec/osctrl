import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listEnvTags } from '$/api/tags';
import { cn } from '$/lib/cn';
import type { TargetSelection } from '$/components/forms/TargetSelector';

interface TargetingPanelProps {
  value: TargetSelection;
  onChange: (v: TargetSelection) => void;
  env: string;
}

const PLATFORM_OPTIONS = [
  { id: 'linux',   label: 'Linux',   color: 'var(--plat-linux, var(--warning))' },
  { id: 'darwin',  label: 'macOS',   color: 'var(--plat-mac, var(--info))' },
  { id: 'windows', label: 'Windows', color: 'var(--plat-windows, var(--info))' },
  { id: 'freebsd', label: 'FreeBSD', color: 'var(--text-3)' },
  { id: 'all',     label: 'All',     color: 'var(--signal)' },
] as const;

type PlatformId = (typeof PLATFORM_OPTIONS)[number]['id'];

function parseList(raw: string): string[] {
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * TargetingPanel — sticky-right column form for picking the nodes a
 * distributed query should run against. Compact / chip-forward; uses the
 * shared TargetSelection shape so the surrounding QueryRunPage doesn't need
 * to convert.
 *
 * Sub-blocks (top → bottom):
 *   - PlatformPills (pressable chip row)
 *   - TagSelect (env-scoped chips; clicking toggles inclusion)
 *   - UUIDs textarea + ChipList of parsed UUIDs
 *   - Hostnames textarea + ChipList of parsed hosts
 *   - TargetPreview (one-line summary of what will fire)
 */
export function TargetingPanel({ value, onChange, env }: TargetingPanelProps) {
  const [uuidRaw, setUuidRaw] = useState(value.uuids.join(', '));
  const [hostRaw, setHostRaw] = useState(value.hosts.join(', '));

  const { data: envTags } = useQuery({
    queryKey: ['tags', env],
    queryFn: () => listEnvTags(env),
    enabled: !!env,
    staleTime: 60_000,
  });

  function togglePlatform(p: PlatformId) {
    const has = value.platforms.includes(p);
    const next = has ? value.platforms.filter((x) => x !== p) : [...value.platforms, p];
    onChange({ ...value, platforms: next });
  }
  function toggleTag(name: string) {
    const has = value.tags.includes(name);
    const next = has ? value.tags.filter((x) => x !== name) : [...value.tags, name];
    onChange({ ...value, tags: next });
  }
  function commitUuids(raw: string) {
    setUuidRaw(raw);
    onChange({ ...value, uuids: parseList(raw) });
  }
  function commitHosts(raw: string) {
    setHostRaw(raw);
    onChange({ ...value, hosts: parseList(raw) });
  }
  function removeUuid(u: string) {
    const next = value.uuids.filter((x) => x !== u);
    setUuidRaw(next.join(', '));
    onChange({ ...value, uuids: next });
  }
  function removeHost(h: string) {
    const next = value.hosts.filter((x) => x !== h);
    setHostRaw(next.join(', '));
    onChange({ ...value, hosts: next });
  }

  const totalSelectors =
    value.uuids.length + value.platforms.length + value.tags.length + value.hosts.length;

  return (
    <div className="space-y-4">
      {/* ── Platforms ─────────────────────────────────────────────────── */}
      <div>
        <SectionLabel>Platforms</SectionLabel>
        <div className="flex flex-wrap gap-1.5">
          {PLATFORM_OPTIONS.map((p) => {
            const active = value.platforms.includes(p.id);
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => togglePlatform(p.id)}
                aria-pressed={active}
                className={cn(
                  'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full',
                  'text-[11px] font-medium transition-colors duration-[120ms]',
                  'border focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  active
                    ? 'bg-[color:var(--signal)]/12 text-[color:var(--signal-bright,var(--signal))] border-[color:var(--signal)]/40'
                    : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
                )}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ background: p.color }}
                  aria-hidden
                />
                {p.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Tags ──────────────────────────────────────────────────────── */}
      <div>
        <SectionLabel>Tags</SectionLabel>
        {envTags && envTags.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {envTags.map((t) => {
              const active = value.tags.includes(t.name);
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => toggleTag(t.name)}
                  aria-pressed={active}
                  className={cn(
                    'px-2 py-0.5 rounded-full text-[11px] font-medium border transition-colors duration-[120ms]',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                    active
                      ? 'bg-[color:var(--signal)]/12 text-[color:var(--signal-bright,var(--signal))] border-[color:var(--signal)]/40'
                      : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
                  )}
                >
                  {t.name}
                </button>
              );
            })}
          </div>
        ) : (
          <p className="text-[11px] text-[color:var(--text-3)] italic">
            No tags in this environment.
          </p>
        )}
      </div>

      {/* ── UUIDs ─────────────────────────────────────────────────────── */}
      <div>
        <SectionLabel>Node UUIDs</SectionLabel>
        <input
          id="target-uuids"
          type="text"
          value={uuidRaw}
          onChange={(e) => setUuidRaw(e.target.value)}
          onBlur={(e) => commitUuids(e.target.value)}
          placeholder="comma-separated"
          className={cn(
            'w-full px-2.5 py-1.5 text-xs rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
            'font-mono-tabular',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        {value.uuids.length > 0 && (
          <ChipList items={value.uuids} onRemove={removeUuid} mono />
        )}
      </div>

      {/* ── Hostnames ─────────────────────────────────────────────────── */}
      <div>
        <SectionLabel>Hostnames</SectionLabel>
        <input
          id="target-hosts"
          type="text"
          value={hostRaw}
          onChange={(e) => setHostRaw(e.target.value)}
          onBlur={(e) => commitHosts(e.target.value)}
          placeholder="comma-separated"
          className={cn(
            'w-full px-2.5 py-1.5 text-xs rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
            'font-mono-tabular',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        {value.hosts.length > 0 && (
          <ChipList items={value.hosts} onRemove={removeHost} mono />
        )}
      </div>

      {/* ── Preview ───────────────────────────────────────────────────── */}
      <TargetPreview value={value} total={totalSelectors} />
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-1.5">
      {children}
    </label>
  );
}

function ChipList({
  items,
  onRemove,
  mono,
}: {
  items: string[];
  onRemove: (item: string) => void;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {items.map((it) => (
        <span
          key={it}
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px]',
            'bg-[color:var(--signal)]/10 text-[color:var(--signal-bright,var(--signal))]',
            'border border-[color:var(--signal)]/30',
            mono && 'font-mono-tabular',
          )}
        >
          <span className="truncate max-w-[100px]" title={it}>
            {mono ? it.slice(0, 8) + (it.length > 8 ? '…' : '') : it}
          </span>
          <button
            type="button"
            onClick={() => onRemove(it)}
            aria-label={`Remove ${it}`}
            className="text-[color:var(--text-3)] hover:text-[color:var(--danger)] transition-colors"
          >
            ×
          </button>
        </span>
      ))}
    </div>
  );
}

interface TargetPreviewProps {
  value: TargetSelection;
  total: number;
}

function TargetPreview({ value, total }: TargetPreviewProps) {
  // Compose a 1-line summary of the union of all target selectors.
  const parts: string[] = [];
  if (value.platforms.length) parts.push(`${value.platforms.length} platform${value.platforms.length === 1 ? '' : 's'}`);
  if (value.tags.length) parts.push(`${value.tags.length} tag${value.tags.length === 1 ? '' : 's'}`);
  if (value.uuids.length) parts.push(`${value.uuids.length} UUID${value.uuids.length === 1 ? '' : 's'}`);
  if (value.hosts.length) parts.push(`${value.hosts.length} host${value.hosts.length === 1 ? '' : 's'}`);

  return (
    <div
      className={cn(
        'rounded-md px-3 py-2.5',
        'border border-[color:var(--border)]',
        total === 0
          ? 'bg-[color:var(--warning)]/8 border-[color:var(--warning)]/30'
          : 'bg-[color:var(--bg-2)]',
      )}
    >
      <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-1">
        Target preview
      </div>
      {total === 0 ? (
        <p className="text-[11px] text-[color:var(--warning)]">
          No targets selected — the query will fire against <strong>all nodes</strong> in this env.
        </p>
      ) : (
        <p className="text-[11px] text-[color:var(--text-1)]">
          Will fire against <span className="text-[color:var(--signal)] font-mono-tabular">{parts.join(' · ')}</span>.
        </p>
      )}
    </div>
  );
}
