import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listEnvTags } from '$/api/tags';
import { listNodes } from '$/api/nodes';
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

  const { data: envTags } = useQuery({
    queryKey: ['tags', env],
    queryFn: () => listEnvTags(env),
    enabled: !!env,
    staleTime: 60_000,
  });

  // Enrolled nodes for typeahead suggestions on the UUID and hostname
  // fields. pageSize=500 caps how many we list inline; operators with
  // more than that should use Platforms/Tags chips above.
  const { data: nodeResp } = useQuery({
    queryKey: ['nodes-for-target', env],
    queryFn: () =>
      listNodes({ env, page: 1, pageSize: 500, status: 'all' }),
    enabled: !!env,
    staleTime: 30_000,
  });
  const allNodes = useMemo(
    () =>
      (nodeResp?.items ?? []).map((n) => ({
        uuid: n.uuid,
        hostname: n.hostname || n.localname || n.uuid,
      })),
    [nodeResp],
  );

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
  function removeUuid(u: string) {
    const next = value.uuids.filter((x) => x !== u);
    setUuidRaw(next.join(', '));
    onChange({ ...value, uuids: next });
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

      {/* ── Nodes — typeahead by hostname or UUID, commits as UUID ──
          One picker for both lookup modes. Typing matches against
          BOTH the UUID and the hostname; selecting a row commits
          the node's UUID to value.uuids. The wire format stays
          UUID-based (immutable, unambiguous); we just don't make
          the operator know that. */}
      <div>
        <SectionLabel>Nodes</SectionLabel>
        <TypeaheadInput
          inputId="target-uuids"
          value={uuidRaw}
          onChange={setUuidRaw}
          onBlur={commitUuids}
          allNodes={allNodes}
          selected={value.uuids}
          searchKey="uuid"
          onPick={(uuid) => {
            if (value.uuids.includes(uuid)) return;
            const next = [...value.uuids, uuid];
            // Trailing ", " puts the cursor in the right place to
            // start typing the next token. endsWithComma in the
            // picker keeps the suggestion list open so the operator
            // can keep clicking without re-focusing.
            setUuidRaw(next.join(', ') + ', ');
            onChange({ ...value, uuids: next });
          }}
          placeholder="type hostname or uuid"
        />
        {value.uuids.length > 0 && (
          <NodeChipList
            uuids={value.uuids}
            allNodes={allNodes}
            onRemove={removeUuid}
          />
        )}
      </div>

      {/* ── Preview ───────────────────────────────────────────────────── */}
      <TargetPreview value={value} total={totalSelectors} />
    </div>
  );
}

// TypeaheadInput is the per-field input + inline suggestion list used
// for UUIDs and Hostnames. As the operator types, it matches the
// trailing token (after the last comma) against the env's node list
// by both UUID and hostname — so typing "web" finds web-01 even
// inside the UUID field, and typing a UUID prefix finds it inside
// the Hostname field. Clicking a suggestion commits via onPick.
// onBlur still fires through commitUuids/commitHosts so a paste of
// a value the picker didn't surface still works.
function TypeaheadInput({
  inputId,
  value,
  onChange,
  onBlur,
  allNodes,
  selected,
  searchKey,
  onPick,
  placeholder,
}: {
  inputId: string;
  value: string;
  onChange: (next: string) => void;
  onBlur: (raw: string) => void;
  allNodes: { uuid: string; hostname: string }[];
  selected: string[];
  searchKey: 'uuid' | 'hostname';
  onPick: (key: string) => void;
  placeholder?: string;
}) {
  const [focused, setFocused] = useState(false);

  // The token we filter against is the substring after the LAST
  // comma (so multi-target paste works: "abc, web-".prefix matches
  // "web-01"). Empty token shows no suggestions — we don't want a
  // 500-row dropdown on focus.
  const lastToken = useMemo(() => {
    const segs = value.split(',');
    return segs[segs.length - 1]!.trim().toLowerCase();
  }, [value]);

  // endsWithComma tells the picker "operator just finished a token
  // and is ready to type another". In that state we show the top-8
  // unselected nodes so the operator can keep picking without
  // typing — same affordance as a multi-select dropdown.
  const endsWithComma = /,[\s]*$/.test(value);

  const filtered = useMemo(() => {
    if (!focused) return [];
    const sel = new Set(selected);
    const unselected = allNodes.filter((n) => {
      const k = searchKey === 'uuid' ? n.uuid : n.hostname;
      return !sel.has(k);
    });
    // No active token but trailing comma → show top 8 to invite
    // another pick. No token AND no comma → show nothing (avoid
    // dropdown opening on an empty unfocused-then-clicked input).
    if (!lastToken) {
      return endsWithComma ? unselected.slice(0, 8) : [];
    }
    return unselected
      .filter((n) =>
        // Match against BOTH uuid and hostname — operator typing
        // "web" in the UUID field still finds web-01.
        n.uuid.toLowerCase().includes(lastToken) ||
        n.hostname.toLowerCase().includes(lastToken),
      )
      .slice(0, 8);
  }, [focused, lastToken, endsWithComma, allNodes, selected, searchKey]);

  return (
    <div className="relative">
      <input
        id={inputId}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        // Delay blur so mousedown on a suggestion fires before the
        // suggestion list unmounts. 120ms is the same duration the
        // rest of the SPA uses for state transitions.
        onBlur={(e) => {
          const raw = e.target.value;
          setTimeout(() => {
            setFocused(false);
            onBlur(raw);
          }, 120);
        }}
        placeholder={placeholder}
        className={cn(
          'w-full px-2.5 py-1.5 text-xs rounded-md border border-[color:var(--border)]',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
          'font-mono-tabular',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
        )}
        autoComplete="off"
      />
      {filtered.length > 0 && (
        <div
          role="listbox"
          className={cn(
            'absolute z-10 mt-1 w-full max-h-48 overflow-auto rounded-md',
            'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
            'shadow-lg',
          )}
        >
          {filtered.map((n) => {
            const key = searchKey === 'uuid' ? n.uuid : n.hostname;
            return (
              <button
                key={n.uuid}
                type="button"
                // onMouseDown (not onClick) so we fire BEFORE the
                // input's blur registers — otherwise the suggestion
                // list unmounts before the click lands.
                onMouseDown={(e) => {
                  e.preventDefault();
                  onPick(key);
                }}
                className={cn(
                  'w-full text-left px-2.5 py-1 text-xs',
                  'hover:bg-[color:var(--bg-1)] transition-colors',
                  'focus:outline focus:outline-2 focus:outline-[color:var(--signal)] focus:bg-[color:var(--bg-1)]',
                )}
              >
                <span className="font-mono-tabular text-[color:var(--text-1)]">
                  {n.hostname}
                </span>
                <span className="ml-2 font-mono-tabular text-[color:var(--text-3)] text-[10px]">
                  {n.uuid.slice(0, 12)}…
                </span>
              </button>
            );
          })}
        </div>
      )}
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

// NodeChipList renders selected node UUIDs as hostname-labeled chips
// (with the UUID prefix in muted text alongside) so the operator sees
// who they actually targeted, not a row of opaque hex strings. Wire
// format stays UUID-based; this is presentation only.
function NodeChipList({
  uuids,
  allNodes,
  onRemove,
}: {
  uuids: string[];
  allNodes: { uuid: string; hostname: string }[];
  onRemove: (uuid: string) => void;
}) {
  const lookup = new Map<string, string>();
  for (const n of allNodes) lookup.set(n.uuid, n.hostname);
  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {uuids.map((u) => {
        const host = lookup.get(u);
        return (
          <span
            key={u}
            className={cn(
              'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px]',
              'bg-[color:var(--signal)]/10 text-[color:var(--signal-bright,var(--signal))]',
              'border border-[color:var(--signal)]/30 font-mono-tabular',
            )}
            title={u}
          >
            <span className="truncate max-w-[120px]">
              {host ?? u.slice(0, 8) + (u.length > 8 ? '…' : '')}
            </span>
            <button
              type="button"
              onClick={() => onRemove(u)}
              aria-label={`Remove ${host ?? u}`}
              className="text-[color:var(--text-3)] hover:text-[color:var(--danger)] transition-colors"
            >
              ×
            </button>
          </span>
        );
      })}
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
