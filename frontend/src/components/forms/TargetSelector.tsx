import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listEnvTags } from '$/api/tags';
import { listNodes } from '$/api/nodes';
import { cn } from '$/lib/cn';

export interface TargetSelection {
  uuids: string[];
  platforms: string[];
  tags: string[];
  hosts: string[];
}

const PLATFORMS = ['linux', 'darwin', 'windows', 'freebsd', 'all'] as const;
type Platform = (typeof PLATFORMS)[number];

interface TargetSelectorProps {
  value: TargetSelection;
  onChange: (v: TargetSelection) => void;
  className?: string;
  /** Env scope for tag lookup. Pass undefined to keep the tag picker disabled. */
  env?: string;
}

function parseList(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Multi-target picker used on query-run and carve-run forms.
 * Sub-sections: Nodes (searchable combobox of UUID+hostname),
 * Platforms (chips), Tags (chips, env-scoped), Hostnames (free-text
 * for not-yet-enrolled hosts).
 */
export function TargetSelector({ value, onChange, className, env }: TargetSelectorProps) {
  const [hostRaw, setHostRaw] = useState(value.hosts.join(', '));
  const [nodeFilter, setNodeFilter] = useState('');

  // Env-scoped tags. If env is omitted we don't render the picker as enabled.
  const { data: envTags } = useQuery({
    queryKey: ['tags', env],
    queryFn: () => listEnvTags(env ?? ''),
    enabled: !!env,
    staleTime: 60_000,
  });

  // Env-scoped node list for the picker. The /nodes endpoint pages;
  // we ask for pageSize=500 (the API's documented max) and ignore
  // any beyond — picking from thousands by clicking is unrealistic
  // anyway, and operators with that many nodes will use platform +
  // tag filters instead of clicking individual UUIDs.
  const { data: nodeResp } = useQuery({
    queryKey: ['nodes-for-target', env],
    queryFn: () =>
      listNodes({
        env: env ?? '',
        page: 1,
        pageSize: 500,
        status: 'all',
      }),
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
  // Lookup map so we can show the friendly hostname on chips even
  // when the operator added a UUID that's not currently in the
  // fetched page (rare but possible if they deep-link into the form
  // with a UUID query param).
  const nodeByUuid = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of allNodes) m.set(n.uuid, n.hostname);
    return m;
  }, [allNodes]);
  const filteredNodes = useMemo(() => {
    const f = nodeFilter.trim().toLowerCase();
    const selected = new Set(value.uuids);
    const out = allNodes.filter((n) => !selected.has(n.uuid));
    if (!f) return out.slice(0, 20);
    return out
      .filter(
        (n) =>
          n.uuid.toLowerCase().includes(f) || n.hostname.toLowerCase().includes(f),
      )
      .slice(0, 20);
  }, [allNodes, nodeFilter, value.uuids]);

  function addUuid(uuid: string) {
    if (!uuid || value.uuids.includes(uuid)) return;
    onChange({ ...value, uuids: [...value.uuids, uuid] });
    setNodeFilter('');
  }
  function removeUuid(uuid: string) {
    onChange({ ...value, uuids: value.uuids.filter((u) => u !== uuid) });
  }

  function togglePlatform(p: Platform) {
    const has = value.platforms.includes(p);
    const next = has
      ? value.platforms.filter((x) => x !== p)
      : [...value.platforms, p];
    onChange({ ...value, platforms: next });
  }

  function toggleTag(name: string) {
    const has = value.tags.includes(name);
    const next = has
      ? value.tags.filter((x) => x !== name)
      : [...value.tags, name];
    onChange({ ...value, tags: next });
  }

  function commitHosts(raw: string) {
    setHostRaw(raw);
    onChange({ ...value, hosts: parseList(raw) });
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Nodes — searchable combobox of UUID + hostname.
          Selected nodes appear as chips above the input. Typing
          filters the dropdown by either UUID prefix or hostname
          substring. Clicking a row adds its UUID to value.uuids;
          the wire format stays UUID-based even though the picker
          shows hostnames.

          For env scopes with >500 nodes we cap the fetched page;
          operators with that many should filter via Platforms +
          Tags rather than handpick UUIDs. */}
      <div>
        <span className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
          Nodes
        </span>

        {/* Selected chips */}
        {value.uuids.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-2">
            {value.uuids.map((u) => {
              const host = nodeByUuid.get(u) ?? u;
              return (
                <button
                  key={u}
                  type="button"
                  onClick={() => removeUuid(u)}
                  className={cn(
                    'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full',
                    'bg-[color:var(--signal)] text-black border border-[color:var(--signal)]',
                    'hover:opacity-90 transition-opacity',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  )}
                  title={u}
                  aria-label={`Remove ${host}`}
                >
                  <span className="font-mono-tabular">{host}</span>
                  <span aria-hidden className="text-[10px]">×</span>
                </button>
              );
            })}
          </div>
        )}

        {env ? (
          <div className="relative">
            <input
              id="target-nodes"
              type="text"
              value={nodeFilter}
              onChange={(e) => setNodeFilter(e.target.value)}
              placeholder="Search UUID or hostname…"
              className={cn(
                'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            />
            {/* Dropdown of matching nodes. Open while the filter has
                ANY value (typed search) OR the input is focused via
                tab/click. We use a simple boolean derived from the
                filter state — focus-based open is good UX but adds
                ref+useEffect complexity that's not worth it here. */}
            {filteredNodes.length > 0 && (
              <div
                role="listbox"
                className={cn(
                  'absolute z-10 mt-1 w-full max-h-60 overflow-auto rounded-md',
                  'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
                  'shadow-lg',
                )}
              >
                {filteredNodes.map((n) => (
                  <button
                    key={n.uuid}
                    type="button"
                    onClick={() => addUuid(n.uuid)}
                    className={cn(
                      'w-full text-left px-3 py-1.5 text-xs',
                      'hover:bg-[color:var(--bg-1)] transition-colors',
                      'focus:outline focus:outline-2 focus:outline-[color:var(--signal)] focus:bg-[color:var(--bg-1)]',
                    )}
                  >
                    <span className="font-mono-tabular text-[color:var(--text-1)]">
                      {n.hostname}
                    </span>
                    <span className="ml-2 font-mono-tabular text-[color:var(--text-3)] text-[10px]">
                      {n.uuid}
                    </span>
                  </button>
                ))}
              </div>
            )}
            {allNodes.length === 0 && (
              <p className="mt-1 text-xs text-[color:var(--text-3)] italic">
                No enrolled nodes in this environment yet.
              </p>
            )}
          </div>
        ) : (
          <p className="text-xs text-[color:var(--text-3)] italic">
            Node selection requires an env scope.
          </p>
        )}
      </div>

      {/* Platforms */}
      <div>
        <span className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
          Platforms
        </span>
        <div className="flex flex-wrap gap-1.5">
          {PLATFORMS.map((p) => {
            const active = value.platforms.includes(p);
            return (
              <button
                key={p}
                type="button"
                onClick={() => togglePlatform(p)}
                aria-pressed={active}
                className={cn(
                  'px-3 py-1 text-xs font-medium rounded-full border transition-colors capitalize',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  active
                    ? 'bg-[color:var(--signal)] text-black border-[color:var(--signal)]'
                    : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
                )}
              >
                {p}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tags — env-scoped multi-select */}
      <div>
        <span className="block text-xs font-medium text-[color:var(--text-2)] mb-1">
          Tags
        </span>
        {env && envTags && envTags.length > 0 ? (
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
                    'px-3 py-1 text-xs font-medium rounded-full border transition-colors',
                    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                    active
                      ? 'bg-[color:var(--signal)] text-black border-[color:var(--signal)]'
                      : 'bg-[color:var(--bg-2)] text-[color:var(--text-2)] border-[color:var(--border)] hover:text-[color:var(--text-1)]',
                  )}
                >
                  {t.name}
                </button>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-[color:var(--text-3)] italic">
            {env ? 'No tags in this environment.' : 'Tag selection requires an env scope.'}
          </p>
        )}
      </div>

      {/* Hostnames */}
      <div>
        <label
          htmlFor="target-hosts"
          className="block text-xs font-medium text-[color:var(--text-2)] mb-1"
        >
          Hostnames
          <span className="ml-1 text-[color:var(--text-3)] font-normal">(comma-separated)</span>
        </label>
        <input
          id="target-hosts"
          type="text"
          value={hostRaw}
          onChange={(e) => setHostRaw(e.target.value)}
          onBlur={(e) => commitHosts(e.target.value)}
          placeholder="e.g. web-01, db-02"
          className={cn(
            'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
      </div>
    </div>
  );
}
