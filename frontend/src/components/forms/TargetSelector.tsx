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

/**
 * Multi-target picker used on query-run and carve-run forms.
 * Sub-sections:
 *   - Nodes (searchable combobox; matches UUID or hostname,
 *     commits as UUID — the wire format)
 *   - Platforms (chip toggles)
 *   - Tags (env-scoped chip toggles)
 *
 * The hostnames-as-free-text section was dropped: the node combobox
 * already supports lookup by hostname, so a separate input added no
 * capability — only confusion about which field to type into.
 */
export function TargetSelector({ value, onChange, className, env }: TargetSelectorProps) {
  // Free-text mirror of value.uuids — same UX as
  // queries/TargetingPanel: operator types comma-separated values,
  // typeahead matches the LAST token after the most recent comma,
  // and selecting from the suggestion list appends to value.uuids.
  // onBlur parses whatever's typed so paste-and-tab also works.
  const [uuidRaw, setUuidRaw] = useState(value.uuids.join(', '));
  const [focused, setFocused] = useState(false);

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
  // Typeahead token is the substring after the LAST comma — so
  // multi-target paste works (e.g. "abc, web-" matches "web-01").
  const lastToken = useMemo(() => {
    const segs = uuidRaw.split(',');
    return segs[segs.length - 1]!.trim().toLowerCase();
  }, [uuidRaw]);

  const filteredNodes = useMemo(() => {
    if (!focused || !lastToken) return [];
    const selected = new Set(value.uuids);
    return allNodes
      .filter((n) => {
        if (selected.has(n.uuid)) return false;
        return (
          n.uuid.toLowerCase().includes(lastToken) ||
          n.hostname.toLowerCase().includes(lastToken)
        );
      })
      .slice(0, 8);
  }, [focused, lastToken, allNodes, value.uuids]);

  function commitUuids(raw: string) {
    setUuidRaw(raw);
    const parsed = raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    onChange({ ...value, uuids: parsed });
  }
  function pickUuid(uuid: string) {
    if (value.uuids.includes(uuid)) return;
    const next = [...value.uuids, uuid];
    setUuidRaw(next.join(', '));
    onChange({ ...value, uuids: next });
  }
  function removeUuid(uuid: string) {
    const next = value.uuids.filter((u) => u !== uuid);
    setUuidRaw(next.join(', '));
    onChange({ ...value, uuids: next });
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

        {env ? (
          <>
            <div className="relative">
              <input
                id="target-nodes"
                type="text"
                value={uuidRaw}
                onChange={(e) => setUuidRaw(e.target.value)}
                onFocus={() => setFocused(true)}
                // Delay blur so a mousedown on a suggestion fires
                // before the dropdown unmounts.
                onBlur={(e) => {
                  const raw = e.target.value;
                  setTimeout(() => {
                    setFocused(false);
                    commitUuids(raw);
                  }, 120);
                }}
                placeholder="type hostname or uuid, comma-separated"
                autoComplete="off"
                className={cn(
                  'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
                  'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
                  'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                )}
              />
              {filteredNodes.length > 0 && (
                <div
                  role="listbox"
                  className={cn(
                    'absolute z-10 mt-1 w-full max-h-48 overflow-auto rounded-md',
                    'border border-[color:var(--border)] bg-[color:var(--bg-2)]',
                    'shadow-lg',
                  )}
                >
                  {filteredNodes.map((n) => (
                    <button
                      key={n.uuid}
                      type="button"
                      // onMouseDown (not onClick) so we fire BEFORE
                      // the input's blur registers — otherwise the
                      // suggestion list unmounts before the click.
                      onMouseDown={(e) => {
                        e.preventDefault();
                        pickUuid(n.uuid);
                      }}
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
                        {n.uuid.slice(0, 12)}…
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            {value.uuids.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
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
            {allNodes.length === 0 && (
              <p className="mt-1 text-xs text-[color:var(--text-3)] italic">
                No enrolled nodes in this environment yet.
              </p>
            )}
          </>
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

    </div>
  );
}
