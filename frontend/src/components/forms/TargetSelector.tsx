import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listEnvTags } from '$/api/tags';
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
 * Sub-sections: UUIDs (free-text), Platforms (multi-select chips), Tags
 * (multi-select chips, env-scoped), Hostnames (free-text).
 */
export function TargetSelector({ value, onChange, className, env }: TargetSelectorProps) {
  const [uuidRaw, setUuidRaw] = useState(value.uuids.join(', '));
  const [hostRaw, setHostRaw] = useState(value.hosts.join(', '));

  // Env-scoped tags. If env is omitted we don't render the picker as enabled.
  const { data: envTags } = useQuery({
    queryKey: ['tags', env],
    queryFn: () => listEnvTags(env ?? ''),
    enabled: !!env,
    staleTime: 60_000,
  });

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

  function commitUuids(raw: string) {
    setUuidRaw(raw);
    onChange({ ...value, uuids: parseList(raw) });
  }

  function commitHosts(raw: string) {
    setHostRaw(raw);
    onChange({ ...value, hosts: parseList(raw) });
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* UUIDs */}
      <div>
        <label
          htmlFor="target-uuids"
          className="block text-xs font-medium text-[color:var(--text-2)] mb-1"
        >
          Node UUIDs
          <span className="ml-1 text-[color:var(--text-3)] font-normal">(comma-separated)</span>
        </label>
        <input
          id="target-uuids"
          type="text"
          value={uuidRaw}
          onChange={(e) => setUuidRaw(e.target.value)}
          onBlur={(e) => commitUuids(e.target.value)}
          placeholder="e.g. abc123, def456"
          className={cn(
            'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
            'bg-[color:var(--bg-2)] text-[color:var(--text-1)] placeholder-[color:var(--text-3)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
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
