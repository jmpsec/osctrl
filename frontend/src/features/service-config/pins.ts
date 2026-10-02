import type { ServiceConfig } from '$/api/service-config';

/**
 * Which fields of a section beat flags, environment variables and the YAML
 * file. Pure logic, deliberately kept out of the API client module: tests mock
 * that module wholesale, and a parser in it vanishes with the mock.
 */
export interface PinnedFields {
  /** Every field in the section is pinned. */
  all: boolean;
  /** Lower-cased names of the pinned fields; unused when `all` is set. */
  keys: ReadonlySet<string>;
}

export const NO_PINS: PinnedFields = { all: false, keys: new Set() };

/** Field names match case-insensitively, as encoding/json does server-side. */
export const normalizeField = (key: string): string => key.toLowerCase();

/**
 * Mirrors ServiceConfig.pinSet in pkg/serviceconfig, so the page tells the
 * operator exactly what the service will do at startup.
 *
 * Only a source=db row pins anything. An empty list on such a row means a row
 * from before per-field overrides (or one replaced as a whole), where every
 * field is pinned. An unreadable list pins everything too: the safe wrong
 * answer is "your edit is kept", never "it is dropped".
 */
export function parsePins(section: Pick<ServiceConfig, 'Source' | 'Overrides'>): PinnedFields {
  if (section.Source !== 'db') return NO_PINS;
  const raw = (section.Overrides ?? '').trim();
  if (raw === '') return { all: true, keys: new Set() };
  try {
    const list: unknown = JSON.parse(raw);
    if (Array.isArray(list)) {
      return { all: false, keys: new Set(list.map((k) => normalizeField(String(k)))) };
    }
  } catch {
    // fall through to the safe reading
  }
  return { all: true, keys: new Set() };
}

export const isPinned = (pins: PinnedFields, key: string): boolean =>
  pins.all || pins.keys.has(normalizeField(key));
