import { describe, it, expect } from 'vitest';
import { parsePins, isPinned } from './pins';

// parsePins mirrors ServiceConfig.pinSet in pkg/serviceconfig. If the two
// disagree, the page tells the operator one thing while the service does
// another at startup — so every rule is pinned here.

describe('parsePins', () => {
  it('pins nothing on a row that follows the YAML file', () => {
    const pins = parsePins({ Source: 'yaml', Overrides: '' });
    expect(pins.all).toBe(false);
    expect(isPinned(pins, 'Port')).toBe(false);
  });

  it('ignores a stale pin list on a yaml row', () => {
    // After "Write to disk" the server clears the list, but a stale column
    // must never resurrect a pin on a row the file now owns.
    const pins = parsePins({ Source: 'yaml', Overrides: '["Port"]' });
    expect(isPinned(pins, 'Port')).toBe(false);
  });

  it('pins everything on a db row with no pin list', () => {
    // A row from before per-field overrides, or one replaced as a whole.
    const pins = parsePins({ Source: 'db', Overrides: '' });
    expect(pins.all).toBe(true);
    expect(isPinned(pins, 'AnyField')).toBe(true);
  });

  it('treats a missing Overrides like an empty one', () => {
    expect(parsePins({ Source: 'db' }).all).toBe(true);
  });

  it('pins only the listed fields', () => {
    const pins = parsePins({ Source: 'db', Overrides: '["LogLevel","Port"]' });
    expect(pins.all).toBe(false);
    expect(isPinned(pins, 'LogLevel')).toBe(true);
    expect(isPinned(pins, 'Port')).toBe(true);
    expect(isPinned(pins, 'Host')).toBe(false);
  });

  it('matches field names case-insensitively, as the server does', () => {
    const pins = parsePins({ Source: 'db', Overrides: '["LogLevel"]' });
    expect(isPinned(pins, 'loglevel')).toBe(true);
    expect(isPinned(pins, 'LOGLEVEL')).toBe(true);
  });

  it.each([
    ['malformed JSON', '{not json'],
    ['a JSON object', '{"Port":1}'],
    ['a JSON string', '"Port"'],
  ])('pins everything when the list is %s', (_name, raw) => {
    // The safe wrong answer is "your edit is kept", never "it is dropped".
    const pins = parsePins({ Source: 'db', Overrides: raw });
    expect(pins.all).toBe(true);
  });
});
