import { describe, expect, it } from 'vitest';
import type { PostureProfile } from '$/api/types';
import { applyPostureProfileToSchedule } from './postureSchedule';

const profile: PostureProfile = {
  id: 'linux-server',
  name: 'Linux Servers',
  description: 'Test profile',
  platform: 'linux',
  queries: {
    users: {
      query: 'SELECT username FROM users',
      interval: 86400,
      snapshot: true,
    },
    packages: {
      query: 'SELECT name FROM deb_packages',
      interval: 86400,
      platform: 'linux',
      snapshot: true,
    },
  },
};

describe('applyPostureProfileToSchedule', () => {
  it('merges fixed-prefix entries and replaces matching drafts', () => {
    const schedule = JSON.stringify({
      existing: { query: 'SELECT 1', interval: 60 },
      'osctrl:posture:users': { query: 'old query', interval: 10 },
    });

    const result = JSON.parse(applyPostureProfileToSchedule(schedule, profile, 3600));

    expect(result.existing).toEqual({ query: 'SELECT 1', interval: 60 });
    expect(result['osctrl:posture:users']).toEqual({
      query: 'SELECT username FROM users',
      interval: 3600,
      snapshot: true,
    });
    expect(result['osctrl:posture:packages']).toEqual({
      query: 'SELECT name FROM deb_packages',
      interval: 3600,
      platform: 'linux',
      snapshot: true,
    });
  });

  it.each(['{"broken"', '[]', 'null', '"text"'])(
    'rejects a schedule that is not a JSON object: %s',
    (schedule) => {
      expect(() => applyPostureProfileToSchedule(schedule, profile, 86400)).toThrow(
        'Schedule must be a JSON object.',
      );
    },
  );
});
