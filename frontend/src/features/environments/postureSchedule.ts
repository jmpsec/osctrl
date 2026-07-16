import type { PostureProfile } from '$/api/types';

const POSTURE_QUERY_PREFIX = 'osctrl:posture:';

export function applyPostureProfileToSchedule(
  schedule: string,
  profile: PostureProfile,
  interval: number,
): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(schedule || '{}');
  } catch {
    throw new Error('Schedule must be a JSON object.');
  }
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Schedule must be a JSON object.');
  }

  const entries = parsed as Record<string, unknown>;
  for (const [name, query] of Object.entries(profile.queries)) {
    entries[POSTURE_QUERY_PREFIX + name] = {
      query: query.query,
      interval,
      snapshot: query.snapshot,
      ...(query.platform ? { platform: query.platform } : {}),
    };
  }
  return JSON.stringify(entries, null, 2);
}
