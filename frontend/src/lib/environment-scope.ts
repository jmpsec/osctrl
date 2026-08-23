const ACTIVE_ENVIRONMENT_KEY = 'osctrl.active-environment';

export function readActiveEnvironment(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(ACTIVE_ENVIRONMENT_KEY);
  } catch {
    return null;
  }
}

export function writeActiveEnvironment(environment: string): void {
  if (typeof window === 'undefined' || !environment) return;
  try {
    window.localStorage.setItem(ACTIVE_ENVIRONMENT_KEY, environment);
  } catch {
    // Storage can be unavailable in hardened browser contexts. URL scope
    // remains authoritative, so navigation still works without persistence.
  }
}
