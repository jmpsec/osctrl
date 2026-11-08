import type { EnvAccess, UserMeResponse } from '$/api/types';

export type Page =
  | 'users' | 'environments' | 'settings' | 'serviceConfig' | 'logSinks' | 'extensions'
  | 'osqueryVersions' | 'authProviders' | 'alerts' | 'health' | 'auditAll' | 'vulnFeeds';

export type EnvCaps = { view: boolean; query: boolean; carve: boolean; manage: boolean };

type Me = UserMeResponse | undefined;

export const isSuperuser = (me: Me): boolean => !!me?.admin;

// user_admin and env_manager imply read-only admin on the server.
export const isReadOnlyAdmin = (me: Me): boolean =>
  !!me && (me.read_only_admin || me.user_admin || me.env_manager);

export function canSeePage(me: Me, page: Page): boolean {
  if (!me) return false;
  if (me.admin) return true;
  switch (page) {
    case 'users':
    case 'environments':
      return isReadOnlyAdmin(me);
    case 'alerts':
      return me.alert_admin || isReadOnlyAdmin(me);
    case 'health':
    case 'auditAll':
    case 'vulnFeeds':
      return isReadOnlyAdmin(me);
    default:
      return false; // superuser-only pages
  }
}

export function canWritePage(me: Me, page: Page): boolean {
  if (!me) return false;
  if (me.admin) return true;
  switch (page) {
    case 'users':
      return me.user_admin;
    case 'environments':
      return me.env_manager;
    case 'alerts':
      return me.alert_admin;
    default:
      return false;
  }
}

// A tier wins over its boolean; with no tier, a true boolean counts as standard.
const tierOn = (tier: EnvAccess['query_tier'], flag: boolean): boolean =>
  tier !== undefined ? tier !== 'none' : flag;

export function envCaps(me: Me, envUuid: string): EnvCaps {
  if (!me) return { view: false, query: false, carve: false, manage: false };
  if (me.admin) return { view: true, query: true, carve: true, manage: true };
  const a = me.permissions?.[envUuid];
  if (a?.admin) return { view: true, query: true, carve: true, manage: true };
  const query = !!a && tierOn(a.query_tier, a.query);
  const carve = !!a && tierOn(a.carve_tier, a.carve);
  return {
    view: isReadOnlyAdmin(me) || !!a?.user || query || carve,
    query,
    carve,
    manage: false,
  };
}

// Mirrors the server's canLogContentRule: superuser, or env admin / full query tier in that
// environment. Never for all-environments rules (no env), so non-superusers get false.
export function canLogContentRule(me: Me, envUuid: string | null | undefined): boolean {
  if (!me) return false;
  if (me.admin) return true;
  if (!envUuid) return false;
  const a = me.permissions?.[envUuid];
  return !!a && (a.admin || a.query_tier === 'full');
}
