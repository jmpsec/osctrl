import { describe, expect, it } from 'vitest';
import type { EnvAccess, UserMeResponse } from '$/api/types';
import { canLogContentRule, canSeePage, canWritePage, envCaps, isReadOnlyAdmin, isSuperuser, type Page } from './access';

const PAGES: Page[] = [
  'users', 'environments', 'settings', 'serviceConfig', 'logSinks', 'extensions',
  'osqueryVersions', 'authProviders', 'alerts', 'health', 'auditAll', 'vulnFeeds',
];

const acc = (o: Partial<EnvAccess> = {}): EnvAccess => ({ user: false, query: false, carve: false, admin: false, ...o });

function me(o: Partial<UserMeResponse> = {}): UserMeResponse {
  return {
    username: 'u', email: '', fullname: '', admin: false, user_admin: false, env_manager: false,
    read_only_admin: false, alert_admin: false, service: false, uuid: '', token_expire: '',
    last_access: '', preferred_language: '', permissions: {}, ...o,
  };
}

describe('page access', () => {
  const cases: { name: string; me: UserMeResponse | undefined; see: Page[]; write: Page[] }[] = [
    { name: 'superuser', me: me({ admin: true }), see: PAGES, write: PAGES },
    { name: 'user_admin', me: me({ user_admin: true }), see: ['users', 'environments', 'alerts', 'health', 'auditAll', 'vulnFeeds'], write: ['users'] },
    { name: 'env_manager', me: me({ env_manager: true }), see: ['users', 'environments', 'alerts', 'health', 'auditAll', 'vulnFeeds'], write: ['environments'] },
    { name: 'alert_admin', me: me({ alert_admin: true }), see: ['alerts'], write: ['alerts'] },
    { name: 'read_only_admin', me: me({ read_only_admin: true }), see: ['users', 'environments', 'alerts', 'health', 'auditAll', 'vulnFeeds'], write: [] },
    { name: 'plain user', me: me(), see: [], write: [] },
    { name: 'undefined', me: undefined, see: [], write: [] },
  ];
  for (const c of cases) {
    it(c.name, () => {
      for (const p of PAGES) {
        expect(canSeePage(c.me, p), `see ${p}`).toBe(c.see.includes(p));
        expect(canWritePage(c.me, p), `write ${p}`).toBe(c.write.includes(p));
      }
    });
  }
  it('role helpers', () => {
    expect(isSuperuser(me({ admin: true }))).toBe(true);
    expect(isSuperuser(undefined)).toBe(false);
    expect(isReadOnlyAdmin(me({ env_manager: true }))).toBe(true);
    expect(isReadOnlyAdmin(me())).toBe(false);
  });
});

describe('envCaps', () => {
  const none = { view: false, query: false, carve: false, manage: false };
  const all = { view: true, query: true, carve: true, manage: true };
  const withEnv = (a: EnvAccess, o: Partial<UserMeResponse> = {}) => me({ permissions: { e1: a }, ...o });
  const cases: { name: string; me: UserMeResponse | undefined; env: string; want: typeof none }[] = [
    { name: 'superuser, unknown env', me: me({ admin: true }), env: 'zz', want: all },
    { name: 'env admin', me: withEnv(acc({ admin: true })), env: 'e1', want: all },
    { name: 'tags tier', me: withEnv(acc({ query_tier: 'tags' })), env: 'e1', want: { ...none, view: true, query: true } },
    { name: 'bool without tier', me: withEnv(acc({ query: true })), env: 'e1', want: { ...none, view: true, query: true } },
    { name: 'tier none beats bool', me: withEnv(acc({ query: true, query_tier: 'none' })), env: 'e1', want: none },
    { name: 'carve tier full', me: withEnv(acc({ carve_tier: 'full' })), env: 'e1', want: { ...none, view: true, carve: true } },
    { name: 'read-only, no row', me: me({ read_only_admin: true }), env: 'e1', want: { ...none, view: true } },
    { name: 'user only', me: withEnv(acc({ user: true })), env: 'e1', want: { ...none, view: true } },
    { name: 'unknown env', me: withEnv(acc({ admin: true })), env: 'e2', want: none },
    { name: 'undefined me', me: undefined, env: 'e1', want: none },
  ];
  for (const c of cases) it(c.name, () => expect(envCaps(c.me, c.env)).toEqual(c.want));
});

describe('canLogContentRule', () => {
  const withEnv = (a: EnvAccess, o: Partial<UserMeResponse> = {}) => me({ permissions: { e1: a }, ...o });
  it.each([
    ['superuser, no env', me({ admin: true }), null, true],
    ['alert admin, all envs', me({ alert_admin: true }), null, false],
    ['alert admin, empty uuid', withEnv(acc({ admin: true })), '', false],
    ['env admin', withEnv(acc({ admin: true })), 'e1', true],
    ['full query tier', withEnv(acc({ query_tier: 'full' })), 'e1', true],
    ['standard query tier', withEnv(acc({ query_tier: 'standard' })), 'e1', false],
    ['legacy query bool only', withEnv(acc({ query: true })), 'e1', false],
    ['other env', withEnv(acc({ admin: true })), 'e2', false],
    ['read-only admin', me({ read_only_admin: true }), 'e1', false],
    ['undefined me', undefined, 'e1', false],
  ])('%s', (_n, m, env, want) => expect(canLogContentRule(m, env)).toBe(want));
});
