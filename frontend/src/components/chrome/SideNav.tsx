import { Link, useRouterState, useParams } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { Logo } from '$/components/atoms/Logo';
import { EnvSwitcher } from './EnvSwitcher';
import { listEnvironments } from '$/api/environments';
import { getMe } from '$/api/users';
import type { EnvAccess } from '$/api/types';

interface NavItemProps {
  active?: boolean;
  to?: string;
  href?: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}

function NavItem({ active, to, href, icon, children }: NavItemProps) {
  const className = cn(
    'flex items-center gap-2 px-2 py-1.5 rounded-md text-sm',
    'transition-colors duration-[120ms] ease-out',
    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
    active
      ? [
          'text-[color:var(--text-1)]',
          'bg-[linear-gradient(90deg,rgba(var(--halo-r),var(--halo-g),var(--halo-b),0.12),rgba(var(--halo-r),var(--halo-g),var(--halo-b),0)_60%),var(--bg-2)]',
          'shadow-[inset_2px_0_0_var(--signal)]',
        ].join(' ')
      : 'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
  );

  const content = (
    <>
      <span className="w-4 h-4 flex-shrink-0">{icon}</span>
      {children}
    </>
  );

  if (to) {
    return (
      <Link to={to} aria-current={active ? 'page' : undefined} className={className}>
        {content}
      </Link>
    );
  }

  return (
    <a
      href={href ?? '#'}
      aria-current={active ? 'page' : undefined}
      className={className}
    >
      {content}
    </a>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-2 py-1 text-[10px] font-mono-tabular uppercase tracking-[0.12em] text-[color:var(--text-3)] select-none">
      {children}
    </div>
  );
}

export function SideNav() {
  const routerState = useRouterState();
  const pathname = routerState.location.pathname;
  const params = useParams({ strict: false });
  // Pick the env scope for the nav links:
  //  1. URL param wins when present (you're already inside an env).
  //  2. Otherwise (dashboard, profile, environments, etc.) fall back to the
  //     first env returned by listEnvironments — same React Query cache the
  //     EnvSwitcher consumes, so this is free if the dropdown was opened.
  //  3. Final fallback is the literal "dev" only because the compose stack
  //     ships exactly that env; in production it's just a placeholder until
  //     the env list arrives.
  const { data: envs } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
  });
  const urlEnv = (params as { env?: string }).env;
  const currentEnv = urlEnv ?? envs?.[0]?.name ?? 'dev';

  // Resolve "who am I" + my per-env access map. Drives the nav
  // gating: items the operator has no access to are hidden. Super-
  // admins see everything (server-side CheckPermissions bypasses
  // per-env rows for AdminLevel + NoEnvironment).
  //
  // Cache shared with the /_app layout route (same query key).
  const { data: me } = useQuery({
    queryKey: ['users-me'],
    queryFn: () => getMe(),
    staleTime: 5 * 60_000,
    retry: 1,
  });
  const isSuperAdmin = me?.admin === true;
  // currentEnv is the SPA's name-of-env; permissions are keyed by
  // env UUID. We need to translate name → UUID via the envs list.
  // Fall back to "no access" when the lookup hasn't resolved yet.
  const envUuid = envs?.find((e) => e.name === currentEnv)?.uuid;
  const myEnvAccess: EnvAccess | undefined =
    envUuid ? me?.permissions?.[envUuid] : undefined;
  // Super-admins bypass per-env checks. For everyone else, "can see
  // this env's surface at all" requires env.user OR env.admin
  // (mirrors the server's CheckPermissions logic for read-only
  // surfaces). Without a permission map we hide everything env-
  // scoped — the safe default that matches the server's posture.
  const canSeeEnv = isSuperAdmin || !!myEnvAccess?.user || !!myEnvAccess?.admin;
  const canQuery = isSuperAdmin || !!myEnvAccess?.query;
  const canCarve = isSuperAdmin || !!myEnvAccess?.carve;
  const canManageEnv = isSuperAdmin || !!myEnvAccess?.admin;

  // Env-scoped routes live under /_app/env/{env}/... per
  // frontend/src/routes/_app/env/$env/*.tsx — the "_app" prefix is the
  // auth-gated layout. Omitting it produces unrouted URLs that fall through
  // to a 404 page.
  const nodesPath = `/_app/env/${currentEnv}/nodes`;
  const isNodesActive = pathname.startsWith(`/_app/env/${currentEnv}/nodes`);
  const queriesPath = `/_app/env/${currentEnv}/queries`;
  const savedQueriesPath = `/_app/env/${currentEnv}/saved-queries`;
  const carvesPath = `/_app/env/${currentEnv}/carves`;
  const tagsPath = `/_app/env/${currentEnv}/tags`;
  const enrollPath = `/_app/env/${currentEnv}/enroll`;
  // Distinguish "/queries" (and its subroutes) from "/saved-queries".
  const isSavedQueriesActive = pathname.startsWith(`/_app/env/${currentEnv}/saved-queries`);
  const isQueriesActive =
    pathname.startsWith(`/_app/env/${currentEnv}/queries`) && !isSavedQueriesActive;
  const isCarvesActive = pathname.startsWith(`/_app/env/${currentEnv}/carves`);
  const isTagsActive = pathname.startsWith(`/_app/env/${currentEnv}/tags`);
  const isEnrollActive = pathname.startsWith(`/_app/env/${currentEnv}/enroll`);
  const isUsersActive = pathname.startsWith('/_app/users') || pathname === '/users';
  const isProfileActive = pathname.startsWith('/_app/profile') || pathname === '/profile';
  const isEnvironmentsActive =
    pathname.startsWith('/_app/environments') || pathname === '/environments';
  const isSettingsActive =
    pathname.startsWith('/_app/settings') || pathname.startsWith('/settings');
  const isAuditActive = pathname.startsWith('/_app/audit') || pathname === '/audit';
  // Match exactly '/' or '/_app/' (the dashboard route) but NOT '/env/...'
  const isDashboardActive = pathname === '/' || pathname === '/_app' || pathname === '/_app/';

  return (
    <aside
      className="w-60 shrink-0 flex flex-col border-r border-[color:var(--border)] px-2 py-3"
      style={{
        background:
          'linear-gradient(180deg, rgba(var(--halo-r), var(--halo-g), var(--halo-b), 0.04) 0%, transparent 280px), var(--bg-0)',
      }}
    >
      {/* Wordmark */}
      <div className="px-2 py-2 flex items-center gap-2.5 mb-4">
        <Logo size={30} decorative />
        <div>
          <div className="font-display text-[15px] font-bold tracking-tight text-[color:var(--text-1)]">
            osctrl
          </div>
          <div className="text-[10px] font-mono-tabular text-[color:var(--text-3)] leading-none mt-0.5">
            CONTROL
          </div>
        </div>
      </div>

      {/* Overview section.
          Each item gates on a specific capability for the current
          env (canSeeEnv / canQuery / canCarve / canManageEnv) so a
          user with limited permissions only sees what they can
          actually use. Super-admins bypass every gate (isSuperAdmin
          short-circuits all of them to true above). */}
      <SectionLabel>Overview</SectionLabel>
      <nav className="space-y-0.5 mb-4">
        <NavItem
          active={isDashboardActive}
          to="/_app/"
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M3 12h6v9H3zM15 3h6v9h-6zM3 3h6v6H3zM15 15h6v6h-6z" />
            </svg>
          }
        >
          Dashboard
        </NavItem>
        {canSeeEnv && (
          <NavItem
            active={isNodesActive}
            to={nodesPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="3" y="4" width="18" height="16" rx="2" />
                <path d="M3 10h18" />
              </svg>
            }
          >
            Nodes
          </NavItem>
        )}
        {canQuery && (
          <NavItem
            active={isQueriesActive}
            to={queriesPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" />
              </svg>
            }
          >
            Queries
          </NavItem>
        )}
        {canQuery && (
          <NavItem
            active={isSavedQueriesActive}
            to={savedQueriesPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z" />
              </svg>
            }
          >
            Saved
          </NavItem>
        )}
        {canCarve && (
          <NavItem
            active={isCarvesActive}
            to={carvesPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M3 7h18v10a2 2 0 01-2 2H5a2 2 0 01-2-2zM3 7l3-3h12l3 3" />
              </svg>
            }
          >
            Carves
          </NavItem>
        )}
        {canManageEnv && (
          <NavItem
            active={isTagsActive}
            to={tagsPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z" />
              </svg>
            }
          >
            Tags
          </NavItem>
        )}
        {canManageEnv && (
          <NavItem
            active={isEnrollActive}
            to={enrollPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                {/* download-arrow into-a-tray glyph — fits the "install scripts" theme */}
                <path d="M12 4v12m0 0l-4-4m4 4l4-4M4 18v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
              </svg>
            }
          >
            Enrollment
          </NavItem>
        )}
        {isSuperAdmin && (
          <NavItem
            active={isAuditActive}
            to="/_app/audit"
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M2 12h20M12 2a15 15 0 010 20M12 2a15 15 0 000 20" />
              </svg>
            }
          >
            Audit Trail
          </NavItem>
        )}
      </nav>

      {/* Environments section */}
      <div className="flex items-center justify-between px-2 py-1">
        <span className="text-[10px] font-mono-tabular uppercase tracking-[0.12em] text-[color:var(--text-3)] select-none">
          Environments
        </span>
      </div>
      <div className="mb-4">
        <EnvSwitcher />
      </div>

      {/* Admin section.
          Operators / Environments / Settings are super-admin only —
          they touch deployment-wide state. Profile stays visible for
          everyone because it's "my own account" — every user can
          change their email/password.
          The "Admin" section label itself is hidden when nothing
          inside it would render except Profile (a non-admin user
          shouldn't see an "Admin" header just for their profile
          link). Move Profile into its own footer-y group for the
          non-admin case. */}
      {isSuperAdmin ? (
        <>
          <SectionLabel>Admin</SectionLabel>
          <nav className="space-y-0.5">
            <NavItem
              active={isUsersActive}
              to="/_app/users"
              icon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="9" cy="7" r="4" />
                  <path d="M3 21v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
                </svg>
              }
            >
              Operators
            </NavItem>
            <NavItem
              active={isProfileActive}
              to="/_app/profile"
              icon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="12" cy="8" r="4" />
                  <path d="M4 21v-2a4 4 0 014-4h8a4 4 0 014 4v2" />
                </svg>
              }
            >
              Profile
            </NavItem>
            <NavItem
              active={isEnvironmentsActive}
              to="/_app/environments"
              icon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <rect x="3" y="3" width="18" height="18" rx="2" />
                  <path d="M3 9h18" />
                </svg>
              }
            >
              Environments
            </NavItem>
            <NavItem
              active={isSettingsActive}
              to="/_app/settings/admin"
              icon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              }
            >
              Settings
            </NavItem>
          </nav>
        </>
      ) : (
        <nav className="space-y-0.5">
          <NavItem
            active={isProfileActive}
            to="/_app/profile"
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="8" r="4" />
                <path d="M4 21v-2a4 4 0 014-4h8a4 4 0 014 4v2" />
              </svg>
            }
          >
            Profile
          </NavItem>
        </nav>
      )}
    </aside>
  );
}
