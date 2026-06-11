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
  collapsed?: boolean;
  children: React.ReactNode;
}

function NavItem({ active, to, href, icon, collapsed, children }: NavItemProps) {
  const className = cn(
    'flex items-center gap-2 px-2 py-1.5 rounded-md text-sm',
    collapsed && 'justify-center',
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

  // In collapsed (icon-rail) mode the label moves to a native tooltip +
  // sr-only text, so the item stays accessible and hover-discoverable.
  const title = collapsed && typeof children === 'string' ? children : undefined;
  const content = (
    <>
      <span className="w-4 h-4 flex-shrink-0">{icon}</span>
      <span className={collapsed ? 'sr-only' : undefined}>{children}</span>
    </>
  );

  if (to) {
    return (
      <Link to={to} aria-current={active ? 'page' : undefined} className={className} title={title}>
        {content}
      </Link>
    );
  }

  return (
    <a
      href={href ?? '#'}
      aria-current={active ? 'page' : undefined}
      className={className}
      title={title}
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

interface SideNavProps {
  className?: string;
  /** Desktop icon-rail mode: labels collapse to tooltips, rail narrows. */
  collapsed?: boolean;
  /** Renders the collapse/expand chevron at the rail's foot when provided. */
  onToggleCollapse?: () => void;
}

export function SideNav({ className, collapsed, onToggleCollapse }: SideNavProps = {}) {
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
  const configPath = `/_app/env/${currentEnv}/config`;
  // Distinguish "/queries" (and its subroutes) from "/saved-queries".
  const isSavedQueriesActive = pathname.startsWith(`/_app/env/${currentEnv}/saved-queries`);
  const isQueriesActive =
    pathname.startsWith(`/_app/env/${currentEnv}/queries`) && !isSavedQueriesActive;
  const isCarvesActive = pathname.startsWith(`/_app/env/${currentEnv}/carves`);
  const isTagsActive = pathname.startsWith(`/_app/env/${currentEnv}/tags`);
  const isEnrollActive = pathname.startsWith(`/_app/env/${currentEnv}/enroll`);
  const isConfigActive = pathname.startsWith(`/_app/env/${currentEnv}/config`);
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
      // The .sidenav-circuit class (base.css) layers the legacy circuit
      // SVG behind the rail content. Background-image inherits the
      // brand teal at theme-tuned alpha so dark and light read at
      // similar density. The teal sheen from the previous background
      // gradient is preserved via the linear-gradient layered on top
      // of the SVG — the SVG sits at the bottom of the stack.
      className={cn(
        'sidenav-circuit relative shrink-0 flex flex-col border-r border-[color:var(--border)] px-2 py-3',
        'transition-[width] duration-200 ease-out',
        collapsed ? 'w-14' : 'w-60',
        className,
      )}
    >
      {/* Wordmark — mirrors the login card header (stacked logo +
          "osctrl" wordmark + "OSQUERY CONTROL" tagline) so the brand
          presentation stays consistent between the unauth surface and
          the app shell. Font sizes are tuned down a step versus the
          login card because the sidenav rail is narrower (~240px). */}
      <div className="flex flex-col items-center px-2 py-3 mb-4">
        <Logo size={collapsed ? 28 : 40} decorative />
        {!collapsed && (
          <>
            <div className="mt-2 font-wordmark text-lg font-bold tracking-tight text-[color:var(--text-1)] leading-none">
              osctrl
            </div>
            <div className="mt-1 text-[10px] font-mono-tabular text-[color:var(--text-3)] uppercase tracking-[0.1em] leading-none">
              Osquery Control
            </div>
          </>
        )}
      </div>

      {/* Overview section.
          Each item gates on a specific capability for the current
          env (canSeeEnv / canQuery / canCarve / canManageEnv) so a
          user with limited permissions only sees what they can
          actually use. Super-admins bypass every gate (isSuperAdmin
          short-circuits all of them to true above). */}
      {collapsed ? (
        <div className="mx-2 mb-2 border-t border-[color:var(--border)]" aria-hidden />
      ) : (
        <SectionLabel>Overview</SectionLabel>
      )}
      <nav className="space-y-0.5 mb-4">
        <NavItem
          collapsed={collapsed}
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
            collapsed={collapsed}
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
            collapsed={collapsed}
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
            collapsed={collapsed}
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
            collapsed={collapsed}
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
            collapsed={collapsed}
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
            collapsed={collapsed}
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
        {canManageEnv && (
          <NavItem
            collapsed={collapsed}
            active={isConfigActive}
            to={configPath}
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                {/* settings-cog glyph — config covers pull intervals,
                    expiration, and the six osquery config sections. */}
                <circle cx="12" cy="12" r="3" />
                <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
              </svg>
            }
          >
            Configuration
          </NavItem>
        )}
        {/* Audit Trail is visible to everyone. Super-admins see all
            operator activity; non-admins see only their own (the api
            force-clamps the username filter to the requester
            server-side). The label changes to reflect that scope. */}
        <NavItem
          collapsed={collapsed}
          active={isAuditActive}
          to="/_app/audit"
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <path d="M2 12h20M12 2a15 15 0 010 20M12 2a15 15 0 000 20" />
            </svg>
          }
        >
          {isSuperAdmin ? 'Audit Trail' : 'My Activity'}
        </NavItem>
      </nav>

      {/* Environments section */}
      {collapsed ? (
        <div className="mx-2 mb-2 border-t border-[color:var(--border)]" aria-hidden />
      ) : (
        <div className="flex items-center justify-between px-2 py-1">
          <span className="text-[10px] font-mono-tabular uppercase tracking-[0.12em] text-[color:var(--text-3)] select-none">
            Environments
          </span>
        </div>
      )}
      <div className="mb-4">
        <EnvSwitcher compact={collapsed} />
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
          {collapsed ? (
            <div className="mx-2 mb-2 border-t border-[color:var(--border)]" aria-hidden />
          ) : (
            <SectionLabel>Admin</SectionLabel>
          )}
          <nav className="space-y-0.5">
            <NavItem
              collapsed={collapsed}
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
              collapsed={collapsed}
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
              collapsed={collapsed}
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
              collapsed={collapsed}
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
            collapsed={collapsed}
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

      {/* Collapse toggle — desktop rail only (the mobile drawer never
          passes onToggleCollapse; it always renders full width).
          Floats on the rail's right border at mid-height so it's
          reachable without scrolling regardless of nav length. */}
      {onToggleCollapse && (
        <button
          type="button"
          onClick={onToggleCollapse}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          className={cn(
            'absolute top-1/2 -translate-y-1/2 -right-3 z-20',
            'w-6 h-6 rounded-full flex items-center justify-center',
            'border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:border-[color:var(--signal)]',
            'shadow-[0_1px_4px_rgba(0,0,0,0.25)]',
            'transition-colors duration-[120ms]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          <svg
            className={cn('w-3.5 h-3.5 transition-transform duration-200', collapsed && 'rotate-180')}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M14 17l-5-5 5-5" />
          </svg>
        </button>
      )}
    </aside>
  );
}
