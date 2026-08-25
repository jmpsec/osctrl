import { useEffect, useRef, useState } from 'react';
import { Link, useRouterState, useParams } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Archive,
  Bookmark,
  Boxes,
  DatabaseBackup,
  Download,
  FileSearch,
  FileStack,
  LayoutDashboard,
  ListChecks,
  Monitor,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Tag,
  UserRound,
  Users,
} from 'lucide-react';
import { cn } from '$/lib/cn';
import { Logo } from '$/components/atoms/Logo';
import { EnvSwitcher } from './EnvSwitcher';
import { listEnvironments } from '$/api/environments';
import { getMe } from '$/api/users';
import { getFeatures } from '$/api/features';
import type { EnvAccess } from '$/api/types';
import { readActiveEnvironment, writeActiveEnvironment } from '$/lib/environment-scope';
import {
  SIDE_NAV_PREVIEW_ID,
  SideNavPreview,
  type SideNavPreviewKind,
} from './SideNavPreview';

interface NavItemProps {
  active?: boolean;
  to?: string;
  href?: string;
  icon: React.ReactNode;
  tone?: NavIconTone;
  collapsed?: boolean;
  previewExpanded?: boolean;
  children: React.ReactNode;
}

type NavIconTone =
  | 'blue'
  | 'sky'
  | 'teal'
  | 'violet'
  | 'rose'
  | 'green'
  | 'amber'
  | 'neutral';

const navIconToneVariables: Record<NavIconTone, string> = {
  blue: 'var(--accent)',
  sky: 'var(--info)',
  teal: 'var(--nav-teal)',
  violet: 'var(--nav-violet)',
  rose: 'var(--nav-rose)',
  green: 'var(--success)',
  amber: 'var(--warning)',
  neutral: 'var(--text-2)',
};

function NavItem({
  active,
  to,
  href,
  icon,
  tone = 'neutral',
  collapsed,
  previewExpanded,
  children,
}: NavItemProps) {
  const className = cn(
    'flex h-7 items-center gap-2 rounded-md px-1.5 text-[13px] font-medium',
    collapsed && 'justify-center',
    'transition-colors duration-[100ms] ease-out',
    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--accent)]',
    active
      ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]'
      : 'text-[color:var(--text-2)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
  );

  // In collapsed (icon-rail) mode the label moves to a native tooltip +
  // sr-only text, so the item stays accessible and hover-discoverable.
  const title = collapsed && typeof children === 'string' ? children : undefined;
  const iconColor = navIconToneVariables[tone];
  const content = (
    <>
      <span
        className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-[5px] border"
        style={{
          color: iconColor,
          backgroundColor: `color-mix(in srgb, ${iconColor} ${active ? 16 : 11}%, transparent)`,
          borderColor: `color-mix(in srgb, ${iconColor} 24%, transparent)`,
        }}
        aria-hidden
      >
        {icon}
      </span>
      <span className={collapsed ? 'sr-only' : undefined}>{children}</span>
    </>
  );

  if (to) {
    return (
      <Link
        to={to}
        aria-current={active ? 'page' : undefined}
        aria-expanded={previewExpanded}
        aria-controls={previewExpanded !== undefined ? SIDE_NAV_PREVIEW_ID : undefined}
        className={className}
        title={title}
      >
        {content}
      </Link>
    );
  }

  return (
    <a
      href={href ?? '#'}
      aria-current={active ? 'page' : undefined}
      aria-expanded={previewExpanded}
      aria-controls={previewExpanded !== undefined ? SIDE_NAV_PREVIEW_ID : undefined}
      className={className}
      title={title}
    >
      {content}
    </a>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-1.5 py-1 text-xs font-medium text-[color:var(--text-3)] select-none">
      {children}
    </div>
  );
}

interface SideNavProps {
  className?: string;
  /** Desktop icon-rail mode: labels collapse to tooltips, rail narrows. */
  collapsed?: boolean;
  /** Context previews are desktop-only; the mobile drawer navigates directly. */
  previewsEnabled?: boolean;
}

interface OpenPreview {
  kind: SideNavPreviewKind;
  anchor: { top: number; right: number };
  focusFirstItem: boolean;
}

export function SideNav({ className, collapsed, previewsEnabled = true }: SideNavProps = {}) {
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
  const currentEnv = urlEnv ?? readActiveEnvironment() ?? envs?.[0]?.name ?? 'dev';

  useEffect(() => {
    if (urlEnv) writeActiveEnvironment(urlEnv);
  }, [urlEnv]);

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
  // Service Config is opt-in server-side (service.serviceConfigEnabled).
  // When it is off the endpoints do not exist, so hide the entry rather
  // than link to a page that can only fail.
  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  // currentEnv is the SPA's name-of-env; permissions are keyed by
  // env UUID. We need to translate name → UUID via the envs list.
  // Fall back to "no access" when the lookup hasn't resolved yet.
  const envUuid = envs?.find(
    (e) => e.name === currentEnv || e.uuid === currentEnv,
  )?.uuid;
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
  const isServiceConfigActive =
    pathname.startsWith('/_app/config') || pathname.startsWith('/config');
  const isLogSinksActive =
    pathname.startsWith('/_app/log-sinks') || pathname.startsWith('/log-sinks');
  const isAuthProvidersActive =
    pathname.startsWith('/_app/auth-providers') || pathname.startsWith('/auth-providers');
  const isAuditActive = pathname.startsWith('/_app/audit') || pathname === '/audit';
  // Dashboard is now env-scoped at /_app/env/{env}
  const dashboardPath = `/_app/env/${currentEnv}`;
  const isDashboardActive = pathname === dashboardPath || pathname === dashboardPath + '/';

  const [preview, setPreview] = useState<OpenPreview | null>(null);
  const openTimer = useRef<number | null>(null);
  const closeTimer = useRef<number | null>(null);
  const previewTrigger = useRef<HTMLAnchorElement | null>(null);

  function clearOpenTimer() {
    if (openTimer.current != null) window.clearTimeout(openTimer.current);
    openTimer.current = null;
  }

  function clearCloseTimer() {
    if (closeTimer.current != null) window.clearTimeout(closeTimer.current);
    closeTimer.current = null;
  }

  function openPreview(
    kind: SideNavPreviewKind,
    triggerContainer: HTMLElement,
    options: { immediate?: boolean; focusFirstItem?: boolean } = {},
  ) {
    if (!previewsEnabled) return;
    clearOpenTimer();
    clearCloseTimer();
    const show = () => {
      const rect = triggerContainer.getBoundingClientRect();
      previewTrigger.current = triggerContainer.querySelector('a');
      setPreview({
        kind,
        anchor: { top: rect.top, right: rect.right },
        focusFirstItem: options.focusFirstItem ?? false,
      });
    };
    if (options.immediate) show();
    else openTimer.current = window.setTimeout(show, 140);
  }

  function schedulePreviewClose() {
    clearOpenTimer();
    clearCloseTimer();
    closeTimer.current = window.setTimeout(() => setPreview(null), 220);
  }

  function dismissPreview({ restoreFocus = false } = {}) {
    clearOpenTimer();
    clearCloseTimer();
    setPreview(null);
    if (restoreFocus) previewTrigger.current?.focus();
  }

  function previewTriggerProps(kind: SideNavPreviewKind) {
    return {
      onMouseEnter: (event: React.MouseEvent<HTMLDivElement>) => openPreview(kind, event.currentTarget),
      onMouseLeave: schedulePreviewClose,
      onFocus: (event: React.FocusEvent<HTMLDivElement>) => {
        openPreview(kind, event.currentTarget, { immediate: true });
      },
      onBlur: schedulePreviewClose,
      onKeyDown: (event: React.KeyboardEvent<HTMLDivElement>) => {
        if (event.key === 'ArrowRight') {
          event.preventDefault();
          openPreview(kind, event.currentTarget, { immediate: true, focusFirstItem: true });
        }
        if (event.key === 'Escape' && preview?.kind === kind) {
          event.preventDefault();
          dismissPreview();
        }
      },
    };
  }

  useEffect(() => {
    dismissPreview();
  }, [pathname, currentEnv]);

  useEffect(() => () => {
    clearOpenTimer();
    clearCloseTimer();
  }, []);

  return (
    <aside
      className={cn(
        'side-nav-circuit relative shrink-0 flex min-h-0 flex-col overflow-y-auto bg-[color:var(--bg-0)] px-2 py-2',
        'transition-[width] duration-200 ease-out',
        collapsed ? 'w-14' : 'w-60',
        className,
      )}
    >
      <div className={cn('mb-2 flex h-9 items-center gap-2 px-1.5', collapsed && 'justify-center px-0')}>
        <Logo size={24} decorative />
        {!collapsed && (
          <div className="font-wordmark text-[15px] font-semibold text-[color:var(--text-1)]">
            osctrl
          </div>
        )}
      </div>

      {/* Environment is the primary navigation scope. Keep it adjacent to
          the product identity so every destination below reads as operating
          within this selection. */}
      <div className={cn('mb-3', collapsed ? 'px-1' : 'px-0.5')}>
        <EnvSwitcher compact={collapsed} />
      </div>

      {/* Environment workspace section.
          Each item gates on a specific capability for the current
          env (canSeeEnv / canQuery / canCarve / canManageEnv) so a
          user with limited permissions only sees what they can
          actually use. Super-admins bypass every gate (isSuperAdmin
          short-circuits all of them to true above). */}
      {collapsed ? (
        <div className="mx-2 mb-2 border-t border-[color:var(--border)]" aria-hidden />
      ) : (
        <SectionLabel>Workspace</SectionLabel>
      )}
      <nav className="space-y-0.5 mb-3">
        <NavItem
          collapsed={collapsed}
          active={isDashboardActive}
          to={dashboardPath}
          tone="blue"
          icon={<LayoutDashboard size={14} strokeWidth={1.8} />}
        >
          Dashboard
        </NavItem>
        {canSeeEnv && (
          <div {...previewTriggerProps('nodes')}>
            <NavItem
              collapsed={collapsed}
              active={isNodesActive}
              to={nodesPath}
              tone="sky"
              icon={<Monitor size={14} strokeWidth={1.8} />}
              previewExpanded={preview?.kind === 'nodes'}
            >
              Nodes
            </NavItem>
          </div>
        )}
        {canQuery && (
          <div {...previewTriggerProps('queries')}>
            <NavItem
              collapsed={collapsed}
              active={isQueriesActive}
              to={queriesPath}
              tone="violet"
              icon={<FileSearch size={14} strokeWidth={1.8} />}
              previewExpanded={preview?.kind === 'queries'}
            >
              Queries
            </NavItem>
          </div>
        )}
        {canQuery && (
          <NavItem
            collapsed={collapsed}
            active={isSavedQueriesActive}
            to={savedQueriesPath}
            tone="amber"
            icon={<Bookmark size={14} strokeWidth={1.8} />}
          >
            Saved
          </NavItem>
        )}
        {canCarve && (
          <NavItem
            collapsed={collapsed}
            active={isCarvesActive}
            to={carvesPath}
            tone="rose"
            icon={<DatabaseBackup size={14} strokeWidth={1.8} />}
          >
            Carves
          </NavItem>
        )}
        {canManageEnv && (
          <NavItem
            collapsed={collapsed}
            active={isTagsActive}
            to={tagsPath}
            tone="green"
            icon={<Tag size={14} strokeWidth={1.8} />}
          >
            Tags
          </NavItem>
        )}
        {canManageEnv && (
          <NavItem
            collapsed={collapsed}
            active={isEnrollActive}
            to={enrollPath}
            tone="teal"
            icon={<Download size={14} strokeWidth={1.8} />}
          >
            Enrollment
          </NavItem>
        )}
        {canManageEnv && (
          <NavItem
            collapsed={collapsed}
            active={isConfigActive}
            to={configPath}
            tone="neutral"
            icon={<SlidersHorizontal size={14} strokeWidth={1.8} />}
          >
            Configuration
          </NavItem>
        )}
      </nav>

      {/* Organization-wide activity is intentionally separated from the
          environment workspace above; changing environments does not scope
          this destination. */}
      {collapsed ? (
        <div className="mx-2 mb-2 border-t border-[color:var(--border)]" aria-hidden />
      ) : (
        <SectionLabel>Organization</SectionLabel>
      )}
      <nav className="mb-3 space-y-0.5">
        <NavItem
          collapsed={collapsed}
          active={isAuditActive}
          to="/_app/audit"
          tone="amber"
          icon={<ListChecks size={14} strokeWidth={1.8} />}
        >
          {isSuperAdmin ? 'Audit Trail' : 'My Activity'}
        </NavItem>
      </nav>

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
              tone="violet"
              icon={<Users size={14} strokeWidth={1.8} />}
            >
              Operators
            </NavItem>
            <NavItem
              collapsed={collapsed}
              active={isProfileActive}
              to="/_app/profile"
              tone="sky"
              icon={<UserRound size={14} strokeWidth={1.8} />}
            >
              Profile
            </NavItem>
            <NavItem
              collapsed={collapsed}
              active={isEnvironmentsActive}
              to="/_app/environments"
              tone="green"
              icon={<Boxes size={14} strokeWidth={1.8} />}
            >
              Environments
            </NavItem>
            <NavItem
              collapsed={collapsed}
              active={isSettingsActive}
              to="/_app/settings/api"
              tone="neutral"
              icon={<Settings size={14} strokeWidth={1.8} />}
            >
              Settings
            </NavItem>
            {features?.service_config && <NavItem
              collapsed={collapsed}
              active={isServiceConfigActive}
              to="/_app/config/api"
              tone="blue"
              icon={<Archive size={14} strokeWidth={1.8} />}
            >
              Service Config
            </NavItem>}
            {features?.log_sinks && <NavItem
              collapsed={collapsed}
              active={isLogSinksActive}
              to="/_app/log-sinks"
              tone="teal"
              icon={<FileStack size={14} strokeWidth={1.8} />}
            >
              Log Sinks
            </NavItem>}
            {features?.auth_providers && <NavItem
              collapsed={collapsed}
              active={isAuthProvidersActive}
              to="/_app/auth-providers"
              tone="rose"
              icon={<ShieldCheck size={14} strokeWidth={1.8} />}
            >
              Auth Providers
            </NavItem>}
          </nav>
        </>
      ) : (
        <nav className="space-y-0.5">
          <NavItem
            collapsed={collapsed}
            active={isProfileActive}
            to="/_app/profile"
            tone="sky"
            icon={<UserRound size={14} strokeWidth={1.8} />}
          >
            Profile
          </NavItem>
        </nav>
      )}
      {preview && (
        <SideNavPreview
          kind={preview.kind}
          env={currentEnv}
          anchor={preview.anchor}
          focusFirstItem={preview.focusFirstItem}
          onDismiss={() => dismissPreview({ restoreFocus: true })}
          onInteractionStart={clearCloseTimer}
          onInteractionEnd={schedulePreviewClose}
        />
      )}
    </aside>
  );
}
