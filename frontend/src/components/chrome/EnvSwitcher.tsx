/**
 * EnvSwitcher — environment selector backed by the real /api/v1/environments
 * endpoint. The UUID is what we navigate to (env routes are keyed by UUID
 * to match the API surface), and the dropdown shows the human-friendly name.
 *
 * On navigation we resolve the current `env` path param against the env list
 * and highlight it. Falls back to a "(select)" placeholder when no env is
 * selected (e.g. on /_app, /_app/environments).
 */
import { useNavigate, useParams, useRouterState } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { cn } from '$/lib/cn';
import { DropdownMenu } from '$/components/primitives/DropdownMenu';
import { listEnvironments, type TLSEnvironment } from '$/api/environments';
import { isAuthenticated } from '$/api/client';

export function EnvSwitcher({ compact }: { compact?: boolean } = {}) {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const routerState = useRouterState();
  const currentEnv = (params as { env?: string }).env;

  const { data, isLoading } = useQuery({
    queryKey: ['environments-switcher'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
    enabled: isAuthenticated(),
  });

  const envs: TLSEnvironment[] = data ?? [];
  // The URL env param may be either the env name (what the SideNav links emit)
  // or the env UUID (legacy callers). Try both so the active row highlights
  // correctly regardless of which form is in the URL.
  const active = envs.find((e) => e.name === currentEnv || e.uuid === currentEnv);

  function handleSelect(envName: string) {
    // Send the user to the same logical page on the new env when possible.
    // We pass the env *name* in the URL (not UUID) for symmetry with SideNav
    // and for human readability; the API resolves both since the path-param
    // env now goes through Envs.Get(envVar) which accepts name OR UUID.
    const pathname = routerState.location.pathname;
    const match = pathname.match(/^\/_app\/env\/[^/]+\/(.*)$/);
    // If we're at /_app/env/{env} (dashboard, no sub-route), stay at the
    // dashboard for the new env. Otherwise preserve the sub-route.
    const sub = match?.[1] ? match[1] : '';
    void navigate({ to: sub ? `/_app/env/${envName}/${sub}` : `/_app/env/${envName}` });
  }

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          className={cn(
            'flex items-center gap-2 w-full',
            compact ? 'justify-center' : 'justify-between',
            'px-2 py-1.5 rounded-md text-sm',
            'text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
            'transition-colors duration-[120ms] focus-visible:outline focus-visible:outline-2',
            'focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
          )}
          aria-label="Switch environment"
          title={compact ? `Environment: ${active?.name ?? 'none selected'}` : undefined}
        >
          <span className={cn('flex items-center gap-2 truncate', compact && 'justify-center')}>
            <span
              className={cn(
                'inline-block w-[7px] h-[7px] rounded-full flex-shrink-0',
                active?.accept_enrolls
                  ? 'bg-[color:var(--success)]'
                  : 'bg-[color:var(--text-3)]',
              )}
            />
            <span className={cn('font-medium truncate', compact && 'sr-only')}>
              {active?.name ?? (isLoading ? 'loading…' : 'select environment')}
            </span>
          </span>
          {!compact && (
            <svg
              className="w-3.5 h-3.5 text-[color:var(--text-3)] flex-shrink-0"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M6 9l6 6 6-6" />
            </svg>
          )}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="start" className="min-w-[200px]">
        <DropdownMenu.Label>Environments</DropdownMenu.Label>
        {envs.length === 0 && !isLoading && (
          <div className="px-2 py-1.5 text-[10px] font-mono-tabular text-[color:var(--text-3)]">
            No environments configured.
          </div>
        )}
        <DropdownMenu.RadioGroup
          value={active?.name ?? currentEnv ?? ''}
          onValueChange={(v) => handleSelect(v)}
        >
          {envs.map((e) => (
            // value=e.name so onValueChange hands the name to handleSelect,
            // matching the URL shape SideNav emits (`/_app/env/{name}/...`).
            <DropdownMenu.RadioItem key={e.uuid} value={e.name}>
              <span className="flex items-center gap-2">
                <span
                  className={cn(
                    'inline-block w-[7px] h-[7px] rounded-full',
                    e.accept_enrolls
                      ? 'bg-[color:var(--success)]'
                      : 'bg-[color:var(--text-3)]',
                  )}
                />
                <span className="font-mono-tabular text-xs">{e.name}</span>
              </span>
            </DropdownMenu.RadioItem>
          ))}
        </DropdownMenu.RadioGroup>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}
