/**
 * EnvSwitcher — environment selector backed by the real /api/v1/environments
 * endpoint. Routes use the human-friendly environment name while the API
 * continues to resolve either names or UUIDs.
 *
 * On navigation we resolve the current `env` path param against the env list
 * and highlight it. On global routes it keeps the last selected environment,
 * so every environment-scoped navigation item continues to target that scope.
 */
import { useEffect } from 'react';
import { useNavigate, useParams, useRouterState } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { Boxes, ChevronsUpDown } from 'lucide-react';
import { cn } from '$/lib/cn';
import { DropdownMenu } from '$/components/primitives/DropdownMenu';
import { listEnvironments, type TLSEnvironment } from '$/api/environments';
import { isAuthenticated } from '$/api/client';
import { readActiveEnvironment, writeActiveEnvironment } from '$/lib/environment-scope';

export function EnvSwitcher({ compact }: { compact?: boolean } = {}) {
  const navigate = useNavigate();
  const params = useParams({ strict: false });
  const routerState = useRouterState();
  const currentEnv = (params as { env?: string }).env;

  const { data, isLoading } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
    enabled: isAuthenticated(),
  });

  const envs: TLSEnvironment[] = data ?? [];
  // The URL env param may be either the env name (what the SideNav links emit)
  // or the env UUID (legacy callers). Try both so the active row highlights
  // correctly regardless of which form is in the URL.
  const storedEnv = readActiveEnvironment();
  const activeScope = currentEnv ?? storedEnv;
  const active = envs.find((e) => e.name === activeScope || e.uuid === activeScope);

  useEffect(() => {
    if (currentEnv) writeActiveEnvironment(currentEnv);
  }, [currentEnv]);

  function handleSelect(envName: string) {
    // Send the user to the same logical page on the new env when possible.
    // We pass the env *name* in the URL (not UUID) for symmetry with SideNav
    // and for human readability; the API resolves both since the path-param
    // env now goes through Envs.Get(envVar) which accepts name OR UUID.
    writeActiveEnvironment(envName);
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
            'flex w-full items-center text-left',
            compact ? 'h-8 justify-center rounded-md' : 'h-10 gap-2 rounded-lg px-2',
            'border border-[color:var(--border)] bg-[color:var(--bg-1)]',
            'text-[color:var(--text-2)] shadow-[0_1px_1px_rgba(0,0,0,0.03)]',
            'hover:border-[color:var(--border-strong)] hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)]',
            'transition-[background-color,border-color,color] duration-[120ms] focus-visible:outline focus-visible:outline-2',
            'focus-visible:outline-offset-1 focus-visible:outline-[color:var(--accent)]',
          )}
          aria-label={`Switch environment${active?.name ? `, current ${active.name}` : ''}`}
          title={compact ? `Environment: ${active?.name ?? 'none selected'}` : undefined}
        >
          <span className="relative flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-md bg-[color:color-mix(in_srgb,var(--accent)_10%,transparent)] text-[color:var(--accent)]">
            <Boxes size={14} strokeWidth={1.8} aria-hidden />
            <span
              className={cn(
                'absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full border-2 border-[color:var(--bg-1)]',
                active?.accept_enrolls
                  ? 'bg-[color:var(--success)]'
                  : 'bg-[color:var(--text-3)]',
              )}
              aria-hidden
            />
          </span>
          {!compact && (
            <span className="min-w-0 flex-1 leading-tight">
              <span className="block text-xs font-medium text-[color:var(--text-3)]">
                Environment
              </span>
              <span className="mt-0.5 block truncate text-[13px] font-semibold text-[color:var(--text-1)]">
                {active?.name ?? (isLoading ? 'Loading…' : 'Select environment')}
              </span>
            </span>
          )}
          {!compact && <ChevronsUpDown size={14} strokeWidth={1.75} className="flex-shrink-0 text-[color:var(--text-3)]" aria-hidden />}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="start" className="min-w-[200px]">
        <DropdownMenu.Label>Environments</DropdownMenu.Label>
        {envs.length === 0 && !isLoading && (
          <div className="px-2 py-1.5 text-xs tabular-nums text-[color:var(--text-3)]">
            No environments configured.
          </div>
        )}
        <DropdownMenu.RadioGroup
          value={active?.name ?? activeScope ?? ''}
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
                <span className="text-xs font-medium">{e.name}</span>
              </span>
            </DropdownMenu.RadioItem>
          ))}
        </DropdownMenu.RadioGroup>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}
