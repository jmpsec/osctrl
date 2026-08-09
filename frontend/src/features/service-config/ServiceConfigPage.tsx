import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { listServiceConfig, type ServiceConfig } from '$/api/service-config';
import { AuthError } from '$/api/client';
import { cn } from '$/lib/cn';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { formatRelative } from '$/lib/time';

const SERVICES = ['api', 'tls'] as const;
type Service = (typeof SERVICES)[number];

export function ServiceConfigPage() {
  usePageTitle('Service Config');
  const params = useParams({ strict: false });
  const navigate = useNavigate();
  const serviceParam = (params as { service?: string }).service ?? 'api';
  const service: Service = (SERVICES as readonly string[]).includes(serviceParam)
    ? (serviceParam as Service)
    : 'api';

  const {
    data,
    isLoading,
    isFetching,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['service-config', service],
    queryFn: () => listServiceConfig(service),
    staleTime: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const sections = data ?? [];
  const loading = isLoading;
  const fetching = isFetching;
  const hasError = isError;
  const pageError = error;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar row */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Service Config
        </h1>
        {fetching && !loading && (
          <span
            aria-live="polite"
            aria-label="Refreshing data"
            className="ml-auto text-[10px] text-[color:var(--text-3)] font-mono-tabular"
          >
            refreshing…
          </span>
        )}
      </div>

      {/* Service tabs — same underline TabButton pattern as SettingsPage */}
      <div
        role="tablist"
        aria-label="Service config service tabs"
        className="flex items-center gap-1 px-2 border-b border-[color:var(--border)] overflow-x-auto"
      >
        {SERVICES.map((s) => (
          <Link
            key={s}
            to="/_app/config/$service"
            params={{ service: s }}
            role="tab"
            aria-selected={s === service}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 pt-2 pb-1.5 text-xs whitespace-nowrap',
              'border-b-2 transition-colors',
              'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              s === service
                ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
                : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
            )}
          >
            osctrl-{s}
          </Link>
        ))}
      </div>

      <div className="flex-1 overflow-auto min-h-0 p-4">
        {loading && (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-20 w-full" />
            ))}
          </div>
        )}

        {hasError && !loading && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title={pageError instanceof Error ? pageError.message : 'Failed to load service config'}
            action={
              <button
                type="button"
                onClick={() => void refetch()}
                className="px-3 py-1.5 text-xs font-medium rounded bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)] transition-colors"
              >
                Retry
              </button>
            }
          />
        )}

        {!loading && !hasError && sections.length === 0 && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            }
            title={`No service config for ${service}.`}
          />
        )}

        {!loading && !hasError && sections.length > 0 && (
          <div className="space-y-3">
            {sections.map((s) => (
              <ConfigSectionCard key={s.ID} section={s} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ConfigSectionCard({ section }: { section: ServiceConfig }) {
  // Pretty-print the JSON so the Monaco viewer gets syntax-highlighted,
  // folded, scrollable content instead of a single long line.
  let prettyValue = section.Value;
  try {
    prettyValue = JSON.stringify(JSON.parse(section.Value), null, 2);
  } catch {
    // not JSON — show raw
  }

  return (
    <section
      className="border border-[color:var(--border)] rounded-md overflow-hidden bg-[color:var(--bg-1)]"
      aria-labelledby={`config-${section.Name}-heading`}
    >
      <header className="flex items-center gap-3 px-3 py-2 bg-[color:var(--bg-0)] border-b border-[color:var(--border)]">
        <h2
          id={`config-${section.Name}-heading`}
          className="font-display text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular"
        >
          {section.Name}
        </h2>
        <span
          className={cn(
            'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular',
            section.Source === 'db'
              ? 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]'
              : 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
          )}
          title={section.Source === 'db' ? 'Edited via database' : 'Seeded from YAML file'}
        >
          {section.Source}
        </span>
        <span
          className={cn(
            'px-1.5 py-0.5 rounded text-[10px] font-mono-tabular',
            section.Editable
              ? 'bg-[rgba(var(--signal-r),var(--signal-g),var(--signal-b),0.12)] text-[color:var(--signal)]'
              : 'bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
          )}
        >
          {section.Editable ? 'editable' : 'read-only'}
        </span>
        {section.Info && (
          <p className="text-[10px] text-[color:var(--text-3)] truncate flex-1">
            {section.Info}
          </p>
        )}
        {!section.Info && <div className="flex-1" />}
        <span
          className="text-[10px] tnum text-[color:var(--text-3)] whitespace-nowrap"
          title={section.UpdatedAt}
        >
          updated {formatRelative(section.UpdatedAt)}
        </span>
      </header>

      <div className="p-3">
        <CodeEditor
          value={prettyValue}
          language="json"
          readOnly
          height="200px"
          aria-label={`Configuration section ${section.Name}`}
        />
      </div>
    </section>
  );
}

export default ServiceConfigPage;
