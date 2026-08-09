import { useState, useEffect } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listServiceConfig,
  updateServiceConfig,
  type ServiceConfig,
} from '$/api/service-config';
import { AuthError, ApiError } from '$/api/client';
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

  const qc = useQueryClient();
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
              <ConfigSectionCard
                key={s.ID}
                section={s}
                service={service}
                onSaved={() => qc.invalidateQueries({ queryKey: ['service-config', service] })}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function prettyPrint(value: string): string {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}

function ConfigSectionCard({
  section,
  service,
  onSaved,
}: {
  section: ServiceConfig;
  service: string;
  onSaved: () => void;
}) {
  const storedPretty = prettyPrint(section.Value);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(storedPretty);
  const [savedFlash, setSavedFlash] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Reset draft when the section value changes externally (e.g. after a
  // refetch invalidates the query and new data arrives), but only when not
  // actively editing so we don't clobber unsaved changes.
  useEffect(() => {
    if (!editing) {
      setDraft(storedPretty);
    }
  }, [storedPretty, editing]);

  const dirty = editing && draft !== storedPretty;

  const mutation = useMutation({
    mutationFn: () => {
      // Parse the draft so we send a raw JSON object, not a pre-serialized
      // string. The backend expects { "value": {...} }.
      const parsed = JSON.parse(draft);
      return updateServiceConfig(service, section.Name, { value: parsed });
    },
    onSuccess: () => {
      setErr(null);
      setEditing(false);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1200);
      onSaved();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 409) {
        setErr('Section is not editable.');
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        setErr('Invalid JSON value.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  function handleCancel() {
    setEditing(false);
    setDraft(storedPretty);
    setErr(null);
  }

  function handleEdit() {
    setEditing(true);
    setDraft(storedPretty);
    setErr(null);
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
        {dirty && (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]">
            pending
          </span>
        )}
        <span
          className="text-[10px] tnum text-[color:var(--text-3)] whitespace-nowrap"
          title={section.UpdatedAt}
        >
          updated {formatRelative(section.UpdatedAt)}
        </span>
        {section.Editable && !editing && (
          <button
            type="button"
            onClick={handleEdit}
            className="text-[10px] px-2 py-0.5 rounded font-medium border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] transition-colors"
          >
            Edit
          </button>
        )}
        {editing && (
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={!dirty || mutation.isPending}
              onClick={() => mutation.mutate()}
              className={cn(
                'text-[10px] px-2 py-0.5 rounded font-medium',
                'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
                'disabled:opacity-40 disabled:cursor-not-allowed',
              )}
            >
              {mutation.isPending ? 'Saving…' : savedFlash ? 'Saved ✓' : 'Save'}
            </button>
            <button
              type="button"
              onClick={handleCancel}
              disabled={mutation.isPending}
              className="text-[10px] px-2 py-0.5 rounded font-medium border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Cancel
            </button>
          </div>
        )}
      </header>

      <div className="p-3">
        <CodeEditor
          value={editing ? draft : storedPretty}
          onChange={editing ? (v) => setDraft(v ?? '') : undefined}
          language="json"
          readOnly={!editing}
          height="200px"
          aria-label={`Configuration section ${section.Name}`}
        />

        {err && (
          <p
            role="alert"
            className="mt-2 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-1.5 rounded-md"
          >
            {err}
          </p>
        )}
      </div>
    </section>
  );
}

export default ServiceConfigPage;
