import { useState, useEffect } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listServiceConfig,
  updateServiceConfig,
  applyServiceConfig,
  type ServiceConfig,
} from '$/api/service-config';
import { AuthError, ApiError } from '$/api/client';
import { cn } from '$/lib/cn';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { ModalShell } from '$/components/feedback/ModalShell';
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

  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const [restarting, setRestarting] = useState(false);
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

  // An "Apply & Restart" is relevant when any section has source=db (meaning
  // the operator has edited it through the API and the change is pending a
  // restart to take effect).
  const hasPendingChanges = sections.some((s) => s.Source === 'db');

  const applyMutation = useMutation({
    mutationFn: () => applyServiceConfig(),
    onSuccess: () => {
      setApplyErr(null);
      setApplyFlash(true);
      // Poll until the service comes back up, then refetch the config.
      // The service restarts with exit code 1, so the API is briefly
      // unavailable. We poll every 2 seconds until a request succeeds.
      setRestarting(true);
      const poll = setInterval(() => {
        listServiceConfig(service)
          .then(() => {
            clearInterval(poll);
            setRestarting(false);
            setApplyFlash(false);
            qc.invalidateQueries({ queryKey: ['service-config', service] });
          })
          .catch(() => {
            // Service still restarting — keep polling.
          });
      }, 2000);
      // Safety: stop polling after 60 seconds.
      setTimeout(() => {
        clearInterval(poll);
        setRestarting(false);
      }, 60_000);
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Apply failed');
    },
  });

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar row */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Service Config
        </h1>
        {hasPendingChanges && !loading && !hasError && !restarting && (
          <button
            type="button"
            disabled={applyMutation.isPending}
            onClick={() => setShowApplyConfirm(true)}
            className={cn(
              'px-3 py-1 text-xs font-medium rounded transition-colors',
              applyMutation.isPending
                ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)]'
                : 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)] hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.2)]',
            )}
          >
            {applyMutation.isPending ? 'Restarting…' : applyFlash ? 'Restart triggered ✓' : 'Apply \u0026 Restart'}
          </button>
        )}
        {restarting && (
          <span
            aria-live="polite"
            className="text-xs text-[color:var(--text-3)] font-mono-tabular"
          >
            Restarting — waiting for service…
          </span>
        )}
        {applyErr && (
          <span className="text-xs text-[color:var(--danger)]">{applyErr}</span>
        )}
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

      {showApplyConfirm && (
        <ApplyConfirmDialog
          pendingSections={sections.filter((s) => s.Source === 'db')}
          isPending={applyMutation.isPending}
          onConfirm={() => {
            applyMutation.mutate();
            setShowApplyConfirm(false);
          }}
          onCancel={() => setShowApplyConfirm(false)}
        />
      )}
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

function ApplyConfirmDialog({
  pendingSections,
  isPending,
  onConfirm,
  onCancel,
}: {
  pendingSections: ServiceConfig[];
  isPending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <ModalShell
      title="Apply & Restart"
      titleId="apply-confirm-title"
      onClose={onCancel}
      panelClassName="max-w-md"
    >
      <div className="space-y-4">
        <p className="text-sm text-[color:var(--text-1)]">
          This will restart the osctrl-api service to apply the following
          configuration changes. The service will be briefly unavailable.
        </p>
        <div className="rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)] p-3">
          <p className="text-[10px] uppercase tracking-[0.08em] text-[color:var(--text-3)] mb-2">
            Pending changes ({pendingSections.length})
          </p>
          <ul className="space-y-1">
            {pendingSections.map((s) => (
              <li
                key={s.ID}
                className="flex items-center gap-2 text-xs text-[color:var(--text-2)]"
              >
                <span className="font-mono-tabular text-[color:var(--text-1)]">
                  {s.Name}
                </span>
                {s.Info && (
                  <span className="text-[color:var(--text-3)] truncate">
                    — {s.Info}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={isPending}
            className="px-3 py-1.5 text-xs font-medium rounded border border-[color:var(--border)] text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded transition-colors',
              'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.16)] text-[color:var(--warning)]',
              'hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.24)]',
              'disabled:opacity-40 disabled:cursor-not-allowed',
            )}
          >
            {isPending ? 'Restarting…' : 'Restart now'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
