import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listServiceSettings,
  patchSetting,
  type SettingValue,
  type SettingType,
} from '$/api/settings';
import { AuthError, ApiError } from '$/api/client';
import { cn } from '$/lib/cn';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { formatRelative } from '$/lib/time';

// Services are constant in the backend (pkg/settings.ValidServices = {tls, admin, api}).
// The raw values are the strings the API accepts on /api/v1/settings/{service};
// the user-facing labels add the `osctrl-` prefix for readability.
const SERVICES = ['tls', 'admin', 'api'] as const;
type Service = (typeof SERVICES)[number];

export function SettingsPage() {
  const params = useParams({ strict: false });
  const navigate = useNavigate();
  const serviceParam = (params as { service?: string }).service ?? 'admin';
  const service = (SERVICES as readonly string[]).includes(serviceParam)
    ? (serviceParam as Service)
    : 'admin';

  const qc = useQueryClient();
  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ['settings', service],
    queryFn: () => listServiceSettings(service),
    staleTime: 30_000,
  });

  if (isError && error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  const items = data ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Settings
        </h1>
        <nav aria-label="settings service tabs" className="flex items-center gap-1">
          {SERVICES.map((s) => (
            <Link
              key={s}
              to="/_app/settings/$service"
              params={{ service: s }}
              className={cn(
                'px-3 py-1.5 text-xs font-mono-tabular rounded-md transition-colors',
                s === service
                  ? 'bg-[color:var(--bg-2)] text-[color:var(--text-1)] shadow-[inset_0_-2px_0_var(--signal)]'
                  : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
              )}
            >
              {s}
            </Link>
          ))}
        </nav>
        {isFetching && !isLoading && (
          <span
            aria-live="polite"
            aria-label="Refreshing data"
            className="ml-auto text-[10px] text-[color:var(--text-3)] font-mono-tabular"
          >
            refreshing…
          </span>
        )}
      </div>

      <div className="flex-1 overflow-auto min-h-0 p-4">
        {isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-14 w-full" />
            ))}
          </div>
        )}

        {isError && !isLoading && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
            }
            title={error instanceof Error ? error.message : 'Failed to load settings'}
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

        {!isLoading && !isError && items.length === 0 && (
          <EmptyState
            icon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            }
            title={`No settings for ${service}.`}
          />
        )}

        {!isLoading && !isError && items.length > 0 && (
          <div className="space-y-2">
            {items.map((s) => (
              <SettingRow
                key={s.ID}
                setting={s}
                service={service}
                onSaved={() => qc.invalidateQueries({ queryKey: ['settings', service] })}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SettingRow({
  setting,
  service,
  onSaved,
}: {
  setting: SettingValue;
  service: string;
  onSaved: () => void;
}) {
  const [pendingString, setPendingString] = useState(setting.String);
  const [pendingBool, setPendingBool] = useState(setting.Boolean);
  const [pendingInt, setPendingInt] = useState(setting.Integer);
  const [savedFlash, setSavedFlash] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setPendingString(setting.String);
    setPendingBool(setting.Boolean);
    setPendingInt(setting.Integer);
  }, [setting.String, setting.Boolean, setting.Integer]);

  const dirty =
    (setting.Type === 'string' && pendingString !== setting.String) ||
    (setting.Type === 'boolean' && pendingBool !== setting.Boolean) ||
    (setting.Type === 'integer' && pendingInt !== setting.Integer);

  const mutation = useMutation({
    mutationFn: () => {
      switch (setting.Type) {
        case 'string':
          return patchSetting(service, setting.Name, { string: pendingString });
        case 'boolean':
          return patchSetting(service, setting.Name, { boolean: pendingBool });
        case 'integer':
          return patchSetting(service, setting.Name, { integer: pendingInt });
        default: {
          // unreachable: SettingType is exhaustive
          const _exhaustive: never = setting.Type as never;
          throw new Error(`Unsupported setting type: ${String(_exhaustive)}`);
        }
      }
    },
    onSuccess: () => {
      setErr(null);
      setSavedFlash(true);
      window.setTimeout(() => setSavedFlash(false), 1200);
      onSaved();
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 404) {
        setErr('Setting not found.');
        return;
      }
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  return (
    <div className="border border-[color:var(--border)] rounded-md p-3 bg-[color:var(--bg-1)]">
      <div className="flex items-baseline gap-3 mb-2">
        <span className="font-display text-sm font-semibold text-[color:var(--text-1)] font-mono-tabular">
          {setting.Name}
        </span>
        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono-tabular text-[color:var(--text-3)] bg-[color:var(--bg-2)]">
          {setting.Type}
        </span>
        {setting.Info && (
          <span className="text-[10px] text-[color:var(--text-3)]">{setting.Info}</span>
        )}
        <span className="ml-auto text-[10px] tnum text-[color:var(--text-3)]" title={setting.UpdatedAt}>
          updated {formatRelative(setting.UpdatedAt)}
        </span>
      </div>

      <div className="flex items-center gap-2">
        <SettingInput
          name={setting.Name}
          type={setting.Type}
          stringValue={pendingString}
          boolValue={pendingBool}
          intValue={pendingInt}
          onString={setPendingString}
          onBool={setPendingBool}
          onInt={setPendingInt}
        />
        <button
          type="button"
          disabled={!dirty || mutation.isPending}
          onClick={() => mutation.mutate()}
          className={cn(
            'px-3 py-1.5 text-xs font-medium rounded-md',
            'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
            'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
          )}
        >
          {mutation.isPending ? 'Saving…' : savedFlash ? 'Saved' : 'Save'}
        </button>
      </div>

      {err && (
        <p
          role="alert"
          className="mt-2 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-1.5 rounded-md"
        >
          {err}
        </p>
      )}
    </div>
  );
}

function SettingInput({
  name,
  type,
  stringValue,
  boolValue,
  intValue,
  onString,
  onBool,
  onInt,
}: {
  name: string;
  type: SettingType;
  stringValue: string;
  boolValue: boolean;
  intValue: number;
  onString: (s: string) => void;
  onBool: (b: boolean) => void;
  onInt: (n: number) => void;
}) {
  const inputId = `setting-${name}`;

  if (type === 'boolean') {
    return (
      <label
        htmlFor={inputId}
        className="flex items-center gap-2 text-xs text-[color:var(--text-1)] cursor-pointer"
      >
        <input
          id={inputId}
          type="checkbox"
          checked={boolValue}
          onChange={(e) => onBool(e.target.checked)}
          className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
        />
        <span className="font-mono-tabular">{boolValue ? 'enabled' : 'disabled'}</span>
      </label>
    );
  }

  if (type === 'integer') {
    return (
      <input
        id={inputId}
        type="number"
        value={intValue}
        onChange={(e) => {
          const v = Number(e.target.value);
          if (!Number.isNaN(v)) onInt(v);
        }}
        className={cn(
          'flex-1 px-3 py-1.5 text-sm rounded-md border border-[color:var(--border)]',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
        )}
      />
    );
  }

  return (
    <input
      id={inputId}
      type="text"
      value={stringValue}
      onChange={(e) => onString(e.target.value)}
      className={cn(
        'flex-1 px-3 py-1.5 text-sm rounded-md border border-[color:var(--border)]',
        'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
        'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
      )}
    />
  );
}

export default SettingsPage;
